from dataclasses import dataclass
from uuid import UUID, uuid4

from .db import connect


class DispatchUnavailable(RuntimeError):
    pass


class DispatchLeaseLost(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkerDispatch:
    id: UUID
    tenant_id: UUID
    worker_node_id: UUID
    route_key: str
    gateway_model: str
    prompt: str
    claim_version: int


def create_dispatch(
    *,
    tenant_id: UUID,
    worker_node_id: UUID,
    route_key: str,
    gateway_model: str,
    prompt: str,
) -> UUID:

    dispatch_id = uuid4()

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO worker_dispatches (
                    id,
                    tenant_id,
                    worker_node_id,
                    route_key,
                    gateway_model,
                    prompt
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    dispatch_id,
                    tenant_id,
                    worker_node_id,
                    route_key,
                    gateway_model,
                    prompt,
                ),
            )

    return dispatch_id


def claim_next_dispatch(
    *,
    tenant_id: UUID,
    worker_node_id: UUID,
    lease_seconds: int = 120,
) -> WorkerDispatch | None:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH candidate AS (
                    SELECT d.id
                    FROM worker_dispatches d
                    JOIN worker_nodes n
                      ON n.tenant_id = d.tenant_id
                     AND n.id = d.worker_node_id
                    WHERE d.tenant_id = %s
                      AND d.worker_node_id = %s
                      AND n.status = 'online'
                      AND n.last_seen_at >
                          now() - interval '90 seconds'
                      AND (
                          d.status = 'pending'
                          OR (
                              d.status = 'claimed'
                              AND d.lease_expires_at <= now()
                          )
                      )
                    ORDER BY d.created_at
                    FOR UPDATE OF d SKIP LOCKED
                    LIMIT 1
                )
                UPDATE worker_dispatches d
                SET status = 'claimed',
                    claim_version = claim_version + 1,
                    claimed_at = now(),
                    lease_expires_at =
                        now()
                        + (%s * interval '1 second')
                FROM candidate
                WHERE d.id = candidate.id
                RETURNING
                    d.id,
                    d.tenant_id,
                    d.worker_node_id,
                    d.route_key,
                    d.gateway_model,
                    d.prompt,
                    d.claim_version
                """,
                (
                    tenant_id,
                    worker_node_id,
                    lease_seconds,
                ),
            )

            row = cur.fetchone()

    if row is None:
        return None

    return WorkerDispatch(
        id=row[0],
        tenant_id=row[1],
        worker_node_id=row[2],
        route_key=row[3],
        gateway_model=row[4],
        prompt=row[5],
        claim_version=row[6],
    )


def complete_dispatch(
    *,
    tenant_id: UUID,
    dispatch_id: UUID,
    worker_node_id: UUID,
    claim_version: int,
    content: str,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    provider_request_id: str | None = None,
) -> None:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE worker_dispatches
                SET status = 'succeeded',
                    result_content = %s,
                    prompt_tokens = %s,
                    completion_tokens = %s,
                    provider_request_id = %s,
                    completed_at = now(),
                    lease_expires_at = NULL
                WHERE id = %s
                  AND tenant_id = %s
                  AND worker_node_id = %s
                  AND claim_version = %s
                  AND status = 'claimed'
                  AND lease_expires_at > now()
                """,
                (
                    content,
                    prompt_tokens,
                    completion_tokens,
                    provider_request_id,
                    dispatch_id,
                    tenant_id,
                    worker_node_id,
                    claim_version,
                ),
            )

            if cur.rowcount != 1:
                raise DispatchLeaseLost(
                    f"Dispatch lease lost: {dispatch_id}"
                )


def fail_dispatch(
    *,
    tenant_id: UUID,
    dispatch_id: UUID,
    worker_node_id: UUID,
    claim_version: int,
    error: str,
) -> None:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE worker_dispatches
                SET status = 'failed',
                    error = %s,
                    completed_at = now(),
                    lease_expires_at = NULL
                WHERE id = %s
                  AND tenant_id = %s
                  AND worker_node_id = %s
                  AND claim_version = %s
                  AND status = 'claimed'
                  AND lease_expires_at > now()
                """,
                (
                    error[:2000],
                    dispatch_id,
                    tenant_id,
                    worker_node_id,
                    claim_version,
                ),
            )

            if cur.rowcount != 1:
                raise DispatchLeaseLost(
                    f"Dispatch lease lost: {dispatch_id}"
                )


def get_dispatch_result(
    dispatch_id: UUID,
):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    status,
                    result_content,
                    prompt_tokens,
                    completion_tokens,
                    provider_request_id,
                    error
                FROM worker_dispatches
                WHERE id = %s
                """,
                (dispatch_id,),
            )

            row = cur.fetchone()

    if row is None:
        raise DispatchUnavailable(
            f"Dispatch not found: {dispatch_id}"
        )

    return row
