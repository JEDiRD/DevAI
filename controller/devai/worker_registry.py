from uuid import UUID

from .db import connect


class WorkerNotFound(RuntimeError):
    pass


def heartbeat_worker(
    tenant_id: UUID,
    worker_id: UUID,
    *,
    platform: str | None = None,
    architecture: str | None = None,
) -> None:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE worker_nodes
                SET status = CASE
                        WHEN status = 'offline' THEN 'online'
                        ELSE status
                    END,
                    last_seen_at = now(),
                    platform = COALESCE(
                        %s,
                        platform
                    ),
                    architecture = COALESCE(
                        %s,
                        architecture
                    ),
                    updated_at = now()
                WHERE tenant_id = %s
                  AND id = %s
                  AND status <> 'disabled'
                """,
                (
                    platform,
                    architecture,
                    tenant_id,
                    worker_id,
                ),
            )

            if cur.rowcount != 1:
                raise WorkerNotFound(
                    f"Worker not available: {worker_id}"
                )


def set_worker_status(
    tenant_id: UUID,
    worker_id: UUID,
    status: str,
) -> None:

    if status not in {
        "offline",
        "online",
        "draining",
        "disabled",
    }:
        raise ValueError(
            f"Invalid worker status: {status}"
        )

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE worker_nodes
                SET status = %s,
                    updated_at = now()
                WHERE tenant_id = %s
                  AND id = %s
                """,
                (
                    status,
                    tenant_id,
                    worker_id,
                ),
            )

            if cur.rowcount != 1:
                raise WorkerNotFound(
                    f"Worker not found: {worker_id}"
                )
