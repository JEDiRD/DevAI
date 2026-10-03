from dataclasses import dataclass
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from .db import connect


class TaskAlreadyClaimed(RuntimeError):
    pass


class LeaseLost(RuntimeError):
    pass


@dataclass(frozen=True)
class TaskLease:
    """A held task lease carrying its caller's tenant authority.

    ``tenant_id`` is the CALLER tenant that was proven to own the task at claim
    time, not a value read back from a row. It is immutable (frozen) and is
    never persisted or serialized, so adding it changes no storage format.
    """

    task_id: UUID
    owner_id: UUID
    version: int
    expires_at: object
    tenant_id: UUID


@dataclass(frozen=True)
class Checkpoint:
    sequence: int
    lease_version: int
    payload: dict
    created_at: object


def claim_task(
    task_id: UUID,
    owner_id: UUID,
    lease_seconds: int = 60,
    *,
    tenant_id: UUID,
) -> TaskLease:
    """Claim a task for ``tenant_id``.

    The CALLER tenant is the authority. Ownership is proven inside the
    authoritative UPDATE itself, atomically, by following the task to its job
    (tasks.job_id -> jobs.id) and requiring jobs.tenant_id to equal the caller
    tenant. There is no authorization precheck and no row-derived fallback: a
    missing task and a foreign task are indistinguishable to the caller.
    """

    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks t
                SET lease_owner = %s,
                    lease_version = t.lease_version + 1,
                    lease_expires_at =
                        now() + (%s * interval '1 second'),
                    next_attempt_at = NULL,
                    status = 'running',
                    updated_at = now()
                FROM jobs j
                WHERE j.id = t.job_id
                  AND t.id = %s
                  AND j.tenant_id = %s
                  AND t.status IN ('pending', 'running')
                  AND (
                      t.status <> 'pending'
                      OR t.next_attempt_at IS NULL
                      OR t.next_attempt_at <= now()
                  )
                  AND (
                      t.lease_expires_at IS NULL
                      OR t.lease_expires_at <= now()
                  )
                RETURNING
                    t.lease_version,
                    t.lease_expires_at
                """,
                (
                    owner_id,
                    lease_seconds,
                    task_id,
                    tenant_id,
                ),
            )

            row = cur.fetchone()

    if row is None:
        raise TaskAlreadyClaimed(
            f"Task {task_id} is not claimable"
        )

    return TaskLease(
        task_id=task_id,
        owner_id=owner_id,
        version=row[0],
        expires_at=row[1],
        tenant_id=tenant_id,
    )


def renew_lease(
    lease: TaskLease,
    lease_seconds: int = 60,
    *,
    tenant_id: UUID,
) -> TaskLease:
    """Renew ``lease`` for ``tenant_id``.

    The CALLER tenant is the authority. Ownership is proven inside the
    authoritative UPDATE, atomically, alongside the existing owner and
    lease-version fence. Renewing under a foreign tenant leaves owner,
    version, expiry and status untouched and raises the same LeaseLost a stale
    lease would.
    """

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks t
                SET lease_expires_at =
                        now() + (%s * interval '1 second'),
                    updated_at = now()
                FROM jobs j
                WHERE j.id = t.job_id
                  AND t.id = %s
                  AND j.tenant_id = %s
                  AND t.lease_owner = %s
                  AND t.lease_version = %s
                  AND t.lease_expires_at > now()
                RETURNING t.lease_expires_at
                """,
                (
                    lease_seconds,
                    lease.task_id,
                    tenant_id,
                    lease.owner_id,
                    lease.version,
                ),
            )

            row = cur.fetchone()

    if row is None:
        raise LeaseLost("Lease can no longer be renewed")

    return TaskLease(
        task_id=lease.task_id,
        owner_id=lease.owner_id,
        version=lease.version,
        expires_at=row[0],
        tenant_id=tenant_id,
    )


def save_checkpoint(
    lease: TaskLease,
    payload: dict,
) -> Checkpoint:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET checkpoint_seq = checkpoint_seq + 1,
                    updated_at = now()
                WHERE id = %s
                  AND lease_owner = %s
                  AND lease_version = %s
                  AND lease_expires_at > now()
                RETURNING checkpoint_seq
                """,
                (
                    lease.task_id,
                    lease.owner_id,
                    lease.version,
                ),
            )

            row = cur.fetchone()

            if row is None:
                raise LeaseLost(
                    "Cannot checkpoint with a stale lease"
                )

            sequence = row[0]
            checkpoint_id = uuid4()

            cur.execute(
                """
                INSERT INTO task_checkpoints (
                    id,
                    task_id,
                    sequence,
                    lease_version,
                    payload
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING created_at
                """,
                (
                    checkpoint_id,
                    lease.task_id,
                    sequence,
                    lease.version,
                    Jsonb(payload),
                ),
            )

            created_at = cur.fetchone()[0]

    return Checkpoint(
        sequence=sequence,
        lease_version=lease.version,
        payload=payload,
        created_at=created_at,
    )


def load_latest_checkpoint(
    task_id: UUID,
) -> Checkpoint | None:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    sequence,
                    lease_version,
                    payload,
                    created_at
                FROM task_checkpoints
                WHERE task_id = %s
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (task_id,),
            )

            row = cur.fetchone()

    if row is None:
        return None

    return Checkpoint(
        sequence=row[0],
        lease_version=row[1],
        payload=row[2],
        created_at=row[3],
    )


def release_task(
    lease: TaskLease,
    final_status: str,
) -> None:

    if final_status not in {
        "completed",
        "failed",
        "cancelled",
        "pending",
    }:
        raise ValueError("invalid final_status")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET lease_owner = NULL,
                    lease_expires_at = NULL,
                    status = %s,
                    updated_at = now()
                WHERE id = %s
                  AND lease_owner = %s
                  AND lease_version = %s
                  AND lease_expires_at > now()
                """,
                (
                    final_status,
                    lease.task_id,
                    lease.owner_id,
                    lease.version,
                ),
            )

            if cur.rowcount != 1:
                raise LeaseLost(
                    "Cannot release stale task lease"
                )


def defer_task_for_route(
    lease: TaskLease,
    retry_seconds: int = 60,
) -> Checkpoint:
    if retry_seconds <= 0:
        raise ValueError("retry_seconds must be positive")

    payload = {
        "phase": "waiting_for_route",
        "retry_seconds": retry_seconds,
    }

    # The checkpoint and lease release must commit together. A stale owner
    # cannot defer a task claimed by somebody else.
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET checkpoint_seq = checkpoint_seq + 1,
                    status = 'pending',
                    next_attempt_at =
                        now() + (%s * interval '1 second'),
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    updated_at = now()
                WHERE id = %s
                  AND lease_owner = %s
                  AND lease_version = %s
                  AND lease_expires_at > now()
                  AND status = 'running'
                RETURNING checkpoint_seq
                """,
                (
                    retry_seconds,
                    lease.task_id,
                    lease.owner_id,
                    lease.version,
                ),
            )

            row = cur.fetchone()
            if row is None:
                raise LeaseLost("Cannot defer with a stale lease")

            sequence = row[0]
            cur.execute(
                """
                INSERT INTO task_checkpoints (
                    id, task_id, sequence, lease_version, payload
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING created_at
                """,
                (
                    uuid4(),
                    lease.task_id,
                    sequence,
                    lease.version,
                    Jsonb(payload),
                ),
            )
            created_at = cur.fetchone()[0]

    return Checkpoint(
        sequence=sequence,
        lease_version=lease.version,
        payload=payload,
        created_at=created_at,
    )
