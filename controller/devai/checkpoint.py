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
    task_id: UUID
    owner_id: UUID
    version: int
    expires_at: object


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
) -> TaskLease:

    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET lease_owner = %s,
                    lease_version = lease_version + 1,
                    lease_expires_at =
                        now() + (%s * interval '1 second'),
                    status = 'running',
                    updated_at = now()
                WHERE id = %s
                  AND status IN ('pending', 'running')
                  AND (
                      lease_expires_at IS NULL
                      OR lease_expires_at <= now()
                  )
                RETURNING
                    lease_version,
                    lease_expires_at
                """,
                (
                    owner_id,
                    lease_seconds,
                    task_id,
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
    )


def renew_lease(
    lease: TaskLease,
    lease_seconds: int = 60,
) -> TaskLease:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET lease_expires_at =
                        now() + (%s * interval '1 second'),
                    updated_at = now()
                WHERE id = %s
                  AND lease_owner = %s
                  AND lease_version = %s
                  AND lease_expires_at > now()
                RETURNING lease_expires_at
                """,
                (
                    lease_seconds,
                    lease.task_id,
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
