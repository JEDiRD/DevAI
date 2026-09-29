from uuid import UUID

from .db import connect


def add_dependency(
    task_id: UUID,
    depends_on_task_id: UUID,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO task_dependencies (
                    task_id,
                    depends_on_task_id
                )
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
                """,
                (task_id, depends_on_task_id),
            )


def list_ready_tasks(
    job_id: UUID,
) -> list[tuple]:
    """
    A task is ready only when:

    - it belongs to the job
    - status = pending
    - every dependency is completed

    waiting_approval tasks are intentionally excluded.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    t.id,
                    t.external_id,
                    t.title
                FROM tasks t
                WHERE t.job_id = %s
                  AND t.status = 'pending'

                  AND NOT EXISTS (
                      SELECT 1
                      FROM task_dependencies d
                      JOIN tasks parent
                        ON parent.id = d.depends_on_task_id
                      WHERE d.task_id = t.id
                        AND parent.status <> 'completed'
                  )

                ORDER BY t.external_id
                """,
                (job_id,),
            )

            return cur.fetchall()


def set_task_status(
    task_id: UUID,
    status: str,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET status = %s,
                    updated_at = now()
                WHERE id = %s
                """,
                (status, task_id),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Task not found: {task_id}"
                )


from uuid import uuid4

from .checkpoint import TaskLease


def claim_next_ready_task(
    job_id: UUID,
    owner_id: UUID | None = None,
    lease_seconds: int = 60,
) -> TaskLease | None:
    """
    Atomically select and claim one READY task.

    Multiple workers may call this concurrently.
    PostgreSQL SKIP LOCKED ensures they do not receive
    the same task.
    """
    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")

    owner_id = owner_id or uuid4()

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH candidate AS (
                    SELECT t.id
                    FROM tasks t
                    WHERE t.job_id = %s
                      AND t.status = 'pending'

                      AND NOT EXISTS (
                          SELECT 1
                          FROM task_dependencies d
                          JOIN tasks parent
                            ON parent.id = d.depends_on_task_id
                          WHERE d.task_id = t.id
                            AND parent.status <> 'completed'
                      )

                    ORDER BY t.external_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )

                UPDATE tasks t
                SET lease_owner = %s,
                    lease_version = t.lease_version + 1,
                    lease_expires_at =
                        now() + (%s * interval '1 second'),
                    status = 'running',
                    updated_at = now()
                FROM candidate c
                WHERE t.id = c.id
                RETURNING
                    t.id,
                    t.lease_version,
                    t.lease_expires_at
                """,
                (
                    job_id,
                    owner_id,
                    lease_seconds,
                ),
            )

            row = cur.fetchone()

    if row is None:
        return None

    return TaskLease(
        task_id=row[0],
        owner_id=owner_id,
        version=row[1],
        expires_at=row[2],
    )
