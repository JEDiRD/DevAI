from uuid import UUID

from .db import connect
from .tenancy import TenantScopeError


def add_dependency(
    task_id: UUID,
    depends_on_task_id: UUID,
    *,
    tenant_id: UUID,
) -> None:
    """Record a dependency edge between two tasks of ``tenant_id``.

    ``tenant_id`` is expected to come from an already-authorized job or
    boundary context; this layer does not authenticate request input.

    No same-job restriction is imposed: cross-job dependencies are a valid
    domain shape and remain permitted when both tasks belong to the same
    tenant.

    The insert is tenant-scoped through two independent EXISTS branches, one
    per task, so neither side can be satisfied by a foreign task. A losing
    concurrent duplicate then re-checks the edge with a SECOND statement on
    the SAME connection, which under READ COMMITTED takes a fresh snapshot
    after the winner commits. Denials raise one uniform TenantScopeError and
    never reveal whether a foreign or missing task exists.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO task_dependencies (
                    task_id,
                    depends_on_task_id
                )
                SELECT %s, %s
                WHERE EXISTS (
                    SELECT 1
                    FROM tasks a
                    JOIN jobs ja ON ja.id = a.job_id
                    WHERE a.id = %s
                      AND ja.tenant_id = %s
                )
                AND EXISTS (
                    SELECT 1
                    FROM tasks b
                    JOIN jobs jb ON jb.id = b.job_id
                    WHERE b.id = %s
                      AND jb.tenant_id = %s
                )
                ON CONFLICT DO NOTHING
                RETURNING task_id
                """,
                (
                    task_id,
                    depends_on_task_id,
                    task_id,
                    tenant_id,
                    depends_on_task_id,
                    tenant_id,
                ),
            )

            if cur.fetchone() is not None:
                return

            # Second statement, same connection/transaction: a concurrent
            # winner's row must be visible here.
            cur.execute(
                """
                SELECT 1
                FROM task_dependencies d
                JOIN tasks a ON a.id = d.task_id
                JOIN jobs ja ON ja.id = a.job_id
                JOIN tasks b ON b.id = d.depends_on_task_id
                JOIN jobs jb ON jb.id = b.job_id
                WHERE d.task_id = %s
                  AND d.depends_on_task_id = %s
                  AND ja.tenant_id = %s
                  AND jb.tenant_id = %s
                """,
                (
                    task_id,
                    depends_on_task_id,
                    tenant_id,
                    tenant_id,
                ),
            )

            if cur.fetchone() is None:
                raise TenantScopeError(
                    "Dependency is not in tenant scope"
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
                  AND (
                      t.next_attempt_at IS NULL
                      OR t.next_attempt_at <= now()
                  )

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
    *,
    tenant_id: UUID,
) -> None:
    """Set a task's status, scoped to the owning tenant.

    The UPDATE itself proves task.id == task_id AND that the task's job
    belongs to ``tenant_id``; no prior pre-check is relied upon. The
    existing ``rowcount != 1`` RuntimeError contract is preserved exactly,
    so a missing task and a foreign task take the same observable path and
    no tenant-existence oracle is created.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET status = %s,
                    updated_at = now()
                WHERE id = %s
                  AND EXISTS (
                      SELECT 1
                      FROM jobs
                      WHERE jobs.id = tasks.job_id
                        AND jobs.tenant_id = %s
                  )
                """,
                (status, task_id, tenant_id),
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
                      AND (
                          t.next_attempt_at IS NULL
                          OR t.next_attempt_at <= now()
                      )

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
                    next_attempt_at = NULL,
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
