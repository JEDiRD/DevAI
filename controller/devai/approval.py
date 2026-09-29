from uuid import UUID

from .db import connect


class ApprovalError(RuntimeError):
    pass


def require_approval(
    task_id: UUID,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET requires_approval = TRUE,
                    approved_at = NULL,
                    approved_by = NULL,
                    status = 'waiting_approval',
                    updated_at = now()
                WHERE id = %s
                  AND status = 'pending'
                """,
                (task_id,),
            )

            if cur.rowcount != 1:
                raise ApprovalError(
                    "Task cannot enter approval state"
                )


def approve_task(
    task_id: UUID,
    approved_by: str,
) -> None:
    approved_by = approved_by.strip()

    if not approved_by:
        raise ValueError("approved_by is required")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET approved_at = now(),
                    approved_by = %s,
                    status = 'pending',
                    updated_at = now()
                WHERE id = %s
                  AND requires_approval = TRUE
                  AND status = 'waiting_approval'
                  AND approved_at IS NULL
                """,
                (approved_by, task_id),
            )

            if cur.rowcount != 1:
                raise ApprovalError(
                    "Task is not awaiting approval"
                )
