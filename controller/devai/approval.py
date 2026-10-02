"""Human approval gate for tasks.

Both entry points take a TenantPrincipal rather than raw arguments:

- there is no standalone ``tenant_id`` parameter, so tenant scope can only
  come from an authorization context;
- there is no independent ``approved_by`` parameter, so the persisted
  ``tasks.approved_by`` provenance is sourced solely from
  ``approver.subject``.

Authorization order matters: the actor-kind check is the FIRST operation in
each function, before any connection is opened or any SQL is issued, so a
service principal can never reach the database and can never observe
whether a task exists. A WorkerPrincipal is not accepted here at all.

Tenant scope is enforced atomically in the mutating statement itself
(tasks.job_id -> jobs.id -> jobs.tenant_id) rather than by a preceding
SELECT, which would leave a time-of-check/time-of-use gap. A zero rowcount
produces one uniform ApprovalError that does not distinguish a missing task
from a foreign-tenant task, so this path is not a tenant-existence oracle.
"""

from uuid import UUID

from .db import connect
from .principal import OPERATOR_ACTOR, TenantPrincipal


class ApprovalError(RuntimeError):
    pass


def _require_operator(approver: TenantPrincipal) -> None:
    """First authorization operation: no DB work before this check."""
    if not isinstance(approver, TenantPrincipal):
        raise ApprovalError("Operator principal is required")
    if approver.actor_kind != OPERATOR_ACTOR:
        raise ApprovalError("Only an operator may approve")


def require_approval(
    task_id: UUID,
    *,
    approver: TenantPrincipal,
) -> None:
    _require_operator(approver)

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
                  AND EXISTS (
                      SELECT 1
                      FROM jobs
                      WHERE jobs.id = tasks.job_id
                        AND jobs.tenant_id = %s
                  )
                """,
                (task_id, approver.tenant_id),
            )

            if cur.rowcount != 1:
                raise ApprovalError("Task cannot enter approval state")


def approve_task(
    task_id: UUID,
    *,
    approver: TenantPrincipal,
) -> None:
    _require_operator(approver)

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
                  AND EXISTS (
                      SELECT 1
                      FROM jobs
                      WHERE jobs.id = tasks.job_id
                        AND jobs.tenant_id = %s
                  )
                """,
                (approver.subject, task_id, approver.tenant_id),
            )

            if cur.rowcount != 1:
                raise ApprovalError("Task is not awaiting approval")