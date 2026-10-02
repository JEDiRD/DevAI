"""Minimal tenant-scope primitives.

Public API is intentionally small and auditable: one error type, three scope
constants, and two read-only pre-check helpers. There is no ORM, no policy
engine, and no decorator framework here.

The three constants are tenant predicate *fragments*, not column names. Each
one is a complete, self-contained predicate over a table alias and:

- consumes exactly ONE tenant_id placeholder (``%s``), which it supplies
  itself;
- is always the FINAL parameter contributed by that fragment, so a fragment
  is safe to concatenate after the non-tenant predicates of a WHERE clause;
- expands a caller's ``tenant_id`` argument to every tenant_id column it
  references (for example JOB_SCOPE binds jobs.tenant_id once, while
  TASK_ID_SCOPE joins tasks to jobs so that the bound value is checked
  against jobs.tenant_id rather than a task column).

TENANT_SCOPE is the bare ``tenant_id = %s`` predicate and is what
require_job_tenant uses against the jobs table itself. JOB_SCOPE and
TASK_ID_SCOPE are child-row fragments: each embeds a sub-select over jobs so
that it can scope a query whose own table has no tenant_id column (JOB_SCOPE
expects a job_id column, TASK_ID_SCOPE expects a task_id column).

Read-only pre-checks such as require_job_tenant / require_task_tenant are
NOT sufficient authorization for mutable resource operations on their own:
a separate SELECT followed by an unscoped UPDATE/DELETE leaves a
time-of-check/time-of-use gap and silently no-ops (or worse, touches a
foreign row) if the row moves between the two statements.

Mutable operations must therefore embed the tenant predicate atomically in
the mutating SQL statement itself (e.g. via the jobs tenant column through
tasks.job_id -> jobs.id -> jobs.tenant_id), and treat "no row matched" as a
single uniform denial. See controller/devai/approval.py for the pattern.
"""

from __future__ import annotations

from uuid import UUID

TENANT_SCOPE = "tenant_id = %s"

JOB_SCOPE = "job_id IN (SELECT id FROM jobs WHERE tenant_id = %s)"

TASK_ID_SCOPE = (
    "task_id IN (SELECT t.id FROM tasks t "
    "JOIN jobs j ON j.id = t.job_id WHERE j.tenant_id = %s)"
)


class TenantScopeError(RuntimeError):
    """Raised when a row is missing, foreign, or otherwise out of scope."""


_JOB_TENANT_SQL = f"SELECT 1 FROM jobs WHERE id = %s AND {TENANT_SCOPE}"

_TASK_TENANT_SQL = (
    "SELECT t.job_id FROM tasks t "
    f"JOIN jobs j ON j.id = t.job_id WHERE t.id = %s AND j.{TENANT_SCOPE}"
)


def require_job_tenant(cur, job_id: UUID, tenant_id: UUID) -> None:
    """Pre-check that a job belongs to a tenant; raises TenantScopeError if not.

    Read-only pre-check only. Callers performing mutations must additionally
    scope the mutating statement itself (see module docstring).
    """
    cur.execute(_JOB_TENANT_SQL, (job_id, tenant_id))
    if cur.fetchone() is None:
        raise TenantScopeError("Job is not in tenant scope")


def require_task_tenant(cur, task_id: UUID, tenant_id: UUID) -> UUID:
    """Pre-check that a task belongs to a tenant; returns its job_id.

    Raises TenantScopeError when the task is missing or owned by another
    tenant. Read-only pre-check only (see module docstring).
    """
    cur.execute(_TASK_TENANT_SQL, (task_id, tenant_id))
    row = cur.fetchone()
    if row is None:
        raise TenantScopeError("Task is not in tenant scope")
    return row[0]