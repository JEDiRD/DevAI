from __future__ import annotations

from uuid import UUID, uuid4

from .db import connect
from .tenancy import JOB_SCOPE, TENANT_SCOPE, TenantScopeError
from .types import ExecutionAttempt


def create_job(
    objective: str,
    tenant_id: UUID,
    status: str = "running",
) -> UUID:
    job_id = uuid4()

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO jobs (
                    id,
                    tenant_id,
                    objective,
                    status
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    job_id,
                    tenant_id,
                    objective,
                    status,
                ),
            )

    return job_id


def create_task(
    job_id: UUID,
    external_id: str,
    title: str,
    description: str,
    capability: str,
    risk: str,
    needs_review: bool,
    status: str = "running",
    *,
    tenant_id: UUID,
) -> UUID:
    """Create a task under a job owned by ``tenant_id``.

    The INSERT is a guarded INSERT ... SELECT whose key is drawn from
    ``jobs`` filtered by tenant, so the write itself proves both that the
    job exists and that it belongs to the tenant. A foreign or missing job
    produces no row and one uniform scope failure, so this is not a
    job-existence oracle.
    """
    task_id = uuid4()

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tasks (
                    id,
                    job_id,
                    external_id,
                    title,
                    description,
                    capability,
                    risk,
                    needs_review,
                    status
                )
                SELECT
                    %s, j.id,
                    %s, %s, %s,
                    %s, %s, %s, %s
                FROM jobs j
                WHERE j.id = %s
                  AND j.tenant_id = %s
                RETURNING id
                """,
                (
                    task_id,
                    external_id,
                    title,
                    description,
                    capability,
                    risk,
                    needs_review,
                    status,
                    job_id,
                    tenant_id,
                ),
            )

            if cur.fetchone() is None:
                raise TenantScopeError(
                    "Task could not be created in tenant scope"
                )

    return task_id


def record_attempt(
    job_id: UUID,
    task_id: UUID,
    attempt_number: int,
    attempt: ExecutionAttempt,
    *,
    tenant_id: UUID,
) -> UUID:
    """Record a finished attempt for a same-tenant job and task.

    The guarded INSERT proves atomically that the task exists, that the
    task belongs to that job, and that the job belongs to the tenant, so a
    valid foreign task/job pairing cannot create a ledger row.
    """
    attempt_id = uuid4()

    status = "succeeded" if attempt.success else "failed"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO execution_attempts (
                    id,
                    job_id,
                    task_id,
                    attempt_number,
                    route_key,
                    provider,
                    gateway_model,
                    status,
                    error_message,
                    started_at,
                    finished_at
                )
                SELECT
                    %s, j.id, t.id,
                    %s, %s, %s,
                    %s, %s, %s,
                    now(), now()
                FROM jobs j
                JOIN tasks t ON t.job_id = j.id
                WHERE t.id = %s
                  AND t.job_id = j.id
                  AND j.id = %s
                  AND j.tenant_id = %s
                RETURNING id
                """,
                (
                    attempt_id,
                    attempt_number,
                    attempt.route_key,
                    attempt.provider,
                    attempt.gateway_model,
                    status,
                    attempt.error,
                    task_id,
                    job_id,
                    tenant_id,
                ),
            )

            if cur.fetchone() is None:
                raise TenantScopeError(
                    "Attempt could not be recorded in tenant scope"
                )

    return attempt_id


def complete_task(
    task_id: UUID,
    *,
    tenant_id: UUID,
) -> None:
    """Complete a same-tenant task.

    Existing completion semantics are preserved, including the absence of a
    rowcount error: a foreign or missing task is silently not completed, so
    the two are indistinguishable.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE tasks
                SET status = 'completed',
                    updated_at = now()
                WHERE id = %s
                  AND {JOB_SCOPE}
                """,
                (task_id, tenant_id),
            )


def complete_job(
    job_id: UUID,
    *,
    tenant_id: UUID,
) -> None:
    """Complete a same-tenant job (jobs carries tenant_id directly)."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE jobs
                SET status = 'completed',
                    updated_at = now()
                WHERE id = %s
                  AND {TENANT_SCOPE}
                """,
                (job_id, tenant_id),
            )


def start_attempt(
    job_id: UUID,
    task_id: UUID,
    attempt_number: int,
    route_key: str,
    provider: str,
    gateway_model: str,
    billing_mode: str = 'metered',
    *,
    tenant_id: UUID,
) -> UUID:
    attempt_id = uuid4()

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO execution_attempts (
                    id,
                    job_id,
                    task_id,
                    attempt_number,
                    route_key,
                    provider,
                    gateway_model,
                    billing_mode,
                    status,
                    started_at
                )
                SELECT
                    %s, j.id, t.id,
                    %s, %s, %s,
                    %s, %s, 'running',
                    now()
                FROM jobs j
                JOIN tasks t ON t.job_id = j.id
                WHERE t.id = %s
                  AND t.job_id = j.id
                  AND j.id = %s
                  AND j.tenant_id = %s
                RETURNING id
                """,
                (
                    attempt_id,
                    attempt_number,
                    route_key,
                    provider,
                    gateway_model,
                    billing_mode,
                    task_id,
                    job_id,
                    tenant_id,
                ),
            )

            if cur.fetchone() is None:
                raise TenantScopeError(
                    "Attempt could not be started in tenant scope"
                )

    return attempt_id


def finish_attempt(
    attempt_id: UUID,
    success: bool,
    error: str | None = None,
    *,
    tenant_id: UUID,
) -> None:
    """Finish a same-tenant attempt.

    The authoritative UPDATE proves the attempt's job belongs to the
    tenant, so a foreign attempt is left unchanged. The existing
    RuntimeError contract is preserved exactly, which keeps a foreign and a
    missing attempt on one observable path.
    """
    status = "succeeded" if success else "failed"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE execution_attempts
                SET status = %s,
                    error_message = %s,
                    finished_at = now()
                WHERE id = %s
                  AND status = 'running'
                  AND EXISTS (
                      SELECT 1
                      FROM jobs j
                      WHERE j.id = execution_attempts.job_id
                        AND j.tenant_id = %s
                  )
                """,
                (
                    status,
                    error,
                    attempt_id,
                    tenant_id,
                ),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Attempt {attempt_id} is not in running state"
                )
