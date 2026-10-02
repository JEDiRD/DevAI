from decimal import Decimal
from uuid import UUID

from .db import connect
from .tenancy import JOB_SCOPE
from .types import ExecutionAttempt


class AccountingError(RuntimeError):
    pass


def finalize_attempt_and_budget(
    job_id: UUID,
    attempt_id: UUID,
    attempt: ExecutionAttempt,
    reserved_usd: Decimal,
    actual_usd: Decimal,
    pricing_key: str | None,
    pricing_version: int | None,
    billing_mode: str = 'metered',
    *,
    tenant_id: UUID,
) -> None:
    """Finalize an attempt and settle its budget for ``tenant_id``.

    Exactly three statements are security-authoritative and EACH carries its
    own tenant scope; none of them relies on an earlier statement having
    authorized the row:

    1. the attempt SELECT ... FOR UPDATE authorization gate, which proves
       the attempt's job belongs to the tenant;
    2. the job_budgets settlement UPDATE (metered branch), scoped directly
       through jobs.tenant_id;
    3. the execution_attempts finalization UPDATE, scoped directly through
       the attempt -> job -> tenant relationship.

    All three run in the existing transaction, so a scope rejection leaves
    no partial mutation. Transaction boundaries, accounting values, budget
    arithmetic, rowcount/error behavior and reconciliation semantics are
    unchanged.
    """

    if billing_mode not in ('free','metered','subscription','local'):
        raise AccountingError('INVALID_BILLING_MODE')
    if actual_usd < 0 or reserved_usd < 0 or actual_usd > reserved_usd:
        raise AccountingError(
            "Actual cost exceeded reserved ceiling"
        )

    status = (
        "succeeded"
        if attempt.success
        else "failed"
    )

    with connect() as conn:
        with conn.cursor() as cur:

            # (1) authorization gate: tenant-scoped by its own predicate.
            cur.execute('''SELECT a.id FROM execution_attempts a
                JOIN jobs j ON j.id = a.job_id
                WHERE a.id=%s AND a.job_id=%s
                AND a.status='running' AND a.billing_mode=%s
                AND j.tenant_id=%s
                FOR UPDATE OF a''',(attempt_id,job_id,billing_mode,tenant_id))
            if cur.fetchone() is None:
                raise AccountingError('ATTEMPT_SETTLEMENT_FAILED')

            if billing_mode == 'metered':
                _settle_metered(cur, job_id, reserved_usd, actual_usd, tenant_id)
            elif reserved_usd != 0 or actual_usd != 0 or pricing_key is not None or pricing_version is not None:
                raise AccountingError('NON_METERED_COST_MUST_BE_ZERO')
            # (3) finalization mutation: independently tenant-scoped.
            cur.execute(
                """
                UPDATE execution_attempts
                SET status=%s,error_message=%s,prompt_tokens=%s,completion_tokens=%s,
                    provider_request_id=%s,pricing_key=%s,pricing_version=%s,
                    reserved_cost_usd=%s,reconciled_cost_usd=%s,finished_at=now()
                WHERE id=%s AND job_id=%s AND status='running' AND billing_mode=%s
                AND EXISTS (
                    SELECT 1 FROM jobs j
                    WHERE j.id = execution_attempts.job_id
                      AND j.tenant_id = %s
                )
                """,
                (status,attempt.error,attempt.prompt_tokens,attempt.completion_tokens,
                 attempt.provider_request_id,pricing_key,pricing_version,reserved_usd,
                 actual_usd,attempt_id,job_id,billing_mode,tenant_id),
            )
            if cur.rowcount != 1:
                raise AccountingError('ATTEMPT_SETTLEMENT_FAILED')


def _settle_metered(cur, job_id, reserved_usd, actual_usd, tenant_id):
    # (2) budget settlement mutation: independently tenant-scoped.
    cur.execute(f"""UPDATE job_budgets SET reserved_usd=reserved_usd-%s,
        spent_usd=spent_usd+%s,updated_at=now()
        WHERE job_id=%s AND reserved_usd>=%s AND {JOB_SCOPE}""",
        (reserved_usd,actual_usd,job_id,reserved_usd,tenant_id))
    if cur.rowcount != 1:
        raise AccountingError('BUDGET_SETTLEMENT_FAILED')
