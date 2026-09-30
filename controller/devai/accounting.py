from decimal import Decimal
from uuid import UUID

from .db import connect
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
) -> None:

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

            if billing_mode == 'metered':
                _settle_metered(cur, job_id, reserved_usd, actual_usd)
            elif reserved_usd != 0 or actual_usd != 0 or pricing_key is not None or pricing_version is not None:
                raise AccountingError('NON_METERED_COST_MUST_BE_ZERO')
            cur.execute(
                """
                UPDATE execution_attempts
                SET status=%s,error_message=%s,prompt_tokens=%s,completion_tokens=%s,
                    provider_request_id=%s,pricing_key=%s,pricing_version=%s,
                    reserved_cost_usd=%s,reconciled_cost_usd=%s,finished_at=now()
                WHERE id=%s AND job_id=%s AND status='running' AND billing_mode=%s
                """,
                (status,attempt.error,attempt.prompt_tokens,attempt.completion_tokens,
                 attempt.provider_request_id,pricing_key,pricing_version,reserved_usd,
                 actual_usd,attempt_id,job_id,billing_mode),
            )
            if cur.rowcount != 1:
                raise AccountingError('ATTEMPT_SETTLEMENT_FAILED')


def _settle_metered(cur, job_id, reserved_usd, actual_usd):
    cur.execute("""UPDATE job_budgets SET reserved_usd=reserved_usd-%s,
        spent_usd=spent_usd+%s,updated_at=now()
        WHERE job_id=%s AND reserved_usd>=%s""",
        (reserved_usd,actual_usd,job_id,reserved_usd))
    if cur.rowcount != 1:
        raise AccountingError('BUDGET_SETTLEMENT_FAILED')
