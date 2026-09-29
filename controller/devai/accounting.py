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
    pricing_key: str,
    pricing_version: int,
) -> None:

    if actual_usd > reserved_usd:
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

            cur.execute(
                """
                UPDATE job_budgets
                SET reserved_usd =
                        reserved_usd - %s,
                    spent_usd =
                        spent_usd + %s,
                    updated_at = now()
                WHERE job_id = %s
                  AND reserved_usd >= %s
                """,
                (
                    reserved_usd,
                    actual_usd,
                    job_id,
                    reserved_usd,
                ),
            )

            if cur.rowcount != 1:
                raise AccountingError(
                    "Budget settlement failed"
                )

            cur.execute(
                """
                UPDATE execution_attempts
                SET status = %s,
                    error_message = %s,
                    prompt_tokens = %s,
                    completion_tokens = %s,
                    provider_request_id = %s,
                    pricing_key = %s,
                    pricing_version = %s,
                    reserved_cost_usd = %s,
                    reconciled_cost_usd = %s,
                    finished_at = now()
                WHERE id = %s
                  AND status = 'running'
                """,
                (
                    status,
                    attempt.error,
                    attempt.prompt_tokens,
                    attempt.completion_tokens,
                    attempt.provider_request_id,
                    pricing_key,
                    pricing_version,
                    reserved_usd,
                    actual_usd,
                    attempt_id,
                ),
            )

            if cur.rowcount != 1:
                raise AccountingError(
                    "Attempt settlement failed"
                )
