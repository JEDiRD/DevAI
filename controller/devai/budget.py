from decimal import Decimal

from .db import connect


class BudgetError(RuntimeError):
    pass


class BudgetNotConfigured(BudgetError):
    pass


class BudgetExceeded(BudgetError):
    pass


def configure_budget(
    job_id,
    limit_usd: Decimal,
) -> None:
    if limit_usd <= 0:
        raise ValueError("limit_usd must be positive")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO job_budgets (
                    job_id,
                    limit_usd
                )
                VALUES (%s, %s)
                ON CONFLICT (job_id)
                DO UPDATE SET
                    limit_usd = EXCLUDED.limit_usd,
                    updated_at = now()
                """,
                (job_id, limit_usd),
            )


def reserve_budget(
    job_id,
    amount_usd: Decimal,
) -> None:
    if amount_usd < 0:
        raise ValueError("amount_usd cannot be negative")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE job_budgets
                SET reserved_usd = reserved_usd + %s,
                    updated_at = now()
                WHERE job_id = %s
                  AND (
                      reserved_usd +
                      spent_usd +
                      %s
                  ) <= limit_usd
                RETURNING job_id
                """,
                (
                    amount_usd,
                    job_id,
                    amount_usd,
                ),
            )

            if cur.fetchone():
                return

            cur.execute(
                """
                SELECT 1
                FROM job_budgets
                WHERE job_id = %s
                """,
                (job_id,),
            )

            if cur.fetchone() is None:
                raise BudgetNotConfigured(
                    f"No budget configured for job {job_id}"
                )

            raise BudgetExceeded(
                f"Budget reservation denied for job {job_id}"
            )


def release_budget(
    job_id,
    amount_usd: Decimal,
) -> None:
    if amount_usd < 0:
        raise ValueError("amount_usd cannot be negative")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE job_budgets
                SET reserved_usd = reserved_usd - %s,
                    updated_at = now()
                WHERE job_id = %s
                  AND reserved_usd >= %s
                """,
                (
                    amount_usd,
                    job_id,
                    amount_usd,
                ),
            )

            if cur.rowcount != 1:
                raise BudgetError(
                    "Cannot release more budget than reserved"
                )


def settle_budget(
    job_id,
    reserved_usd: Decimal,
    actual_usd: Decimal,
) -> None:
    if reserved_usd < 0 or actual_usd < 0:
        raise ValueError("cost values cannot be negative")

    if actual_usd > reserved_usd:
        raise BudgetError(
            "Actual cost exceeds reserved ceiling"
        )

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE job_budgets
                SET reserved_usd = reserved_usd - %s,
                    spent_usd = spent_usd + %s,
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
                raise BudgetError(
                    "Budget settlement could not be completed"
                )


def get_budget(job_id):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    limit_usd,
                    reserved_usd,
                    spent_usd
                FROM job_budgets
                WHERE job_id = %s
                """,
                (job_id,),
            )

            row = cur.fetchone()

            if row is None:
                raise BudgetNotConfigured(
                    f"No budget configured for job {job_id}"
                )

            return row
