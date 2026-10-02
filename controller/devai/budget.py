"""Per-job budget operations.

Every operation takes a REQUIRED keyword-only ``tenant_id``. There is no
default and no compatibility bypass: omitting it is a TypeError, and
passing ``None`` is not a valid substitute for a tenant.

Provenance: ``tenant_id`` is expected to come from an already-authorized
job context or a trusted boundary context. This layer does NOT authenticate
request input and must not be handed a tenant id taken directly from an
unauthenticated caller. Authorization of the request is the caller's job;
this module's responsibility is to make every statement enforce the tenant
it was given.

Tenant scope is embedded in each SQL statement itself rather than applied as
a preceding pre-check, because a pre-check plus an unscoped mutation leaves
a time-of-check/time-of-use gap. ``job_budgets`` carries no tenant column,
so scope is expressed through the owning job using the accepted
``tenancy.JOB_SCOPE`` fragment, which contributes exactly one tenant
placeholder as its final parameter.

Failure modes are deliberately uniform: a foreign job, a missing job and a
missing budget row all raise ``BudgetNotConfigured``. In particular a
foreign job must never surface as ``BudgetExceeded``, which would leak that
some budget exists for that identifier.
"""

from decimal import Decimal
from uuid import UUID

from .db import connect
from .tenancy import JOB_SCOPE


class BudgetError(RuntimeError):
    pass


class BudgetNotConfigured(BudgetError):
    pass


class BudgetExceeded(BudgetError):
    pass


def configure_budget(
    job_id: UUID,
    limit_usd: Decimal,
    *,
    tenant_id: UUID,
) -> None:
    """Create or update the budget for a job owned by ``tenant_id``.

    The row is written by an INSERT ... SELECT that draws its key from
    ``jobs`` filtered by tenant, so the mutation itself is tenant-scoped:
    a foreign or missing job produces no row at all. ON CONFLICT behaviour
    is unchanged.
    """
    if limit_usd <= 0:
        raise ValueError("limit_usd must be positive")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO job_budgets (
                    job_id,
                    limit_usd
                )
                SELECT id, %s
                FROM jobs
                WHERE id = %s
                  AND tenant_id = %s
                ON CONFLICT (job_id)
                DO UPDATE SET
                    limit_usd = EXCLUDED.limit_usd,
                    updated_at = now()
                """,
                (limit_usd, job_id, tenant_id),
            )

            if cur.rowcount != 1:
                # Uniform: never distinguishes a foreign job from a
                # missing one, so this is not a tenant-existence oracle.
                raise BudgetNotConfigured(
                    "Budget could not be configured for the requested job"
                )


def reserve_budget(
    job_id: UUID,
    amount_usd: Decimal,
    *,
    tenant_id: UUID,
) -> None:
    """Reserve ``amount_usd`` against a same-tenant budget."""
    if amount_usd < 0:
        raise ValueError("amount_usd cannot be negative")

    with connect() as conn:
        with conn.cursor() as cur:
            # JOB_SCOPE contributes one tenant parameter at its own final
            # position, so the tenant value follows job_id here.
            cur.execute(
                f"""
                UPDATE job_budgets
                SET reserved_usd = reserved_usd + %s,
                    updated_at = now()
                WHERE job_id = %s
                  AND ({JOB_SCOPE})
                  AND (
                      reserved_usd +
                      spent_usd +
                      recovery_exposure_usd +
                      unpriced_exposure_usd +
                      %s
                  ) <= limit_usd
                RETURNING job_id
                """,
                (
                    amount_usd,
                    job_id,
                    tenant_id,
                    amount_usd,
                ),
            )

            if cur.fetchone():
                return

            # Fallback must be tenant-scoped too, otherwise a foreign budget
            # would be reported as exceeded and leak its existence.
            cur.execute(
                f"""
                SELECT 1
                FROM job_budgets
                WHERE job_id = %s
                  AND {JOB_SCOPE}
                """,
                (job_id, tenant_id),
            )

            if cur.fetchone() is None:
                raise BudgetNotConfigured(
                    "No budget configured for the requested job"
                )

            raise BudgetExceeded(
                "Budget reservation denied for the requested job"
            )


def release_budget(
    job_id: UUID,
    amount_usd: Decimal,
    *,
    tenant_id: UUID,
) -> None:
    """Release a same-tenant reservation."""
    if amount_usd < 0:
        raise ValueError("amount_usd cannot be negative")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE job_budgets
                SET reserved_usd = reserved_usd - %s,
                    updated_at = now()
                WHERE job_id = %s
                  AND reserved_usd >= %s
                  AND {JOB_SCOPE}
                """,
                (
                    amount_usd,
                    job_id,
                    amount_usd,
                    tenant_id,
                ),
            )

            if cur.rowcount != 1:
                raise BudgetError(
                    "Cannot release more budget than reserved"
                )


def settle_budget(
    job_id: UUID,
    reserved_usd: Decimal,
    actual_usd: Decimal,
    *,
    tenant_id: UUID,
) -> None:
    """Settle a same-tenant reservation into spent budget."""
    if reserved_usd < 0 or actual_usd < 0:
        raise ValueError("cost values cannot be negative")

    if actual_usd > reserved_usd:
        raise BudgetError(
            "Actual cost exceeds reserved ceiling"
        )

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE job_budgets
                SET reserved_usd = reserved_usd - %s,
                    spent_usd = spent_usd + %s,
                    updated_at = now()
                WHERE job_id = %s
                  AND reserved_usd >= %s
                  AND {JOB_SCOPE}
                """,
                (
                    reserved_usd,
                    actual_usd,
                    job_id,
                    reserved_usd,
                    tenant_id,
                ),
            )

            if cur.rowcount != 1:
                raise BudgetError(
                    "Budget settlement could not be completed"
                )


def get_budget(job_id: UUID, *, tenant_id: UUID):
    """Return (limit_usd, reserved_usd, spent_usd) for a same-tenant job."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    limit_usd,
                    reserved_usd,
                    spent_usd
                FROM job_budgets
                WHERE job_id = %s
                  AND {JOB_SCOPE}
                """,
                (job_id, tenant_id),
            )

            row = cur.fetchone()

            if row is None:
                # Uniform for a missing budget and a foreign job alike.
                raise BudgetNotConfigured(
                    "No budget configured for the requested job"
                )

            return row