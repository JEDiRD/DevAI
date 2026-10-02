from decimal import Decimal
from uuid import UUID

from .accounting import (
    finalize_attempt_and_budget,
)
from .budget import (
    release_budget,
    reserve_budget,
)
from .ledger import start_attempt
from .reconciliation import start_metered_attempt, defer_missing_usage
from .pricing import (
    calculate_cost,
    get_active_price,
)
from .types import (
    ExecutionAttempt,
    ModelCandidate,
)


class BudgetPolicyMissing(RuntimeError):
    pass


class UsageMissing(RuntimeError):
    pass


class BudgetedLedgerObserver:

    def __init__(
        self,
        job_id: UUID,
        task_id: UUID,
        reservation_by_cost_class:
            dict[str, Decimal],
        *,
        tenant_id: UUID,
    ):
        self.job_id = job_id
        self.task_id = task_id
        # Immutable execution context from the already-authorized RuntimeTask.
        # The same value is used for the whole lifecycle: it is never derived
        # from a mutable payload field and cannot be overridden per invocation.
        self.tenant_id = tenant_id
        self.reservation_by_cost_class = (
            reservation_by_cost_class
        )

        self._state = {}

    def attempt_started(
        self,
        number: int,
        route: ModelCandidate,
        gateway_model: str,
    ) -> None:

        mode = route.billing_mode
        if mode not in ('free','metered','subscription','local'):
            raise BudgetPolicyMissing('INVALID_BILLING_MODE')
        if mode != 'metered':
            attempt_id = start_attempt(job_id=self.job_id, task_id=self.task_id,
                attempt_number=number, route_key=route.key, provider=route.provider,
                gateway_model=gateway_model, billing_mode=mode,
                tenant_id=self.tenant_id)
            self._state[number] = (attempt_id, Decimal(0), None, mode)
            return
        reservation = (
            self.reservation_by_cost_class.get(
                route.cost_class
            )
        )

        if reservation is None:
            raise BudgetPolicyMissing(
                f"No reservation for "
                f"{route.cost_class}"
            )

        pricing_key = (
            route.pricing_key
            or route.key
        )

        price = get_active_price(
            pricing_key
        )

        attempt_id = start_metered_attempt(job_id=self.job_id,task_id=self.task_id,
            number=number,route=route,model=gateway_model,price=price,reservation=reservation,
            tenant_id=self.tenant_id)

        self._state[number] = (
            attempt_id,
            reservation,
            price,
            mode,
        )

    def attempt_finished(
        self,
        number: int,
        attempt: ExecutionAttempt,
    ) -> None:

        (
            attempt_id,
            reservation,
            price,
            billing_mode,
        ) = self._state[number]

        if billing_mode != 'metered':
            actual = Decimal(0)
        elif (
            attempt.prompt_tokens is None
            or attempt.completion_tokens is None
        ):
            defer_missing_usage(attempt_id=attempt_id,result_success=attempt.success,
            tenant_id=self.tenant_id)
            raise UsageMissing('METERED_USAGE_REQUIRED')

        else:
            actual = calculate_cost(
                price,
                attempt.prompt_tokens,
                attempt.completion_tokens,
            )

        finalize_attempt_and_budget(
            job_id=self.job_id,
            attempt_id=attempt_id,
            attempt=attempt,
            reserved_usd=reservation,
            actual_usd=actual,
            pricing_key=price.pricing_key if price else None,
            pricing_version=price.version if price else None,
            billing_mode=billing_mode,
            tenant_id=self.tenant_id,
        )
