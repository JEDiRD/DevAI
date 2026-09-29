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
    ):
        self.job_id = job_id
        self.task_id = task_id
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

        reserve_budget(
            self.job_id,
            reservation,
        )

        try:
            attempt_id = start_attempt(
                job_id=self.job_id,
                task_id=self.task_id,
                attempt_number=number,
                route_key=route.key,
                provider=route.provider,
                gateway_model=gateway_model,
            )
        except Exception:
            release_budget(
                self.job_id,
                reservation,
            )
            raise

        self._state[number] = (
            attempt_id,
            reservation,
            price,
            route.cost_class,
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
            cost_class,
        ) = self._state[number]

        if (
            attempt.prompt_tokens is None
            or attempt.completion_tokens is None
        ):
            if attempt.success and cost_class != "free":
                raise UsageMissing(
                    "Paid successful call returned "
                    "without token usage"
                )

            actual = Decimal("0")

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
            pricing_key=price.pricing_key,
            pricing_version=price.version,
        )
