from decimal import Decimal
from uuid import UUID

from .budget import release_budget, reserve_budget
from .ledger_observer import LedgerExecutionObserver
from .types import ExecutionAttempt, ModelCandidate


class BudgetPolicyMissing(RuntimeError):
    pass


class BudgetedLedgerObserver:
    """
    Budget reservation happens before ledger start and before provider call.

    Current phase:
    - reserve maximum allowed amount
    - execute
    - release reservation when attempt finishes

    Actual provider cost settlement is added in the next phase.
    """

    def __init__(
        self,
        job_id: UUID,
        task_id: UUID,
        reservation_by_cost_class: dict[str, Decimal],
    ):
        self.job_id = job_id
        self.ledger = LedgerExecutionObserver(
            job_id=job_id,
            task_id=task_id,
        )
        self.reservation_by_cost_class = reservation_by_cost_class
        self._reservations: dict[int, Decimal] = {}

    def attempt_started(
        self,
        number: int,
        route: ModelCandidate,
        gateway_model: str,
    ) -> None:
        amount = self.reservation_by_cost_class.get(
            route.cost_class
        )

        if amount is None:
            raise BudgetPolicyMissing(
                f"No reservation policy for cost class {route.cost_class}"
            )

        # Atomic PostgreSQL gate.
        # If this raises, provider execution never begins.
        reserve_budget(
            self.job_id,
            amount,
        )

        try:
            self.ledger.attempt_started(
                number,
                route,
                gateway_model,
            )
        except Exception:
            release_budget(
                self.job_id,
                amount,
            )
            raise

        self._reservations[number] = amount

    def attempt_finished(
        self,
        number: int,
        attempt: ExecutionAttempt,
    ) -> None:
        amount = self._reservations[number]

        # Persist provider outcome first.
        self.ledger.attempt_finished(
            number,
            attempt,
        )

        # Reservation-only phase.
        # Real cost reconciliation comes next.
        release_budget(
            self.job_id,
            amount,
        )
