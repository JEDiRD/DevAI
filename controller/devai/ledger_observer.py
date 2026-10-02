from uuid import UUID

from .ledger import finish_attempt, start_attempt
from .types import ExecutionAttempt, ModelCandidate


class LedgerExecutionObserver:
    """
    Persists attempt state before and after every provider call.

    If attempt_started() cannot be persisted, execution must not reach
    the provider. This keeps untracked provider calls from occurring.
    """

    def __init__(
        self,
        job_id: UUID,
        task_id: UUID,
        *,
        tenant_id: UUID,
    ):
        self.job_id = job_id
        self.task_id = task_id
        # Immutable execution context. Every ledger mutation this observer
        # performs uses this value; it is never taken from a route, payload
        # or database row.
        self.tenant_id = tenant_id
        self._attempt_ids: dict[int, UUID] = {}

    def attempt_started(
        self,
        number: int,
        route: ModelCandidate,
        gateway_model: str,
    ) -> None:
        attempt_id = start_attempt(
            job_id=self.job_id,
            task_id=self.task_id,
            attempt_number=number,
            route_key=route.key,
            provider=route.provider,
            gateway_model=gateway_model,
            tenant_id=self.tenant_id,
        )

        self._attempt_ids[number] = attempt_id

    def attempt_finished(
        self,
        number: int,
        attempt: ExecutionAttempt,
    ) -> None:
        attempt_id = self._attempt_ids.get(number)

        if attempt_id is None:
            raise RuntimeError(
                f"Missing ledger attempt for attempt {number}"
            )

        finish_attempt(
            attempt_id=attempt_id,
            success=attempt.success,
            error=attempt.error,
            tenant_id=self.tenant_id,
        )
