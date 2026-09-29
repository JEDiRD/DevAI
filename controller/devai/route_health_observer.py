from .provider_registry import (
    record_route_failure,
    record_route_success,
)
from .types import ExecutionAttempt, ModelCandidate


class RouteHealthObserver:
    """
    Wraps another execution observer.

    Provider health is recorded immediately when an attempt finishes,
    independently of whether a later fallback route succeeds or fails.
    """

    def __init__(self, delegate):
        self.delegate = delegate
        self._routes: dict[int, str] = {}

    def attempt_started(
        self,
        number: int,
        route: ModelCandidate,
        gateway_model: str,
    ) -> None:
        self._routes[number] = route.key

        self.delegate.attempt_started(
            number,
            route,
            gateway_model,
        )

    def attempt_finished(
        self,
        number: int,
        attempt: ExecutionAttempt,
    ) -> None:
        route_key = self._routes[number]

        # Provider health represents the provider outcome,
        # not accounting/persistence health.
        if attempt.success:
            record_route_success(route_key)
        else:
            record_route_failure(
                route_key,
                attempt.error or "provider execution failed",
            )

        # Accounting remains authoritative and may still fail hard.
        self.delegate.attempt_finished(
            number,
            attempt,
        )
