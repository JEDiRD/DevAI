from uuid import UUID

from .provider_registry import (
    record_route_failure,
    record_route_success,
)
from .types import ExecutionAttempt, ModelCandidate


class RouteHealthObserver:

    def __init__(
        self,
        delegate,
        tenant_id: UUID,
    ):
        self.delegate = delegate
        self.tenant_id = tenant_id
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

        if attempt.success:
            record_route_success(
                self.tenant_id,
                route_key,
            )
        else:
            record_route_failure(
                self.tenant_id,
                route_key,
                attempt.error or "provider execution failed",
            )

        self.delegate.attempt_finished(
            number,
            attempt,
        )
