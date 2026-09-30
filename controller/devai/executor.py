from typing import Callable

from .gateway import GatewayClient, GatewayResult, ExecutionSafetyError
from .observer import (
    ExecutionObserver,
    NullExecutionObserver,
)
from .types import (
    ExecutionAttempt,
    ExecutionResult,
    ModelCandidate,
)


class AllRoutesFailed(RuntimeError):

    def __init__(
        self,
        attempts: list[ExecutionAttempt],
    ):
        self.attempts = tuple(attempts)
        super().__init__(
            "All approved model routes failed"
        )


GatewayResolver = Callable[
    [ModelCandidate],
    GatewayClient,
]


def execute_with_fallback(
    prompt: str,
    routes: list[ModelCandidate],
    gateway: GatewayClient | None = None,
    gateway_resolver: GatewayResolver | None = None,
    observer: ExecutionObserver | None = None,
) -> ExecutionResult:

    if gateway is None and gateway_resolver is None:
        raise ValueError(
            "A gateway or gateway_resolver is required"
        )

    if gateway is not None and gateway_resolver is not None:
        raise ValueError(
            "Use gateway or gateway_resolver, not both"
        )

    observer = observer or NullExecutionObserver()
    attempts: list[ExecutionAttempt] = []

    for number, route in enumerate(routes, 1):
        gateway_model = (
            route.gateway_model or route.key
        )

        # Resolve the transport independently for this route.
        #
        # A resolver/configuration failure happens before the
        # provider attempt starts, so it must not consume budget
        # or affect provider health.
        try:
            route_gateway = (
                gateway
                if gateway is not None
                else gateway_resolver(route)
            )

        except Exception as exc:
            attempts.append(
                ExecutionAttempt(
                    route_key=route.key,
                    provider=route.provider,
                    gateway_model=gateway_model,
                    success=False,
                    error=str(exc),
                )
            )

            continue

        # Budget reservation + ledger entry happen here,
        # before the provider can be called.
        observer.attempt_started(
            number,
            route,
            gateway_model,
        )

        try:
            raw = route_gateway.complete(
                model=gateway_model,
                prompt=prompt,
            )

        except Exception as exc:
            attempt = ExecutionAttempt(
                route_key=route.key,
                provider=route.provider,
                gateway_model=gateway_model,
                success=False,
                error=str(exc),
            )

            attempts.append(attempt)

            observer.attempt_finished(
                number,
                attempt,
            )

            if isinstance(exc, ExecutionSafetyError):
                raise

            continue

        if isinstance(raw, GatewayResult):
            response = raw
        else:
            response = GatewayResult(
                content=raw
            )

        attempt = ExecutionAttempt(
            route_key=route.key,
            provider=route.provider,
            gateway_model=gateway_model,
            success=True,
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
            provider_request_id=
                response.provider_request_id,
        )

        attempts.append(attempt)

        observer.attempt_finished(
            number,
            attempt,
        )

        return ExecutionResult(
            content=response.content,
            route_key=route.key,
            provider=route.provider,
            gateway_model=gateway_model,
            attempts=tuple(attempts),
        )

    raise AllRoutesFailed(attempts)
