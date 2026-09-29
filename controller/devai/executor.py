from .gateway import GatewayClient
from .observer import ExecutionObserver, NullExecutionObserver
from .types import ExecutionAttempt, ExecutionResult, ModelCandidate


class AllRoutesFailed(RuntimeError):

    def __init__(self, attempts: list[ExecutionAttempt]):
        self.attempts = tuple(attempts)
        super().__init__("All approved model routes failed")


def execute_with_fallback(
    prompt: str,
    routes: list[ModelCandidate],
    gateway: GatewayClient,
    observer: ExecutionObserver | None = None,
) -> ExecutionResult:

    observer = observer or NullExecutionObserver()
    attempts: list[ExecutionAttempt] = []

    for number, route in enumerate(routes, 1):
        gateway_model = route.gateway_model or route.key

        # Must succeed before provider execution.
        observer.attempt_started(
            number,
            route,
            gateway_model,
        )

        try:
            content = gateway.complete(
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

            # Accounting failure here propagates.
            # We do NOT continue to another provider blindly.
            observer.attempt_finished(
                number,
                attempt,
            )
            continue

        attempt = ExecutionAttempt(
            route_key=route.key,
            provider=route.provider,
            gateway_model=gateway_model,
            success=True,
        )

        attempts.append(attempt)

        # If final accounting fails after a provider call,
        # fail hard instead of making another provider call.
        observer.attempt_finished(
            number,
            attempt,
        )

        return ExecutionResult(
            content=content,
            route_key=route.key,
            provider=route.provider,
            gateway_model=gateway_model,
            attempts=tuple(attempts),
        )

    raise AllRoutesFailed(attempts)
