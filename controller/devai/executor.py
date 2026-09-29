from .gateway import GatewayClient, GatewayResult
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


def execute_with_fallback(
    prompt: str,
    routes: list[ModelCandidate],
    gateway: GatewayClient,
    observer: ExecutionObserver | None = None,
) -> ExecutionResult:

    observer = observer or NullExecutionObserver()
    attempts: list[ExecutionAttempt] = []

    for number, route in enumerate(routes, 1):
        gateway_model = (
            route.gateway_model or route.key
        )

        observer.attempt_started(
            number,
            route,
            gateway_model,
        )

        try:
            raw = gateway.complete(
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
