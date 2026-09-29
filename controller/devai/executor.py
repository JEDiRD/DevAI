from .gateway import GatewayClient
from .types import ExecutionAttempt, ExecutionResult, ModelCandidate


class AllRoutesFailed(RuntimeError):

    def __init__(self, attempts: list[ExecutionAttempt]):
        self.attempts = tuple(attempts)
        super().__init__("All approved model routes failed")


def execute_with_fallback(
    prompt: str,
    routes: list[ModelCandidate],
    gateway: GatewayClient,
) -> ExecutionResult:
    """
    Execute each approved route at most once.

    This Controller owns fallback authority.
    It never retries the same route automatically.
    """
    attempts: list[ExecutionAttempt] = []

    for route in routes:
        gateway_model = route.gateway_model or route.key

        try:
            content = gateway.complete(
                model=gateway_model,
                prompt=prompt,
            )

            attempts.append(
                ExecutionAttempt(
                    route_key=route.key,
                    provider=route.provider,
                    gateway_model=gateway_model,
                    success=True,
                )
            )

            return ExecutionResult(
                content=content,
                route_key=route.key,
                provider=route.provider,
                gateway_model=gateway_model,
                attempts=tuple(attempts),
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

    raise AllRoutesFailed(attempts)
