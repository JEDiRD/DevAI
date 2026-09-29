from typing import Protocol


class GatewayError(RuntimeError):
    pass


class GatewayClient(Protocol):
    def complete(self, model: str, prompt: str) -> str:
        ...


class StaticGateway:
    """
    Deterministic gateway used by tests.
    Values may be strings or Exceptions.
    """

    def __init__(self, responses: dict[str, str | Exception]):
        self.responses = responses
        self.calls: list[str] = []

    def complete(self, model: str, prompt: str) -> str:
        self.calls.append(model)

        response = self.responses.get(model)

        if isinstance(response, Exception):
            raise response

        if response is None:
            raise GatewayError(f"No response configured for {model}")

        return response
