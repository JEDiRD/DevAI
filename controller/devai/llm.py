from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class LLMRequest:
    model: str
    system: str
    prompt: str
    temperature: float = 0.1


@dataclass(frozen=True)
class LLMResponse:
    content: str
    provider: str = "unknown"
    model: str = "unknown"


class LLMClient(Protocol):
    def complete(self, request: LLMRequest) -> LLMResponse:
        ...


class StaticLLMClient:
    """
    Deterministic client used by tests.
    Never performs network calls or consumes tokens.
    """

    def __init__(self, content: str):
        self.content = content
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        return LLMResponse(
            content=self.content,
            provider="static",
            model=request.model,
        )
