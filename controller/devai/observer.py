from typing import Protocol

from .types import ExecutionAttempt, ModelCandidate


class ExecutionObserver(Protocol):
    def attempt_started(
        self,
        number: int,
        route: ModelCandidate,
        gateway_model: str,
    ) -> None:
        ...

    def attempt_finished(
        self,
        number: int,
        attempt: ExecutionAttempt,
    ) -> None:
        ...


class NullExecutionObserver:
    def attempt_started(
        self,
        number: int,
        route: ModelCandidate,
        gateway_model: str,
    ) -> None:
        pass

    def attempt_finished(
        self,
        number: int,
        attempt: ExecutionAttempt,
    ) -> None:
        pass
