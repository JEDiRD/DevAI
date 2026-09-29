"""Local dispatch handlers. Add providers here in later checkpoints."""

from typing import Protocol

from .client import Dispatch


class DispatchHandler(Protocol):
    def execute(self, dispatch: Dispatch) -> str: ...


class SyntheticHandler:
    def execute(self, dispatch: Dispatch) -> str:
        return "WINDOWS_WORKER_OK"


class HandlerRegistry:
    def __init__(self):
        self._handlers: dict[str, DispatchHandler] = {
            "synthetic/windows": SyntheticHandler(),
        }

    def execute(self, dispatch: Dispatch) -> str:
        handler = self._handlers.get(dispatch.route_key)
        if handler is None:
            raise ValueError("Unsupported dispatch route")
        return handler.execute(dispatch)
