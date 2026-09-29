"""Long-running outbound Worker loop with connectivity-only backoff."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import platform as host_platform
import random
import threading
from uuid import UUID

from .client import (
    AuthenticationError,
    ConnectivityError,
    LeaseConflict,
    ProtocolError,
    WorkerApiClient,
)
from .credential_store import (
    CredentialStore,
    WindowsDpapiCredentialStore,
    default_credential_path,
)
from .handlers import HandlerRegistry


log = logging.getLogger(__name__)


@dataclass(frozen=True)
class AgentConfig:
    worker_id: UUID
    api_base_url: str
    credential_path: Path
    heartbeat_seconds: float = 30
    poll_seconds: float = 5

    @classmethod
    def load(cls, path: Path) -> "AgentConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        heartbeat = float(data.get("heartbeat_seconds", 30))
        poll = float(data.get("poll_seconds", 5))
        if not (1 <= heartbeat <= 60) or poll <= 0:
            raise ValueError("Invalid Worker timing configuration")
        return cls(
            worker_id=UUID(data["worker_id"]),
            api_base_url=data["api_base_url"],
            credential_path=(
                Path(data["credential_path"])
                if "credential_path" in data
                else default_credential_path()
            ),
            heartbeat_seconds=heartbeat,
            poll_seconds=poll,
        )


class Backoff:
    def __init__(self, maximum: float = 60):
        self.maximum = maximum
        self.failures = 0

    def reset(self) -> None:
        self.failures = 0

    def next_delay(self) -> float:
        self.failures += 1
        base = min(self.maximum, 2 ** min(self.failures - 1, 6))
        return min(self.maximum, base * random.uniform(0.8, 1.2))


class WorkerAgent:
    def __init__(
        self,
        config: AgentConfig,
        credential_store: CredentialStore | None = None,
        *,
        client: WorkerApiClient | None = None,
        handlers: HandlerRegistry | None = None,
    ):
        self.config = config
        self.credential_store = credential_store or WindowsDpapiCredentialStore(
            config.credential_path
        )
        token = self.credential_store.load(config.worker_id)
        self.client = client or WorkerApiClient(
            config.api_base_url, config.worker_id, token
        )
        self.handlers = handlers or HandlerRegistry()
        self.stop_event = threading.Event()
        self.online = threading.Event()

    def stop(self) -> None:
        self.stop_event.set()

    def _refresh_token(self) -> None:
        self.client.replace_token(
            self.credential_store.load(self.config.worker_id)
        )

    def _heartbeat_loop(self) -> None:
        backoff = Backoff()
        delay = 0.0
        while not self.stop_event.wait(delay):
            try:
                self._refresh_token()
                self.client.heartbeat(
                    host_platform.system().lower(),
                    host_platform.machine().lower(),
                )
                if not self.online.is_set():
                    log.info("Worker connected")
                self.online.set()
                backoff.reset()
                delay = self.config.heartbeat_seconds
            except (
                AuthenticationError,
                ConnectivityError,
                ProtocolError,
                OSError,
                ValueError,
            ) as exc:
                if self.online.is_set():
                    log.warning("Worker connection lost: %s", type(exc).__name__)
                self.online.clear()
                delay = backoff.next_delay()

    def _submit(self, dispatch, *, content=None, error_message=None) -> None:
        backoff = Backoff()
        while not self.stop_event.is_set():
            if dispatch.lease_expires_at <= datetime.now(timezone.utc):
                log.warning("Dispatch lease expired before result acknowledgement")
                return
            try:
                self._refresh_token()
                if error_message is None:
                    self.client.complete(dispatch, content)
                else:
                    self.client.fail(dispatch, error_message)
                log.info("Dispatch result acknowledged")
                return
            except LeaseConflict:
                log.warning("Dispatch lease no longer available")
                return
            except ProtocolError:
                log.warning("Controller rejected the dispatch result")
                return
            except (
                AuthenticationError,
                ConnectivityError,
                OSError,
                ValueError,
            ) as exc:
                log.warning("Result submission unavailable: %s", type(exc).__name__)
                self.stop_event.wait(backoff.next_delay())

    def _process(self, dispatch) -> None:
        try:
            content = self.handlers.execute(dispatch)
        except Exception as exc:
            self._submit(
                dispatch,
                error_message=f"handler_error:{type(exc).__name__}",
            )
        else:
            self._submit(dispatch, content=content)

    def run_forever(self) -> None:
        heartbeat = threading.Thread(
            target=self._heartbeat_loop,
            name="worker-heartbeat",
            daemon=True,
        )
        heartbeat.start()
        claim_backoff = Backoff()
        try:
            while not self.stop_event.is_set():
                if not self.online.wait(timeout=1):
                    continue
                try:
                    dispatch = self.client.claim()
                    claim_backoff.reset()
                    if dispatch is None:
                        self.stop_event.wait(self.config.poll_seconds)
                        continue
                    self._process(dispatch)
                except (
                    AuthenticationError,
                    ConnectivityError,
                    ProtocolError,
                ) as exc:
                    if isinstance(exc, AuthenticationError):
                        self.online.clear()
                    log.warning("Claim unavailable: %s", type(exc).__name__)
                    self.stop_event.wait(claim_backoff.next_delay())
        finally:
            self.stop_event.set()
            heartbeat.join(timeout=2)
