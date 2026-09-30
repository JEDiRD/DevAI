"""Long-running outbound Worker loop with connectivity-only backoff."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import platform as host_platform
import random
import threading
import os
import time
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
from .adapters import AdapterRegistry, AdapterError, ExecutionContext, LIMITS
from .execution_journal import ExecutionJournal


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
        adapters: AdapterRegistry | None = None,
        journal: ExecutionJournal | None = None,
    ):
        self.config = config
        self.credential_store = credential_store or WindowsDpapiCredentialStore(
            config.credential_path
        )
        token = self.credential_store.load(config.worker_id)
        self.client = client or WorkerApiClient(
            config.api_base_url, config.worker_id, token
        )
        self.adapters = adapters or AdapterRegistry()
        journal_root=Path(os.environ.get('LOCALAPPDATA',str(config.credential_path.parent)))/'DevAI'
        self.journal = journal or ExecutionJournal(journal_root/f'executions-{config.worker_id}.sqlite')
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
                    self.adapters.capabilities,
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

    def _submit(self, dispatch, *, result=None, error_message=None) -> None:
        if self.stop_event.is_set():
            # Bounded graceful shutdown acknowledgement; connectivity is never
            # retried indefinitely while SCM is waiting for STOPPED.
            try:
                self.client.fail(dispatch,'WORKER_SHUTDOWN')
            except (AuthenticationError,ConnectivityError,LeaseConflict,ProtocolError,OSError,ValueError):
                pass
            return
        backoff = Backoff()
        while not self.stop_event.is_set():
            if min(dispatch.lease_expires_at,dispatch.deadline_at) <= datetime.now(timezone.utc) or (dispatch.local_deadline_monotonic is not None and time.monotonic()>=dispatch.local_deadline_monotonic):
                log.warning("Dispatch lease expired before result acknowledgement")
                return
            try:
                self._refresh_token()
                if error_message is None:
                    self.client.complete(dispatch, result.content,
                        prompt_tokens=result.prompt_tokens,completion_tokens=result.completion_tokens)
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
        started = False
        finished = threading.Event()
        cancellation = threading.Event()
        unsafe = False
        monitor = None
        def authority():
            while not finished.wait(.25):
                try:
                    if self.stop_event.is_set() or self.client.status(dispatch) != 'claimed':
                        cancellation.set()
                        return
                except (AuthenticationError,ConnectivityError,LeaseConflict,ProtocolError,OSError,ValueError):
                    cancellation.set()  # Uncertain authority: stop, never retry execution.
                    return
        try:
            if self.stop_event.is_set() or self.client.status(dispatch) != 'claimed':
                raise AdapterError('EXECUTION_CANCELLED')
            result = self.journal.begin(dispatch)
            if result is None:
                started = True
                remaining=min(LIMITS.max_timeout_seconds,dispatch.execution_timeout_seconds,
                    (min(dispatch.lease_expires_at,dispatch.deadline_at)-datetime.now(timezone.utc)).total_seconds())
                end=time.monotonic()+max(0,remaining)
                if dispatch.local_deadline_monotonic is not None:
                    end=min(end,dispatch.local_deadline_monotonic)
                monitor = threading.Thread(target=authority,name='execution-authority',daemon=True)
                monitor.start()
                result = self.adapters.execute(dispatch,ExecutionContext(cancellation,end))
                self.journal.finish(dispatch,result=result)
        except Exception as exc:
            code=exc.code if isinstance(exc,AdapterError) else 'ADAPTER_INTERNAL_ERROR'
            unsafe = code in ('PROCESS_TREE_TERMINATION_UNCONFIRMED','PROCESS_TREE_TERMINATION_FAILED',
                'PROCESS_IO_TERMINATION_UNCONFIRMED','JOB_QUERY_FAILED')
            if unsafe:
                self.stop_event.set()
            if started:
                self.journal.finish(dispatch,error=code,termination_confirmed=not unsafe)
            if not unsafe:
                self._submit(dispatch,error_message=code)
        else:
            self._submit(dispatch, result=result)
        finally:
            finished.set()
            if monitor:
                monitor.join(timeout=2)
            if not unsafe:
                for _ in range(3):
                    try:
                        self.client.terminated(dispatch)
                        self.journal.termination_reported(dispatch)
                        break
                    except LeaseConflict:
                        break
                    except (AuthenticationError,ConnectivityError,ProtocolError,OSError,ValueError):
                        time.sleep(.1)

    def _reconcile_terminations(self):
        # Connectivity/accounting acknowledgement only: never rerun the adapter.
        for receipt in self.journal.pending_terminations()[:5]:
            if self.stop_event.is_set(): break
            try:
                if self.client.status(receipt)=='claimed':
                    self.client.fail(receipt,'EXECUTION_OUTCOME_UNKNOWN')
                self.client.terminated(receipt)
                self.journal.termination_reported(receipt)
            except LeaseConflict:
                # Wrong version/tenant is retained for audit, never broaden scope.
                continue
            except (AuthenticationError,ConnectivityError,ProtocolError,OSError,ValueError):
                break

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
                    self._reconcile_terminations()
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
