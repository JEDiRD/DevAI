"""Local allowlist and fail-closed execution limits. No model/process adapter yet."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import threading
import time
from typing import Protocol, Literal


class AdapterError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LocalLimits:
    max_prompt_bytes: int = 65536
    max_output_bytes: int = 65536
    max_timeout_seconds: int = 60
    max_concurrent_processes: int = 1


LIMITS = LocalLimits()  # Controller cannot override this local policy.


@dataclass(frozen=True)
class AdapterResult:
    content: str = field(repr=False)
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass(frozen=True)
class ExecutionContext:
    cancellation: threading.Event = field(repr=False)
    monotonic_deadline: float

    def check(self):
        if self.cancellation.is_set():
            raise AdapterError('EXECUTION_CANCELLED')
        if time.monotonic() >= self.monotonic_deadline:
            raise AdapterError('EXECUTION_TIMEOUT')


class LocalModelAdapter(Protocol):
    key: str
    version: str
    def execute(self, dispatch, context: ExecutionContext) -> AdapterResult: ...


class SyntheticAdapter:
    key = 'synthetic_test'
    version = '1.0'

    def execute(self, dispatch, context):
        context.check()
        return AdapterResult('REMOTE_ADAPTER_OK')


class AdapterRegistry:
    def __init__(self):
        self._allowlisted = {'synthetic_test': SyntheticAdapter()}
        self._slots = threading.BoundedSemaphore(LIMITS.max_concurrent_processes)

    @property
    def capabilities(self):
        return sorted(self._allowlisted)

    def execute(self, dispatch, context):
        if type(dispatch.spec_version) is not int or dispatch.spec_version != 1:
            raise AdapterError('UNSUPPORTED_SPEC_VERSION')
        adapter = self._allowlisted.get(dispatch.adapter_key)
        if adapter is None:
            raise AdapterError('UNSUPPORTED_ADAPTER')
        if dispatch.adapter_version != adapter.version:
            raise AdapterError('INCOMPATIBLE_ADAPTER_VERSION')
        if not dispatch.connection_id or not dispatch.idempotency_key:
            raise AdapterError('INVALID_EXECUTION_SPEC')
        if type(dispatch.execution_timeout_seconds) is not int or not 1 <= dispatch.execution_timeout_seconds <= LIMITS.max_timeout_seconds:
            raise AdapterError('TIMEOUT_LIMIT_EXCEEDED')
        if not isinstance(dispatch.prompt,str) or len(dispatch.prompt.encode('utf-8')) > LIMITS.max_prompt_bytes:
            raise AdapterError('PROMPT_LIMIT_EXCEEDED')
        if min(dispatch.deadline_at,dispatch.lease_expires_at) <= datetime.now(timezone.utc):
            raise AdapterError('DEADLINE_EXCEEDED')
        context.check()
        if not self._slots.acquire(blocking=False):
            raise AdapterError('LOCAL_CONCURRENCY_LIMIT')
        try:
            result = adapter.execute(dispatch,context)
            context.check()
            if min(dispatch.deadline_at,dispatch.lease_expires_at) <= datetime.now(timezone.utc):
                raise AdapterError('DEADLINE_EXCEEDED')
            if not isinstance(result,AdapterResult) or len(result.content.encode('utf-8')) > LIMITS.max_output_bytes:
                raise AdapterError('OUTPUT_LIMIT_EXCEEDED')
            for count in (result.prompt_tokens,result.completion_tokens):
                if count is not None and (type(count) is not int or count < 0):
                    raise AdapterError('INVALID_USAGE')
            return result
        finally:
            self._slots.release()


@dataclass(frozen=True)
class LocalProcessPolicy:
    """Defined in local adapter code only, never deserialized from a dispatch."""
    executable: Path
    working_directory: Path
    arguments: tuple[str,...] = ()
    shell: Literal[False] = False
    limits: LocalLimits = LIMITS

    def validate(self):
        if self.shell is not False or not self.executable.is_absolute() or not self.working_directory.is_absolute() or self.limits != LIMITS:
            raise AdapterError('UNSAFE_LOCAL_PROCESS_POLICY')
        if any(not isinstance(arg,str) or '\x00' in arg for arg in self.arguments):
            raise AdapterError('UNSAFE_LOCAL_PROCESS_POLICY')


def sanitized_environment():
    # No ambient token/API/session/database secrets are inherited.
    return {key:os.environ[key] for key in ('SystemRoot','WINDIR') if key in os.environ}


def bounded_redacted_stream(data: bytes):
    text=data[:LIMITS.max_output_bytes].decode('utf-8',errors='replace')
    text=re.sub(r'(?i)Bearer\s+\S+|devai_wkr_\S+|(?:api[_-]?key|password|token|secret)\s*[=:]\s*\S+', '[REDACTED]', text)
    text=re.sub(r'(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)','[REDACTED]',text)
    return text.encode('utf-8')[:LIMITS.max_output_bytes].decode('utf-8',errors='ignore')


class ProcessTreeSession(Protocol):
    def terminate_tree_and_wait(self) -> None: ...
    def bounded_result(self,context: ExecutionContext) -> AdapterResult: ...


class ProcessTreeLauncher(Protocol):
    """Future backend MUST contain descendants before user code can run.

    Windows: suspended child -> Job Object KILL_ON_JOB_CLOSE -> resume. POSIX:
    dedicated process group. Timeout/cancel/error closes/kills the entire tree
    and waits, including descendants after normal parent exit. Prompt is stdin,
    argv is a local tuple; shell=False, sanitized env and bounded streams only.
    """
    def launch(self,policy: LocalProcessPolicy, *, stdin_payload: bytes,
               environment: dict[str,str], shell: Literal[False]) -> ProcessTreeSession: ...


class DisabledProcessTreeLauncher:
    def launch(self,policy, *, stdin_payload,environment,shell=False):
        # No orphan-capable fallback to raw Popen/TerminateProcess is allowed.
        raise AdapterError('PROCESS_ADAPTER_DISABLED')
