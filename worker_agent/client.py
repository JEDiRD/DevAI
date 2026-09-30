"""Outbound HTTP protocol for the Worker Control API."""

from dataclasses import dataclass, field
from datetime import datetime
import time
import ipaddress
import json
from urllib import error, request
from urllib.parse import urlsplit
from uuid import UUID


class ConnectivityError(RuntimeError):
    pass


class AuthenticationError(RuntimeError):
    pass


class LeaseConflict(RuntimeError):
    pass


class ProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class Dispatch:
    id: UUID
    route_key: str
    gateway_model: str
    prompt: str = field(repr=False)
    claim_version: int
    lease_expires_at: datetime
    connection_id: UUID
    adapter_key: str
    execution_timeout_seconds: int
    spec_version: int
    adapter_version: str
    deadline_at: datetime
    idempotency_key: UUID
    local_deadline_monotonic: float | None = field(default=None,repr=False)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def validate_private_base_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Worker API URL must be a private origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Worker API URL must use a numeric private IP") from exc
    tailscale = ipaddress.ip_network("100.64.0.0/10")
    if address not in tailscale and not address.is_loopback:
        raise ValueError("Worker API URL must use Tailscale or loopback")
    return base_url.rstrip("/")


class WorkerApiClient:
    def __init__(
        self,
        base_url: str,
        worker_id: UUID,
        token: str,
        *,
        timeout: float = 10,
        opener=None,
    ):
        self.base_url = validate_private_base_url(base_url)
        self.worker_id = worker_id
        self._token = token
        self.timeout = timeout
        # Never route the bearer token through an ambient HTTP proxy or a
        # redirect to a different host.
        self._opener = opener or request.build_opener(
            request.ProxyHandler({}), _NoRedirect()
        )

    def replace_token(self, token: str) -> None:
        self._token = token

    def _post(self, path: str, payload: dict | None = None):
        body = json.dumps(payload or {}).encode("utf-8")
        outgoing = request.Request(
            self.base_url + path,
            data=body,
            headers={
                "Authorization": "Bearer " + self._token,
                "X-Worker-Id": str(self.worker_id),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener.open(outgoing, timeout=self.timeout) as incoming:
                status = incoming.status
                raw = incoming.read(1_000_001)
                if len(raw)>1_000_000:
                    raise ProtocolError('Controller response exceeds local limit')
        except error.HTTPError as exc:
            if exc.code == 401 or exc.code == 403:
                raise AuthenticationError("Worker authentication rejected") from None
            if exc.code == 409:
                raise LeaseConflict("Dispatch lease unavailable") from None
            if exc.code >= 500:
                raise ConnectivityError("Controller unavailable") from None
            raise ProtocolError(f"Controller rejected request: HTTP {exc.code}") from None
        except (error.URLError, TimeoutError, OSError):
            raise ConnectivityError("Controller connection unavailable") from None

        if status == 204:
            return None
        if status != 200:
            raise ProtocolError(f"Unexpected Controller status: {status}")
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ProtocolError("Controller returned invalid JSON") from None

    def heartbeat(self, platform: str, architecture: str, capabilities=None) -> None:
        result = self._post(
            "/v1/worker/heartbeat",
            {"platform": platform, "architecture": architecture, "capabilities": capabilities},
        )
        if result is not None:
            raise ProtocolError("Unexpected heartbeat response")

    def claim(self) -> Dispatch | None:
        started=time.monotonic()
        data = self._post("/v1/worker/claim")
        if data is None:
            return None
        try:
            expected={'id','route_key','gateway_model','prompt','claim_version','lease_expires_at',
                'connection_id','adapter_key','execution_timeout_seconds','spec_version',
                'adapter_version','deadline_at','idempotency_key','server_time'}
            if set(data)!=expected:
                raise ValueError('unexpected execution fields')
            expires_at = datetime.fromisoformat(
                data["lease_expires_at"].replace("Z", "+00:00")
            )
            if expires_at.tzinfo is None:
                raise ValueError("naive lease timestamp")
            version = int(data["claim_version"])
            if version < 1:
                raise ValueError("invalid claim version")
            deadline=datetime.fromisoformat(data['deadline_at'].replace('Z','+00:00'))
            server_time=datetime.fromisoformat(data['server_time'].replace('Z','+00:00'))
            if deadline.tzinfo is None or server_time.tzinfo is None:
                raise ValueError('naive deadline')
            return Dispatch(
                id=UUID(data["id"]),
                route_key=data["route_key"],
                gateway_model=data["gateway_model"],
                prompt=data["prompt"],
                claim_version=version,
                lease_expires_at=expires_at,
                connection_id=UUID(data['connection_id']),adapter_key=data['adapter_key'],
                execution_timeout_seconds=data['execution_timeout_seconds'],
                spec_version=data['spec_version'],adapter_version=data['adapter_version'],
                deadline_at=deadline,idempotency_key=UUID(data['idempotency_key']),
                local_deadline_monotonic=started+max(0,(min(deadline,expires_at)-server_time).total_seconds()),
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ProtocolError("Controller returned invalid dispatch") from None

    def complete(self, dispatch: Dispatch, content: str, *, prompt_tokens=None,completion_tokens=None) -> None:
        result = self._post(
            f"/v1/worker/dispatches/{dispatch.id}/complete",
            {"claim_version": dispatch.claim_version, "content": content,
             "prompt_tokens":prompt_tokens,"completion_tokens":completion_tokens},
        )
        if result is not None:
            raise ProtocolError("Unexpected completion response")

    def fail(self, dispatch: Dispatch, error_message: str) -> None:
        result = self._post(
            f"/v1/worker/dispatches/{dispatch.id}/fail",
            {
                "claim_version": dispatch.claim_version,
                "error": error_message[:2000],
            },
        )
        if result is not None:
            raise ProtocolError("Unexpected failure response")
