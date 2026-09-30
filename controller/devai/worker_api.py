"""Authenticated, Worker-only control surface.

Provisioning and token rotation are controller administration operations,
not routes exposed to Workers.
"""

from typing import Annotated
from datetime import datetime, timezone
from uuid import UUID
import json
import logging

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from .db import connect
from .worker_dispatch import (
    DispatchLeaseLost,
    DispatchUnavailable,
    claim_next_dispatch,
    complete_dispatch,
    fail_dispatch,
)
from .worker_identity import (
    WorkerAuthenticationError,
    WorkerPrincipal,
    authenticate_worker_token,
)
from .worker_registry import WorkerNotFound, heartbeat_worker


app = FastAPI(
    title="Dev AI Worker Control API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def auth_failure(status: int) -> None:
    # Fixed schema only: never include token, headers, body or exception text.
    logging.getLogger('devai.security').warning(
        'DEVAI_SECURITY %s',
        json.dumps({'kind': 'worker_auth_failure', 'status': status}),
    )


def require_worker(
    authorization: Annotated[str | None, Header()] = None,
    x_worker_id: Annotated[UUID | None, Header()] = None,
) -> WorkerPrincipal:
    scheme, separator, token = (authorization or "").partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token:
        auth_failure(401)
        raise HTTPException(
            status_code=401,
            detail="Worker authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        principal = authenticate_worker_token(token)
    except WorkerAuthenticationError:
        auth_failure(401)
        raise HTTPException(
            status_code=401,
            detail="Invalid Worker credential",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    if x_worker_id is not None and x_worker_id != principal.worker_node_id:
        auth_failure(403)
        raise HTTPException(status_code=403, detail="Worker identity mismatch")
    return principal


Principal = Annotated[WorkerPrincipal, Depends(require_worker)]


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    platform: str | None = Field(default=None, max_length=80)
    architecture: str | None = Field(default=None, max_length=80)
    capabilities: list[str] | None = Field(default=None,max_length=32)


class DispatchResponse(BaseModel):
    id: UUID
    route_key: str
    gateway_model: str
    prompt: str
    claim_version: int
    lease_expires_at: datetime
    connection_id: UUID
    adapter_key: str
    execution_timeout_seconds: int
    spec_version: int
    adapter_version: str
    deadline_at: datetime
    idempotency_key: UUID
    server_time: datetime


class CompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim_version: int = Field(ge=1)
    content: str = Field(max_length=1_000_000)
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    provider_request_id: str | None = Field(default=None, max_length=255)


class FailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim_version: int = Field(ge=1)
    error: str = Field(min_length=1, max_length=2000)


@app.post("/v1/worker/heartbeat", status_code=204)
def heartbeat(body: HeartbeatRequest, principal: Principal) -> None:
    try:
        heartbeat_worker(
            principal.tenant_id,
            principal.worker_node_id,
            platform=body.platform,
            architecture=body.architecture,
            capabilities=body.capabilities,
        )
    except WorkerNotFound:
        raise HTTPException(status_code=403, detail="Worker unavailable") from None
    except ValueError:
        raise HTTPException(status_code=422,detail='Invalid capabilities') from None


@app.get("/healthz")
def health() -> dict[str, str]:
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
    except Exception:
        raise HTTPException(status_code=503, detail="unavailable") from None
    return {"status": "ok"}


@app.post("/v1/worker/claim", response_model=DispatchResponse)
def claim(principal: Principal) -> DispatchResponse | Response:
    dispatch = claim_next_dispatch(
        tenant_id=principal.tenant_id,
        worker_node_id=principal.worker_node_id,
    )
    if dispatch is None:
        return Response(status_code=204)
    return DispatchResponse(
        id=dispatch.id,
        route_key=dispatch.route_key,
        gateway_model=dispatch.gateway_model,
        prompt=dispatch.prompt,
        claim_version=dispatch.claim_version,
        lease_expires_at=dispatch.lease_expires_at,
        connection_id=dispatch.connection_id,
        adapter_key=dispatch.adapter_key,
        execution_timeout_seconds=dispatch.execution_timeout_seconds,
        spec_version=dispatch.spec_version,
        adapter_version=dispatch.adapter_version,
        deadline_at=dispatch.deadline_at,
        idempotency_key=dispatch.idempotency_key,
        server_time=datetime.now(timezone.utc),
    )


@app.post("/v1/worker/dispatches/{dispatch_id}/complete", status_code=204)
def complete(
    dispatch_id: UUID,
    body: CompleteRequest,
    principal: Principal,
) -> None:
    try:
        complete_dispatch(
            tenant_id=principal.tenant_id,
            dispatch_id=dispatch_id,
            worker_node_id=principal.worker_node_id,
            claim_version=body.claim_version,
            content=body.content,
            prompt_tokens=body.prompt_tokens,
            completion_tokens=body.completion_tokens,
            provider_request_id=body.provider_request_id,
        )
    except DispatchLeaseLost:
        raise HTTPException(
            status_code=409,
            detail="Dispatch lease unavailable",
        ) from None
    except DispatchUnavailable:
        raise HTTPException(status_code=422,detail='Invalid result') from None


@app.post("/v1/worker/dispatches/{dispatch_id}/fail", status_code=204)
def fail(
    dispatch_id: UUID,
    body: FailRequest,
    principal: Principal,
) -> None:
    try:
        fail_dispatch(
            tenant_id=principal.tenant_id,
            dispatch_id=dispatch_id,
            worker_node_id=principal.worker_node_id,
            claim_version=body.claim_version,
            error=body.error,
        )
    except DispatchLeaseLost:
        raise HTTPException(
            status_code=409,
            detail="Dispatch lease unavailable",
        ) from None
