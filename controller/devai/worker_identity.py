"""Controller-owned credentials for individual Worker nodes."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import secrets
from uuid import UUID, uuid4

from .db import connect


class WorkerAuthenticationError(RuntimeError):
    pass


class WorkerTokenNotFound(RuntimeError):
    pass


class WorkerTokenProvisioningError(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkerPrincipal:
    tenant_id: UUID
    worker_node_id: UUID
    token_id: UUID


@dataclass(frozen=True)
class IssuedWorkerToken:
    id: UUID
    tenant_id: UUID
    worker_node_id: UUID
    token: str = field(repr=False)


def _new_token() -> tuple[UUID, str, bytes]:
    token = "devai_wkr_" + secrets.token_urlsafe(32)
    return uuid4(), token, hashlib.sha256(token.encode("utf-8")).digest()


def _check_expiry(expires_at: datetime | None) -> None:
    if expires_at is not None and (
        expires_at.tzinfo is None
        or expires_at <= datetime.now(timezone.utc)
    ):
        raise ValueError("expires_at must be a future aware datetime")


def _require_worker(cur, tenant_id: UUID, worker_node_id: UUID) -> None:
    cur.execute(
        """
        SELECT n.id
        FROM worker_nodes n
        JOIN tenants tenant ON tenant.id = n.tenant_id
        WHERE n.tenant_id = %s
          AND n.id = %s
          AND n.status <> 'disabled'
          AND tenant.status = 'active'
        FOR UPDATE OF n
        """,
        (tenant_id, worker_node_id),
    )
    if cur.fetchone() is None:
        raise WorkerTokenProvisioningError("Worker is not available")


def _insert_token(cur, tenant_id, worker_node_id, expires_at):
    token_id, token, token_hash = _new_token()
    cur.execute(
        """
        INSERT INTO worker_tokens (
            id, tenant_id, worker_node_id, token_hash, expires_at
        ) VALUES (%s, %s, %s, %s, %s)
        """,
        (token_id, tenant_id, worker_node_id, token_hash, expires_at),
    )
    return IssuedWorkerToken(token_id, tenant_id, worker_node_id, token)


def issue_worker_token(
    tenant_id: UUID,
    worker_node_id: UUID,
    *,
    expires_at: datetime | None = None,
) -> IssuedWorkerToken:
    """Administrative provisioning; return the secret exactly once."""
    _check_expiry(expires_at)
    with connect() as conn:
        with conn.cursor() as cur:
            _require_worker(cur, tenant_id, worker_node_id)
            issued = _insert_token(cur, tenant_id, worker_node_id, expires_at)
    return issued


def revoke_worker_token(
    tenant_id: UUID,
    worker_node_id: UUID,
    token_id: UUID,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE worker_tokens
                SET revoked_at = now()
                WHERE id = %s
                  AND tenant_id = %s
                  AND worker_node_id = %s
                  AND revoked_at IS NULL
                """,
                (token_id, tenant_id, worker_node_id),
            )
            if cur.rowcount != 1:
                raise WorkerTokenNotFound("Active Worker token not found")


def rotate_worker_token(
    tenant_id: UUID,
    worker_node_id: UUID,
    token_id: UUID,
    *,
    expires_at: datetime | None = None,
) -> IssuedWorkerToken:
    """Revoke one token and issue its replacement in one transaction."""
    _check_expiry(expires_at)
    with connect() as conn:
        with conn.cursor() as cur:
            _require_worker(cur, tenant_id, worker_node_id)
            cur.execute(
                """
                UPDATE worker_tokens
                SET revoked_at = now()
                WHERE id = %s
                  AND tenant_id = %s
                  AND worker_node_id = %s
                  AND revoked_at IS NULL
                """,
                (token_id, tenant_id, worker_node_id),
            )
            if cur.rowcount != 1:
                raise WorkerTokenNotFound("Active Worker token not found")
            issued = _insert_token(cur, tenant_id, worker_node_id, expires_at)
    return issued


def authenticate_worker_token(token: str) -> WorkerPrincipal:
    if (
        not isinstance(token, str)
        or not token.startswith("devai_wkr_")
        or len(token) > 256
    ):
        raise WorkerAuthenticationError("Invalid Worker credential")

    token_hash = hashlib.sha256(token.encode("utf-8")).digest()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE worker_tokens t
                SET last_used_at = now()
                FROM worker_nodes n
                JOIN tenants tenant ON tenant.id = n.tenant_id
                WHERE t.token_hash = %s
                  AND t.revoked_at IS NULL
                  AND (
                      t.expires_at IS NULL
                      OR t.expires_at > now()
                  )
                  AND n.tenant_id = t.tenant_id
                  AND n.id = t.worker_node_id
                  AND n.status <> 'disabled'
                  AND tenant.status = 'active'
                RETURNING t.tenant_id, t.worker_node_id, t.id
                """,
                (token_hash,),
            )
            row = cur.fetchone()

    if row is None:
        raise WorkerAuthenticationError("Invalid Worker credential")
    return WorkerPrincipal(row[0], row[1], row[2])
