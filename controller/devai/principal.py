"""Tenant authorization-context primitives.

TenantPrincipal is an authorization-context data structure. It is NOT itself
proof that authentication occurred.

Constructing a TenantPrincipal is allowed only at:

- authenticated tenant/operator boundaries (code that has already verified
  the caller's identity, e.g. session or API authentication);
- trusted internal code operating with DB-authorized tenant context;
- tests acting as boundary stand-ins.

It must never be built directly from unauthenticated caller-supplied values.
WorkerPrincipal (controller/devai/worker_identity.py) is intentionally not
accepted anywhere a TenantPrincipal is required.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

OPERATOR_ACTOR = "operator"
SERVICE_ACTOR = "service"

ALLOWED_ACTOR_KINDS = frozenset({OPERATOR_ACTOR, SERVICE_ACTOR})

_NIL_UUID = UUID(int=0)


@dataclass(frozen=True)
class TenantPrincipal:
    """Who is acting, and in which tenant's context."""

    tenant_id: UUID
    subject: str
    actor_kind: str

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID) or self.tenant_id == _NIL_UUID:
            raise ValueError("tenant_id must be a non-nil UUID")
        if not isinstance(self.subject, str) or not self.subject.strip():
            raise ValueError("subject must be a non-empty string")
        if self.actor_kind not in ALLOWED_ACTOR_KINDS:
            raise ValueError("actor_kind must be 'operator' or 'service'")
        object.__setattr__(self, "subject", self.subject.strip())


def make_tenant_principal(
    *,
    tenant_id: UUID | str,
    subject: str,
    actor_kind: str,
) -> TenantPrincipal:
    """Build a TenantPrincipal, accepting a UUID or its canonical string form."""
    if isinstance(tenant_id, str):
        tenant_id = UUID(tenant_id.strip())
    return TenantPrincipal(
        tenant_id=tenant_id,
        subject=subject,
        actor_kind=actor_kind,
    )
