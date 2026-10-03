from dataclasses import dataclass
from decimal import Decimal
from uuid import UUID

from .budgeted_observer import BudgetedLedgerObserver
from .checkpoint import (
    TaskLease,
    defer_task_for_route,
    load_latest_checkpoint,
    release_task,
    save_checkpoint,
)
from .db import connect
from .executor import AllRoutesFailed, execute_with_fallback
from .gateway import GatewayClient
from .transport import build_gateway_for_route
from .router import NoRouteAvailable, plan_routes
from .provider_registry import list_available_routes
from .route_health_observer import RouteHealthObserver
from .scheduler import claim_next_ready_task
from .types import Capability, TaskAssessment


@dataclass(frozen=True)
class RuntimeTask:
    id: UUID
    job_id: UUID
    tenant_id: UUID
    external_id: str
    title: str
    description: str
    capability: Capability
    risk: str
    needs_review: bool


def load_runtime_task(task_id: UUID) -> RuntimeTask:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    t.id,
                    t.job_id,
                    j.tenant_id,
                    t.external_id,
                    t.title,
                    t.description,
                    t.capability,
                    t.risk,
                    t.needs_review
                FROM tasks t
                JOIN jobs j
                  ON j.id = t.job_id
                WHERE t.id = %s
                """,
                (task_id,),
            )
            row = cur.fetchone()

    if row is None:
        raise RuntimeError(f"Task not found: {task_id}")

    return RuntimeTask(
        id=row[0],
        job_id=row[1],
        tenant_id=row[2],
        external_id=row[3],
        title=row[4],
        description=row[5],
        capability=Capability[row[6].upper()],
        risk=row[7],
        needs_review=row[8],
    )


def run_claimed_task(
    lease: TaskLease,
    reservation_by_cost_class: dict[str, Decimal],
    gateway: GatewayClient | None = None,
):
    task = load_runtime_task(lease.task_id)

    previous = load_latest_checkpoint(task.id, tenant_id=lease.tenant_id)

    # Authority below is lease.tenant_id, the caller tenant already proven at
    # claim time. It is never re-derived from RuntimeTask or job rows.
    save_checkpoint(
        lease,
        {
            "phase": "execution_started",
            "external_id": task.external_id,
            "resume_from_sequence":
                previous.sequence if previous else None,
        },
    )

    assessment = TaskAssessment(
        capability=task.capability,
        risk=task.risk,
        needs_review=task.needs_review,
        reason="Capability assigned by validated execution plan.",
    )

    candidates = list_available_routes(
        task.tenant_id
    )

    try:
        routes = plan_routes(
            assessment,
            candidates,
        )
    except NoRouteAvailable:
        defer_task_for_route(lease)
        return None

    observer = RouteHealthObserver(
        BudgetedLedgerObserver(
            job_id=task.job_id,
            task_id=task.id,
            reservation_by_cost_class=reservation_by_cost_class,
            tenant_id=task.tenant_id,
        ),
        tenant_id=task.tenant_id,
    )

    try:
        if gateway is not None:
            # Compatibility path for tests/injected gateways.
            result = execute_with_fallback(
                prompt=task.description,
                routes=routes,
                gateway=gateway,
                observer=observer,
            )
        else:
            # Normal runtime path: every route resolves its own
            # tenant-scoped connection and transport.
            result = execute_with_fallback(
                prompt=task.description,
                routes=routes,
                gateway_resolver=lambda route:
                    build_gateway_for_route(
                        task.tenant_id,
                        route.key,
                    ),
                observer=observer,
            )

    except AllRoutesFailed as exc:
        save_checkpoint(
            lease,
            {
                "phase": "execution_failed",
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
            },
        )

        release_task(
            lease,
            "failed",
        )
        raise

    except Exception as exc:
        save_checkpoint(
            lease,
            {
                "phase": "execution_failed",
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
            },
        )

        release_task(
            lease,
            "failed",
        )
        raise

    save_checkpoint(
        lease,
        {
            "phase": "execution_completed",
            "provider": result.provider,
            "gateway_model": result.gateway_model,
            "attempts": len(result.attempts),
        },
    )

    release_task(
        lease,
        "completed",
    )

    return result


def worker_once(
    job_id: UUID,
    owner_id: UUID,
    reservation_by_cost_class: dict[str, Decimal],
    gateway: GatewayClient | None = None,
    *,
    tenant_id: UUID,
):
    """Claim and run one task for ``tenant_id``.

    The CALLER supplies tenant context; it is never derived from the job or
    task row. ``worker_once`` remains unreachable from the live worker API, and
    this adds no caller.
    """

    lease = claim_next_ready_task(
        job_id=job_id,
        owner_id=owner_id,
        lease_seconds=60,
        tenant_id=tenant_id,
    )

    if lease is None:
        return None

    return run_claimed_task(
        lease=lease,
        reservation_by_cost_class=reservation_by_cost_class,
        gateway=gateway,
    )
