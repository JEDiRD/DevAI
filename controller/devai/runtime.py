from dataclasses import dataclass
from decimal import Decimal
from uuid import UUID

from .budgeted_observer import BudgetedLedgerObserver
from .checkpoint import (
    TaskLease,
    load_latest_checkpoint,
    release_task,
    save_checkpoint,
)
from .db import connect
from .executor import AllRoutesFailed, execute_with_fallback
from .gateway import GatewayClient
from .router import plan_routes
from .provider_registry import list_available_routes
from .route_health_observer import RouteHealthObserver
from .scheduler import claim_next_ready_task
from .types import Capability, TaskAssessment


@dataclass(frozen=True)
class RuntimeTask:
    id: UUID
    job_id: UUID
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
                    id,
                    job_id,
                    external_id,
                    title,
                    description,
                    capability,
                    risk,
                    needs_review
                FROM tasks
                WHERE id = %s
                """,
                (task_id,),
            )
            row = cur.fetchone()

    if row is None:
        raise RuntimeError(f"Task not found: {task_id}")

    return RuntimeTask(
        id=row[0],
        job_id=row[1],
        external_id=row[2],
        title=row[3],
        description=row[4],
        capability=Capability[row[5].upper()],
        risk=row[6],
        needs_review=row[7],
    )


def run_claimed_task(
    lease: TaskLease,
    gateway: GatewayClient,
    reservation_by_cost_class: dict[str, Decimal],
):
    task = load_runtime_task(lease.task_id)

    previous = load_latest_checkpoint(task.id)

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

    candidates = list_available_routes()

    routes = plan_routes(
        assessment,
        candidates,
    )

    observer = RouteHealthObserver(
        BudgetedLedgerObserver(
            job_id=task.job_id,
            task_id=task.id,
            reservation_by_cost_class=reservation_by_cost_class,
        )
    )

    try:
        result = execute_with_fallback(
            prompt=task.description,
            routes=routes,
            gateway=gateway,
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
    gateway: GatewayClient,
    reservation_by_cost_class: dict[str, Decimal],
):
    lease = claim_next_ready_task(
        job_id=job_id,
        owner_id=owner_id,
        lease_seconds=60,
    )

    if lease is None:
        return None

    return run_claimed_task(
        lease=lease,
        gateway=gateway,
        reservation_by_cost_class=reservation_by_cost_class,
    )
