from uuid import UUID

from .db import connect
from .types import Capability, ModelCandidate


CAPABILITY_MAP = {
    "basic": Capability.BASIC,
    "strong": Capability.STRONG,
    "frontier": Capability.FRONTIER,
}


def upsert_route(
    *,
    tenant_id: UUID,
    connection_id: UUID,
    route_key: str,
    provider: str,
    gateway_model: str,
    capability: str,
    cost_class: str,
    priority: int,
    pricing_key: str,
    enabled: bool = True,
    failure_threshold: int = 2,
    cooldown_seconds: int = 300,
) -> None:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO provider_routes (
                    tenant_id,
                    connection_id,
                    route_key,
                    provider,
                    gateway_model,
                    capability,
                    cost_class,
                    priority,
                    pricing_key,
                    enabled,
                    failure_threshold,
                    cooldown_seconds
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (tenant_id, route_key)
                DO UPDATE SET
                    connection_id = EXCLUDED.connection_id,
                    provider = EXCLUDED.provider,
                    gateway_model = EXCLUDED.gateway_model,
                    capability = EXCLUDED.capability,
                    cost_class = EXCLUDED.cost_class,
                    priority = EXCLUDED.priority,
                    pricing_key = EXCLUDED.pricing_key,
                    enabled = EXCLUDED.enabled,
                    failure_threshold = EXCLUDED.failure_threshold,
                    cooldown_seconds = EXCLUDED.cooldown_seconds,
                    updated_at = now()
                """,
                (
                    tenant_id,
                    connection_id,
                    route_key,
                    provider,
                    gateway_model,
                    capability,
                    cost_class,
                    priority,
                    pricing_key,
                    enabled,
                    failure_threshold,
                    cooldown_seconds,
                ),
            )


def list_available_routes(
    tenant_id: UUID,
) -> list[ModelCandidate]:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    r.route_key,
                    r.provider,
                    r.gateway_model,
                    r.capability,
                    r.cost_class,
                    r.priority,
                    r.pricing_key
                FROM provider_routes r
                JOIN provider_connections c
                  ON c.tenant_id = r.tenant_id
                 AND c.id = r.connection_id
                LEFT JOIN worker_nodes n
                  ON n.tenant_id = c.tenant_id
                 AND n.id = c.worker_node_id
                WHERE r.tenant_id = %s
                  AND r.enabled = TRUE
                  AND c.enabled = TRUE
                  AND (
                      r.cooldown_until IS NULL
                      OR r.cooldown_until <= now()
                  )
                  AND (
                      c.worker_node_id IS NULL
                      OR (
                          n.status = 'online'
                          AND n.last_seen_at IS NOT NULL
                          AND n.last_seen_at >
                              now() - interval '90 seconds'
                      )
                  )
                ORDER BY r.priority, r.route_key
                """,
                (tenant_id,),
            )

            rows = cur.fetchall()

    return [
        ModelCandidate(
            key=row[0],
            provider=row[1],
            gateway_model=row[2],
            capability=CAPABILITY_MAP[row[3]],
            cost_class=row[4],
            priority=row[5],
            pricing_key=row[6],
        )
        for row in rows
    ]


def record_route_failure(
    tenant_id: UUID,
    route_key: str,
    error: str,
) -> None:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE provider_routes
                SET consecutive_failures =
                        consecutive_failures + 1,

                    cooldown_until =
                        CASE
                            WHEN consecutive_failures + 1
                                 >= failure_threshold
                            THEN now()
                                 + (
                                     cooldown_seconds
                                     * interval '1 second'
                                 )
                            ELSE cooldown_until
                        END,

                    last_error = %s,
                    last_failure_at = now(),
                    updated_at = now()

                WHERE tenant_id = %s
                  AND route_key = %s
                """,
                (
                    error[:1000],
                    tenant_id,
                    route_key,
                ),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Unknown route for tenant: {route_key}"
                )


def record_route_success(
    tenant_id: UUID,
    route_key: str,
) -> None:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE provider_routes
                SET consecutive_failures = 0,
                    cooldown_until = NULL,
                    last_error = NULL,
                    last_success_at = now(),
                    updated_at = now()
                WHERE tenant_id = %s
                  AND route_key = %s
                """,
                (
                    tenant_id,
                    route_key,
                ),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Unknown route for tenant: {route_key}"
                )


def set_route_enabled(
    tenant_id: UUID,
    route_key: str,
    enabled: bool,
) -> None:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE provider_routes
                SET enabled = %s,
                    updated_at = now()
                WHERE tenant_id = %s
                  AND route_key = %s
                """,
                (
                    enabled,
                    tenant_id,
                    route_key,
                ),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Unknown route for tenant: {route_key}"
                )
