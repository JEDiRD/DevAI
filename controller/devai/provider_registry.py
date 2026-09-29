from .db import connect
from .types import Capability, ModelCandidate


CAPABILITY_MAP = {
    "basic": Capability.BASIC,
    "strong": Capability.STRONG,
    "frontier": Capability.FRONTIER,
}


def upsert_route(
    *,
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
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                ON CONFLICT (route_key)
                DO UPDATE SET
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


def list_available_routes() -> list[ModelCandidate]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    route_key,
                    provider,
                    gateway_model,
                    capability,
                    cost_class,
                    priority,
                    pricing_key
                FROM provider_routes
                WHERE enabled = TRUE
                  AND (
                      cooldown_until IS NULL
                      OR cooldown_until <= now()
                  )
                ORDER BY priority, route_key
                """
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

                WHERE route_key = %s
                """,
                (
                    error[:1000],
                    route_key,
                ),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Unknown route: {route_key}"
                )


def record_route_success(
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
                WHERE route_key = %s
                """,
                (route_key,),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Unknown route: {route_key}"
                )


def set_route_enabled(
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
                WHERE route_key = %s
                """,
                (
                    enabled,
                    route_key,
                ),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Unknown route: {route_key}"
                )
