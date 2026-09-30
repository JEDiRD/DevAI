from dataclasses import dataclass
import json
import os
from typing import Callable
from uuid import UUID

from .db import connect
from .gateway import (
    GatewayClient,
    GatewayConfigurationError,
    LiteLLMGateway,
)


@dataclass(frozen=True)
class ConnectionSpec:
    id: UUID
    tenant_id: UUID
    name: str
    transport: str
    auth_type: str
    credential_ref: str | None
    endpoint: str | None
    config: dict
    adapter_key: str | None = None
    worker_node_id: UUID | None = None
    route_key: str | None = None


def get_route_connection(
    tenant_id: UUID,
    route_key: str,
) -> ConnectionSpec:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    c.id,
                    c.tenant_id,
                    c.name,
                    c.transport,
                    c.auth_type,
                    c.credential_ref,
                    c.endpoint,
                    c.config,
                    c.adapter_key,
                    c.worker_node_id
                FROM provider_routes r
                JOIN provider_connections c
                  ON c.tenant_id = r.tenant_id
                 AND c.id = r.connection_id
                WHERE r.tenant_id = %s
                  AND r.route_key = %s
                  AND r.enabled = TRUE
                  AND c.enabled = TRUE
                """,
                (
                    tenant_id,
                    route_key,
                ),
            )

            row = cur.fetchone()

    if row is None:
        raise GatewayConfigurationError(
            f"No enabled connection for route {route_key}"
        )

    config = row[7]

    if isinstance(config, str):
        config = json.loads(config)

    return ConnectionSpec(
        id=row[0],
        tenant_id=row[1],
        name=row[2],
        transport=row[3],
        auth_type=row[4],
        credential_ref=row[5],
        endpoint=row[6],
        config=config or {},
        adapter_key=row[8],
        worker_node_id=row[9],
        route_key=route_key,
    )


class CredentialResolver:

    def resolve(
        self,
        credential_ref: str | None,
    ) -> str | None:

        if credential_ref is None:
            return None

        if credential_ref.startswith("env:"):
            variable = credential_ref[4:]
            value = os.environ.get(variable)

            if not value:
                raise GatewayConfigurationError(
                    f"Credential environment variable "
                    f"{variable} is not available"
                )

            return value

        raise GatewayConfigurationError(
            "Credential reference scheme is not "
            f"implemented: {credential_ref.split(':', 1)[0]}"
        )


TransportFactory = Callable[
    [ConnectionSpec, CredentialResolver],
    GatewayClient,
]


class TransportRegistry:

    def __init__(self):
        self._factories: dict[
            str,
            TransportFactory,
        ] = {}

    def register(
        self,
        transport: str,
        factory: TransportFactory,
    ) -> None:

        if transport in self._factories:
            raise GatewayConfigurationError(
                f"Transport already registered: {transport}"
            )

        self._factories[transport] = factory

    def build(
        self,
        connection: ConnectionSpec,
        resolver: CredentialResolver,
    ) -> GatewayClient:

        factory = self._factories.get(
            connection.transport
        )

        if factory is None:
            raise GatewayConfigurationError(
                f"Unsupported transport: "
                f"{connection.transport}"
            )

        return factory(
            connection,
            resolver,
        )


def build_litellm_gateway(
    connection: ConnectionSpec,
    resolver: CredentialResolver,
) -> GatewayClient:

    if connection.auth_type != "api_key":
        raise GatewayConfigurationError(
            "LiteLLM connection requires api_key auth"
        )

    if not connection.endpoint:
        raise GatewayConfigurationError(
            "LiteLLM connection has no endpoint"
        )

    api_key = resolver.resolve(
        connection.credential_ref
    )

    if api_key is None:
        raise GatewayConfigurationError(
            "LiteLLM API key is unavailable"
        )

    timeout = int(
        connection.config.get(
            "timeout",
            60,
        )
    )

    return LiteLLMGateway(
        base_url=connection.endpoint,
        api_key=api_key,
        timeout=timeout,
    )


def default_transport_registry() -> TransportRegistry:
    registry = TransportRegistry()

    registry.register(
        "litellm",
        build_litellm_gateway,
    )
    registry.register('local_cli', build_remote_worker_gateway)

    return registry


def build_remote_worker_gateway(connection, resolver):
    from .remote_worker_gateway import RemoteWorkerGateway
    if not connection.worker_node_id or not connection.adapter_key or not connection.route_key:
        raise GatewayConfigurationError('REMOTE_WORKER_CONNECTION_INCOMPLETE')
    # Worker credentials/session refs are never resolved in the Controller.
    return RemoteWorkerGateway(tenant_id=connection.tenant_id,
        worker_node_id=connection.worker_node_id, connection_id=connection.id,
        route_key=connection.route_key)


def build_gateway_for_route(
    tenant_id: UUID,
    route_key: str,
    *,
    registry: TransportRegistry | None = None,
    resolver: CredentialResolver | None = None,
) -> GatewayClient:

    connection = get_route_connection(
        tenant_id,
        route_key,
    )

    registry = (
        registry
        or default_transport_registry()
    )

    resolver = (
        resolver
        or CredentialResolver()
    )

    return registry.build(
        connection,
        resolver,
    )
