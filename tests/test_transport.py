import os
import unittest
from uuid import UUID

from devai.gateway import (
    GatewayConfigurationError,
    LiteLLMGateway,
)
from devai.transport import (
    ConnectionSpec,
    CredentialResolver,
    default_transport_registry,
)


TENANT_ID = UUID(
    "00000000-0000-4000-8000-000000000001"
)

CONNECTION_ID = UUID(
    "10000000-0000-4000-8000-000000000001"
)


class TransportTests(unittest.TestCase):

    def test_env_credential_resolution(self):
        os.environ["DEVAI_TEST_SECRET"] = "test-value"

        try:
            resolver = CredentialResolver()

            value = resolver.resolve(
                "env:DEVAI_TEST_SECRET"
            )

            self.assertEqual(
                value,
                "test-value",
            )
        finally:
            os.environ.pop(
                "DEVAI_TEST_SECRET",
                None,
            )

    def test_missing_env_credential_fails_closed(self):
        os.environ.pop(
            "DEVAI_MISSING_SECRET",
            None,
        )

        resolver = CredentialResolver()

        with self.assertRaises(
            GatewayConfigurationError
        ):
            resolver.resolve(
                "env:DEVAI_MISSING_SECRET"
            )

    def test_unknown_credential_scheme_fails_closed(self):
        resolver = CredentialResolver()

        with self.assertRaises(
            GatewayConfigurationError
        ):
            resolver.resolve(
                "vault:secret/example"
            )

    def test_litellm_transport_builds_gateway(self):
        os.environ["DEVAI_TEST_SECRET"] = "secret"

        try:
            connection = ConnectionSpec(
                id=CONNECTION_ID,
                tenant_id=TENANT_ID,
                name="Test LiteLLM",
                transport="litellm",
                auth_type="api_key",
                credential_ref="env:DEVAI_TEST_SECRET",
                endpoint="http://127.0.0.1:4000",
                config={},
            )

            gateway = (
                default_transport_registry()
                .build(
                    connection,
                    CredentialResolver(),
                )
            )

            self.assertIsInstance(
                gateway,
                LiteLLMGateway,
            )

            self.assertEqual(
                gateway.base_url,
                "http://127.0.0.1:4000",
            )
        finally:
            os.environ.pop(
                "DEVAI_TEST_SECRET",
                None,
            )

    def test_unimplemented_transport_fails_closed(self):
        connection = ConnectionSpec(
            id=CONNECTION_ID,
            tenant_id=TENANT_ID,
            name="Codex CLI",
            transport="local_cli",
            auth_type="subscription_session",
            credential_ref="session:codex",
            endpoint=None,
            config={},
        )

        with self.assertRaises(
            GatewayConfigurationError
        ):
            default_transport_registry().build(
                connection,
                CredentialResolver(),
            )


if __name__ == "__main__":
    unittest.main()
