import unittest

from devai.executor import execute_with_fallback
from devai.gateway import (
    GatewayConfigurationError,
    StaticGateway,
)
from devai.types import (
    Capability,
    ModelCandidate,
)


def route(
    key: str,
    provider: str,
    gateway_model: str,
    priority: int,
):
    return ModelCandidate(
        key=key,
        provider=provider,
        capability=Capability.BASIC,
        cost_class="free",
        priority=priority,
        gateway_model=gateway_model,
        pricing_key=key,
    )


class RouteGatewayResolutionTests(unittest.TestCase):

    def test_each_route_gets_its_own_gateway(self):
        first = route(
            "provider-a/free",
            "provider-a",
            "model-a",
            10,
        )

        second = route(
            "provider-b/free",
            "provider-b",
            "model-b",
            20,
        )

        gateway_a = StaticGateway({
            "model-a":
                RuntimeError("provider A failed"),
        })

        gateway_b = StaticGateway({
            "model-b": "ROUTE_B_OK",
        })

        gateways = {
            first.key: gateway_a,
            second.key: gateway_b,
        }

        result = execute_with_fallback(
            prompt="test",
            routes=[first, second],
            gateway_resolver=lambda candidate:
                gateways[candidate.key],
        )

        self.assertEqual(
            result.content,
            "ROUTE_B_OK",
        )

        self.assertEqual(
            gateway_a.calls,
            ["model-a"],
        )

        self.assertEqual(
            gateway_b.calls,
            ["model-b"],
        )

        self.assertEqual(
            len(result.attempts),
            2,
        )

    def test_transport_resolution_failure_falls_back(self):
        unavailable = route(
            "codex/frontier",
            "codex",
            "worker-frontier",
            10,
        )

        available = route(
            "openrouter/free",
            "openrouter",
            "worker-free",
            20,
        )

        good_gateway = StaticGateway({
            "worker-free":
                "TRANSPORT_FALLBACK_OK",
        })

        def resolver(candidate):
            if candidate.key == "codex/frontier":
                raise GatewayConfigurationError(
                    "Unsupported transport: local_cli"
                )

            return good_gateway

        result = execute_with_fallback(
            prompt="test",
            routes=[
                unavailable,
                available,
            ],
            gateway_resolver=resolver,
        )

        self.assertEqual(
            result.content,
            "TRANSPORT_FALLBACK_OK",
        )

        self.assertEqual(
            len(result.attempts),
            2,
        )

        self.assertFalse(
            result.attempts[0].success,
        )

        self.assertTrue(
            result.attempts[1].success,
        )

        self.assertEqual(
            good_gateway.calls,
            ["worker-free"],
        )

    def test_rejects_gateway_and_resolver_together(self):
        candidate = route(
            "test/free",
            "test",
            "test-model",
            10,
        )

        gateway = StaticGateway({
            "test-model": "OK",
        })

        with self.assertRaises(ValueError):
            execute_with_fallback(
                prompt="test",
                routes=[candidate],
                gateway=gateway,
                gateway_resolver=lambda _:
                    gateway,
            )


if __name__ == "__main__":
    unittest.main()
