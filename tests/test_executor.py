import unittest

from devai.executor import AllRoutesFailed, execute_with_fallback
from devai.gateway import GatewayError, StaticGateway
from devai.orchestrator import assess_task
from devai.router import plan_routes


class ExecutorTests(unittest.TestCase):

    def test_basic_task_uses_free_route(self):
        routes = plan_routes(
            assess_task("Resume este documento")
        )

        gateway = StaticGateway({
            "worker-free": "FREE_OK",
        })

        result = execute_with_fallback(
            "Resume este documento",
            routes,
            gateway,
        )

        self.assertEqual(result.content, "FREE_OK")
        self.assertEqual(result.provider, "openrouter")
        self.assertEqual(gateway.calls, ["worker-free"])
        self.assertEqual(len(result.attempts), 1)

    def test_failure_moves_to_next_route(self):
        routes = plan_routes(
            assess_task("Resume este documento")
        )

        gateway = StaticGateway({
            "worker-free": GatewayError("quota exhausted"),
            "worker-standard": "GEMINI_OK",
        })

        result = execute_with_fallback(
            "Resume este documento",
            routes,
            gateway,
        )

        self.assertEqual(result.content, "GEMINI_OK")
        self.assertEqual(result.provider, "gemini")
        self.assertEqual(
            gateway.calls,
            ["worker-free", "worker-standard"],
        )

        self.assertFalse(result.attempts[0].success)
        self.assertTrue(result.attempts[1].success)

    def test_route_is_never_retried(self):
        routes = plan_routes(
            assess_task("Resume este documento")
        )

        gateway = StaticGateway({
            "worker-free": GatewayError("429"),
            "worker-standard": GatewayError("503"),
            "worker-frontier": GatewayError("unavailable"),
        })

        with self.assertRaises(AllRoutesFailed) as ctx:
            execute_with_fallback(
                "Resume este documento",
                routes,
                gateway,
            )

        self.assertEqual(
            gateway.calls,
            [
                "worker-free",
                "worker-standard",
                "worker-frontier",
            ],
        )

        self.assertEqual(len(ctx.exception.attempts), 3)


if __name__ == "__main__":
    unittest.main()
