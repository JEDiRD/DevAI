import unittest
from dataclasses import replace

from devai.orchestrator import assess_task
from devai.router import DEFAULT_MODELS, NoRouteAvailable, plan_routes
from devai.types import Capability


class RouterTests(unittest.TestCase):

    def test_basic_prefers_free(self):
        assessment = assess_task("Resume este texto")
        routes = plan_routes(assessment)

        self.assertEqual(assessment.capability, Capability.BASIC)
        self.assertEqual(routes[0].key, "openrouter/free")

    def test_software_task_uses_strong(self):
        assessment = assess_task("Crea una API CRUD para productos")
        routes = plan_routes(assessment)

        self.assertEqual(assessment.capability, Capability.STRONG)
        self.assertEqual(routes[0].key, "gemini/standard")

    def test_security_task_requires_frontier(self):
        assessment = assess_task(
            "Diseña la arquitectura de seguridad para producción"
        )
        routes = plan_routes(assessment)

        self.assertEqual(assessment.capability, Capability.FRONTIER)
        self.assertTrue(assessment.needs_review)
        self.assertEqual(routes[0].key, "codex/local")

    def test_free_provider_failure_falls_back(self):
        assessment = assess_task("Resume este texto")

        candidates = [
            replace(model, available=False)
            if model.key == "openrouter/free"
            else model
            for model in DEFAULT_MODELS
        ]

        routes = plan_routes(assessment, candidates)

        self.assertEqual(routes[0].key, "gemini/standard")
        self.assertEqual(routes[1].key, "codex/local")

    def test_frontier_without_frontier_model_fails_closed(self):
        assessment = assess_task(
            "Revisa una vulnerabilidad crítica de producción"
        )

        candidates = [
            replace(model, available=False)
            if model.key == "codex/local"
            else model
            for model in DEFAULT_MODELS
        ]

        with self.assertRaises(NoRouteAvailable):
            plan_routes(assessment, candidates)


if __name__ == "__main__":
    unittest.main()
