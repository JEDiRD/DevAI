import unittest

from devai.llm import StaticLLMClient
from devai.planner import InvalidPlan
from devai.planner_engine import PlannerEngine
from devai.types import Capability


PLAN = """
{
  "objective": "Build secure inventory system",
  "tasks": [
    {
      "id": "T1",
      "title": "Architecture",
      "description": "Design the application architecture",
      "capability": "frontier",
      "risk": "high",
      "needs_review": true,
      "depends_on": []
    },
    {
      "id": "T2",
      "title": "CRUD",
      "description": "Build product management",
      "capability": "strong",
      "risk": "medium",
      "needs_review": false,
      "depends_on": ["T1"]
    }
  ]
}
"""


class PlannerEngineTests(unittest.TestCase):

    def test_planner_is_provider_agnostic(self):
        client = StaticLLMClient(PLAN)
        engine = PlannerEngine(client)

        result = engine.plan("Build an inventory application")

        self.assertEqual(len(result.plan.tasks), 2)
        self.assertEqual(
            result.plan.tasks[0].capability,
            Capability.FRONTIER,
        )

        request = client.requests[0]

        self.assertEqual(request.model, "planner")
        self.assertNotIn("openai", request.model.lower())
        self.assertNotIn("gemini", request.model.lower())
        self.assertNotIn("openrouter", request.model.lower())

    def test_accepts_markdown_json_fence(self):
        client = StaticLLMClient(
            "```json\n" + PLAN.strip() + "\n```"
        )

        result = PlannerEngine(client).plan("Build application")

        self.assertEqual(
            result.plan.objective,
            "Build secure inventory system",
        )

    def test_rejects_invalid_model_plan(self):
        client = StaticLLMClient('{"objective":"x","tasks":[]}')

        with self.assertRaises(InvalidPlan):
            PlannerEngine(client).plan("Build application")


if __name__ == "__main__":
    unittest.main()
