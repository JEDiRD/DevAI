import unittest

from devai.planner import InvalidPlan, parse_execution_plan
from devai.types import Capability


VALID_PLAN = """
{
  "objective": "Build inventory platform",
  "tasks": [
    {
      "id": "T1",
      "title": "Design architecture",
      "description": "Define application architecture",
      "capability": "frontier",
      "risk": "high",
      "needs_review": true,
      "depends_on": []
    },
    {
      "id": "T2",
      "title": "Build CRUD",
      "description": "Implement product CRUD",
      "capability": "strong",
      "risk": "medium",
      "needs_review": false,
      "depends_on": ["T1"]
    },
    {
      "id": "T3",
      "title": "Write documentation",
      "description": "Document API endpoints",
      "capability": "basic",
      "risk": "low",
      "needs_review": false,
      "depends_on": ["T2"]
    }
  ]
}
"""


class PlannerTests(unittest.TestCase):

    def test_valid_plan(self):
        plan = parse_execution_plan(VALID_PLAN)

        self.assertEqual(len(plan.tasks), 3)
        self.assertEqual(plan.tasks[0].capability, Capability.FRONTIER)
        self.assertEqual(plan.tasks[1].capability, Capability.STRONG)
        self.assertEqual(plan.tasks[2].capability, Capability.BASIC)

    def test_rejects_unknown_dependency(self):
        raw = VALID_PLAN.replace('"depends_on": ["T2"]', '"depends_on": ["T99"]')

        with self.assertRaises(InvalidPlan):
            parse_execution_plan(raw)

    def test_critical_requires_review(self):
        raw = VALID_PLAN.replace(
            '"risk": "high",\n      "needs_review": true',
            '"risk": "critical",\n      "needs_review": false',
        )

        with self.assertRaises(InvalidPlan):
            parse_execution_plan(raw)

    def test_rejects_invalid_json(self):
        with self.assertRaises(InvalidPlan):
            parse_execution_plan("not-json")


if __name__ == "__main__":
    unittest.main()
