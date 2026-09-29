from dataclasses import dataclass

from .llm import LLMClient, LLMRequest
from .planner import parse_execution_plan
from .prompts import ORCHESTRATOR_SYSTEM_PROMPT
from .types import ExecutionPlan


@dataclass(frozen=True)
class PlanningResult:
    plan: ExecutionPlan
    provider: str
    model: str


class PlannerEngine:
    """
    Provider-agnostic planning layer.

    It knows only the logical model alias `planner`.
    Provider selection belongs outside this component.
    """

    def __init__(self, client: LLMClient):
        self.client = client

    def plan(self, objective: str) -> PlanningResult:
        if not isinstance(objective, str) or not objective.strip():
            raise ValueError("objective must be a non-empty string")

        response = self.client.complete(
            LLMRequest(
                model="planner",
                system=ORCHESTRATOR_SYSTEM_PROMPT,
                prompt=objective.strip(),
                temperature=0.1,
            )
        )

        plan = parse_execution_plan(
            _strip_json_fence(response.content)
        )

        return PlanningResult(
            plan=plan,
            provider=response.provider,
            model=response.model,
        )


def _strip_json_fence(value: str) -> str:
    text = value.strip()

    if not text.startswith("```"):
        return text

    lines = text.splitlines()

    if lines and lines[0].startswith("```"):
        lines = lines[1:]

    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]

    return "\n".join(lines).strip()
