import json

from .types import Capability, ExecutionPlan, PlannedTask


class InvalidPlan(ValueError):
    pass


CAPABILITY_MAP = {
    "basic": Capability.BASIC,
    "strong": Capability.STRONG,
    "frontier": Capability.FRONTIER,
}


def parse_execution_plan(raw: str) -> ExecutionPlan:
    """
    Validate structured output produced by the future LLM orchestrator.

    The model may propose a plan, but the controller decides whether
    that plan is acceptable.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidPlan(f"Invalid JSON: {exc}") from exc

    objective = data.get("objective")
    tasks = data.get("tasks")

    if not isinstance(objective, str) or not objective.strip():
        raise InvalidPlan("objective must be a non-empty string")

    if not isinstance(tasks, list) or not tasks:
        raise InvalidPlan("tasks must be a non-empty list")

    planned = []
    seen_ids = set()

    for item in tasks:
        if not isinstance(item, dict):
            raise InvalidPlan("every task must be an object")

        task_id = item.get("id")
        title = item.get("title")
        description = item.get("description")
        capability_name = item.get("capability")
        risk = item.get("risk")
        needs_review = item.get("needs_review")
        depends_on = item.get("depends_on", [])

        if not isinstance(task_id, str) or not task_id:
            raise InvalidPlan("task id is required")

        if task_id in seen_ids:
            raise InvalidPlan(f"duplicate task id: {task_id}")

        seen_ids.add(task_id)

        if not isinstance(title, str) or not title:
            raise InvalidPlan(f"{task_id}: title is required")

        if not isinstance(description, str) or not description:
            raise InvalidPlan(f"{task_id}: description is required")

        if capability_name not in CAPABILITY_MAP:
            raise InvalidPlan(
                f"{task_id}: capability must be basic, strong or frontier"
            )

        if risk not in {"low", "medium", "high", "critical"}:
            raise InvalidPlan(f"{task_id}: invalid risk")

        if not isinstance(needs_review, bool):
            raise InvalidPlan(f"{task_id}: needs_review must be boolean")

        if not isinstance(depends_on, list) or not all(
            isinstance(dep, str) for dep in depends_on
        ):
            raise InvalidPlan(f"{task_id}: depends_on must be a list of ids")

        # Hard safety rule:
        # critical-risk work can never bypass independent review.
        if risk == "critical" and not needs_review:
            raise InvalidPlan(
                f"{task_id}: critical tasks require review"
            )

        planned.append(
            PlannedTask(
                id=task_id,
                title=title,
                description=description,
                capability=CAPABILITY_MAP[capability_name],
                risk=risk,
                needs_review=needs_review,
                depends_on=tuple(depends_on),
            )
        )

    for task in planned:
        for dependency in task.depends_on:
            if dependency not in seen_ids:
                raise InvalidPlan(
                    f"{task.id}: unknown dependency {dependency}"
                )

    return ExecutionPlan(
        objective=objective.strip(),
        tasks=tuple(planned),
    )
