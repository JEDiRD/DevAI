from .types import Capability, ModelCandidate, TaskAssessment


COST_ORDER = {
    "free": 0,
    "standard": 1,
    "premium": 2,
}


DEFAULT_MODELS = (
    ModelCandidate(
        key="openrouter/free",
        provider="openrouter",
        capability=Capability.BASIC,
        cost_class="free",
        priority=10,
        gateway_model="worker-free",
    ),
    ModelCandidate(
        key="gemini/standard",
        provider="gemini",
        capability=Capability.STRONG,
        cost_class="standard",
        priority=20,
        gateway_model="worker-standard",
    ),
    ModelCandidate(
        key="codex/local",
        provider="codex",
        capability=Capability.FRONTIER,
        cost_class="premium",
        priority=30,
        gateway_model="worker-frontier",
    ),
)


class NoRouteAvailable(RuntimeError):
    pass


def plan_routes(
    assessment: TaskAssessment,
    candidates=DEFAULT_MODELS,
) -> list[ModelCandidate]:
    """
    Return every acceptable route in preferred order.

    The controller, not an individual provider, owns fallback/retry decisions.
    """
    eligible = [
        model
        for model in candidates
        if model.available
        and model.capability >= assessment.capability
    ]

    eligible.sort(
        key=lambda model: (
            COST_ORDER[model.cost_class],
            model.capability,
            model.priority,
        )
    )

    if not eligible:
        raise NoRouteAvailable(
            f"No available model satisfies capability={assessment.capability.name}"
        )

    return eligible
