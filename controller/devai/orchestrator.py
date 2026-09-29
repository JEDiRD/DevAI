from .types import Capability, TaskAssessment


FRONTIER_HINTS = (
    "arquitectura",
    "seguridad",
    "autentic",
    "produccion",
    "producción",
    "infraestructura",
    "migracion",
    "migración",
    "criptograf",
    "vulnerabilidad",
    "distributed",
)

STRONG_HINTS = (
    "api",
    "backend",
    "frontend",
    "database",
    "base de datos",
    "crud",
    "docker",
    "tests",
    "pruebas",
    "debug",
)


def assess_task(prompt: str) -> TaskAssessment:
    """
    Bootstrap classifier.

    This is intentionally deterministic and costs zero tokens.
    Later it will be replaced/augmented by the real LLM Orchestrator.
    """
    text = prompt.lower()

    if any(word in text for word in FRONTIER_HINTS):
        return TaskAssessment(
            capability=Capability.FRONTIER,
            risk="high",
            needs_review=True,
            reason="Task contains architecture/security/production signals.",
        )

    if any(word in text for word in STRONG_HINTS):
        return TaskAssessment(
            capability=Capability.STRONG,
            risk="medium",
            needs_review=False,
            reason="Task requires software engineering capabilities.",
        )

    return TaskAssessment(
        capability=Capability.BASIC,
        risk="low",
        needs_review=False,
        reason="No elevated complexity or risk signals detected.",
    )
