from dataclasses import dataclass
from enum import IntEnum


class Capability(IntEnum):
    BASIC = 1
    STRONG = 2
    FRONTIER = 3


@dataclass(frozen=True)
class TaskAssessment:
    capability: Capability
    risk: str
    needs_review: bool
    reason: str


@dataclass(frozen=True)
class ModelCandidate:
    key: str
    provider: str
    capability: Capability
    cost_class: str
    priority: int
    gateway_model: str | None = None
    available: bool = True


@dataclass(frozen=True)
class PlannedTask:
    id: str
    title: str
    description: str
    capability: Capability
    risk: str
    needs_review: bool
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutionPlan:
    objective: str
    tasks: tuple[PlannedTask, ...]


@dataclass(frozen=True)
class ExecutionAttempt:
    route_key: str
    provider: str
    gateway_model: str
    success: bool
    error: str | None = None


@dataclass(frozen=True)
class ExecutionResult:
    content: str
    route_key: str
    provider: str
    gateway_model: str
    attempts: tuple[ExecutionAttempt, ...]
