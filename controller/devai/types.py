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
    available: bool = True
