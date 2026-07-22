"""Stable typed contracts shared by Echelon detection layers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    MALICIOUS_CODE = "malicious_code"
    TOXICITY_HARM = "toxicity_harm"
    ADVERSARIAL_OBFUSCATION = "adversarial_obfuscation"


class Route(str, Enum):
    PASS = "pass"
    ESCALATE = "escalate"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class ThresholdPolicy:
    """Explicit inclusive/exclusive routing boundaries shared by all layers."""

    pass_below: float = 0.35
    block_at_or_above: float = 0.90

    def __post_init__(self) -> None:
        if not 0.0 <= self.pass_below < self.block_at_or_above <= 1.0:
            raise ValueError("thresholds require 0 <= pass_below < block_at_or_above <= 1")

    def route(self, risk_score: float) -> Route:
        if not 0.0 <= risk_score <= 1.0:
            raise ValueError("risk_score must be between 0 and 1")
        if risk_score < self.pass_below:
            return Route.PASS
        if risk_score >= self.block_at_or_above:
            return Route.BLOCK
        return Route.ESCALATE

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ThresholdPolicy":
        return cls(float(value["pass_below"]), float(value["block_at_or_above"]))


@dataclass(frozen=True, slots=True)
class Evidence:
    """Content-free reason emitted by a detector."""

    code: str
    category: ThreatCategory
    weight: float
    source: str
    correlation_group: str
    occurrences: int = 1
    decoded: bool = False


@dataclass(frozen=True, slots=True)
class InputStats:
    original_chars: int
    scanned_chars: int
    truncated: bool
    entropy_bits_per_char: float
    control_character_ratio: float
    decoded_candidates: int


@dataclass(frozen=True, slots=True)
class LayerResult:
    layer: str
    risk_score: float
    category_scores: dict[str, float]
    route: Route
    evidence: tuple[Evidence, ...]
    stats: InputStats
    duration_us: int
    ruleset_sha256: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["route"] = self.route.value
        for evidence in value["evidence"]:
            evidence["category"] = evidence["category"].value
        return value


@dataclass(frozen=True, slots=True)
class Layer2Result:
    """Semantic classifier result; scores must be calibrated by the adapter."""

    layer: str
    risk_score: float
    category_scores: dict[str, float]
    route: Route
    evidence: tuple[Evidence, ...]
    calibrated: bool
    model_id: str
    model_revision: str
    duration_us: int

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["route"] = self.route.value
        for evidence in value["evidence"]:
            evidence["category"] = evidence["category"].value
        return value


@dataclass(frozen=True, slots=True)
class JudgeResult:
    """Validated Layer 3 verdict with no free-form model response."""

    layer: str
    risk_score: float
    category_scores: dict[str, float]
    route: Route
    rationale_codes: tuple[str, ...]
    uncertainty: float
    judge_id: str
    judge_revision: str
    duration_us: int

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["route"] = self.route.value
        value["rationale_codes"] = list(self.rationale_codes)
        return value
