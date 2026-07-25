"""Three-fold ingress cascade with explicit shadow/enforcement behavior."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any

from echelon.contracts import JudgeResult, Layer2Result, LayerResult, Route
from echelon.layer1 import HeuristicAnalyzer
from echelon.layer2 import Layer2Classifier
from echelon.layer3 import Layer3Judge


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    mode: str = "shadow"
    short_circuit_layer1_blocks: bool = False
    fail_route: Route = Route.ESCALATE

    def __post_init__(self) -> None:
        if self.mode not in {"shadow", "enforce"}:
            raise ValueError("mode must be shadow or enforce")


@dataclass(frozen=True, slots=True)
class PipelineDecision:
    route: Route
    enforced_route: Route
    risk_score: float
    stage: str
    layer1: LayerResult
    layer2: Layer2Result | None
    judge: JudgeResult | None
    errors: tuple[str, ...]
    duration_us: int

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["route"] = self.route.value
        value["enforced_route"] = self.enforced_route.value
        value["errors"] = list(self.errors)
        value["layer1"] = self.layer1.to_dict()
        value["layer2"] = self.layer2.to_dict() if self.layer2 else None
        value["judge"] = self.judge.to_dict() if self.judge else None
        return value


class EchelonPipeline:
    def __init__(
        self,
        layer1: HeuristicAnalyzer,
        layer2: Layer2Classifier,
        judge: Layer3Judge | None = None,
        config: PipelineConfig | None = None,
    ):
        self.layer1, self.layer2, self.judge = layer1, layer2, judge
        self.config = config or PipelineConfig()

    def _decision(
        self, route: Route, stage: str, started: int, layer1: LayerResult,
        layer2: Layer2Result | None, judge: JudgeResult | None, errors: list[str],
    ) -> PipelineDecision:
        enforced = route if self.config.mode == "enforce" else Route.PASS
        risk = judge.risk_score if judge else layer2.risk_score if layer2 else layer1.risk_score
        return PipelineDecision(
            route=route, enforced_route=enforced, risk_score=risk, stage=stage,
            layer1=layer1, layer2=layer2, judge=judge, errors=tuple(errors),
            duration_us=max(1, (time.perf_counter_ns() - started) // 1_000),
        )

    @staticmethod
    def _most_restrictive(*routes: Route) -> Route:
        return max(routes, key=lambda route: (Route.PASS, Route.ESCALATE, Route.BLOCK).index(route))

    def analyze(self, prompt: str) -> PipelineDecision:
        started = time.perf_counter_ns()
        layer1 = self.layer1.analyze(prompt)
        if layer1.route is Route.BLOCK and self.config.short_circuit_layer1_blocks:
            return self._decision(Route.BLOCK, "layer1", started, layer1, None, None, [])
        errors: list[str] = []
        try:
            layer2 = self.layer2.analyze(prompt)
        except Exception as exc:  # fail closed to configured review route; do not expose exception text
            errors.append(f"layer2_unavailable:{type(exc).__name__}")
            return self._decision(self.config.fail_route, "layer2_failure", started, layer1, None, None, errors)
        if layer2.route is Route.BLOCK:
            return self._decision(Route.BLOCK, "layer2", started, layer1, layer2, None, errors)
        if layer2.route is Route.PASS:
            if layer1.route is Route.BLOCK:
                return self._decision(Route.BLOCK, "layer1_shadow", started, layer1, layer2, None, errors)
            return self._decision(Route.PASS, "layer2", started, layer1, layer2, None, errors)
        if self.judge is None:
            return self._decision(self.config.fail_route, "layer3_unavailable", started, layer1, layer2, None, ["layer3_unavailable"])
        try:
            judge = self.judge.analyze(prompt, layer1, layer2)
        except Exception as exc:  # no raw judge response or prompt is propagated
            errors.append(f"layer3_unavailable:{type(exc).__name__}")
            return self._decision(self.config.fail_route, "layer3_failure", started, layer1, layer2, None, errors)
        route = self._most_restrictive(layer1.route, judge.route)
        return self._decision(route, "layer3", started, layer1, layer2, judge, errors)
