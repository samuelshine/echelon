"""Local semantic classification adapter and calibration-aware Layer 2."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from echelon.contracts import Evidence, Layer2Result, Route, ThreatCategory, ThresholdPolicy


def _bounded_probability(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"{name} must be finite")
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return value


@dataclass(frozen=True, slots=True)
class ModelOutput:
    """Provider-neutral output; no raw logits or prompt text are retained."""

    category_scores: Mapping[str, float]
    calibrated: bool
    model_id: str
    model_revision: str


class ModelAdapter(Protocol):
    def predict(self, text: str) -> ModelOutput: ...


class StaticModelAdapter:
    """Deterministic fixture adapter used by tests and orchestration smoke runs."""

    def __init__(self, scores: Mapping[str, float], *, calibrated: bool = True, model_id: str = "fixture", revision: str = "0"):
        self._scores = dict(scores)
        self._calibrated = calibrated
        self._model_id = model_id
        self._revision = revision

    def predict(self, text: str) -> ModelOutput:
        if not isinstance(text, str):
            raise TypeError("prompt must be a string")
        return ModelOutput(self._scores, self._calibrated, self._model_id, self._revision)


class UnavailableModelAdapter:
    """Explicit fail-closed adapter for environments without a trained artifact."""

    def __init__(self, reason: str = "no local Layer 2 model artifact is configured"):
        self.reason = reason

    def predict(self, text: str) -> ModelOutput:
        raise RuntimeError(self.reason)


class TransformersModelAdapter:
    """Lazy local Hugging Face adapter; never downloads a model implicitly."""

    def __init__(
        self,
        model_dir: Path,
        *,
        max_length: int = 512,
        positive_category: str = ThreatCategory.PROMPT_INJECTION.value,
        local_files_only: bool = True,
    ):
        if not model_dir.exists():
            raise FileNotFoundError(f"Layer 2 model directory does not exist: {model_dir}")
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("torch and transformers are required for the local Layer 2 adapter") from exc
        self._torch = torch
        self._tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=local_files_only)
        self._model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=local_files_only)
        self._model.eval()
        self._max_length = max_length
        self._positive_category = positive_category
        self._model_id = str(model_dir)
        self._revision = str(getattr(self._model.config, "_commit_hash", None) or "local")

    def predict(self, text: str) -> ModelOutput:
        if not isinstance(text, str):
            raise TypeError("prompt must be a string")
        inputs = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=self._max_length)
        with self._torch.inference_mode():
            logits = self._model(**inputs).logits[0]
            probabilities = self._torch.softmax(logits, dim=-1).tolist()
        labels = getattr(self._model.config, "id2label", {})
        scores: dict[str, float] = {}
        for index, probability in enumerate(probabilities):
            label = str(labels.get(index, labels.get(str(index), index))).casefold()
            if any(token in label for token in ("malicious", "injection", "unsafe", "attack")):
                category = self._positive_category
            else:
                category = ThreatCategory.PROMPT_INJECTION.value if len(probabilities) == 1 else "benign"
            scores[category] = max(scores.get(category, 0.0), float(probability))
        scores.pop("benign", None)
        return ModelOutput(scores, calibrated=False, model_id=self._model_id, model_revision=self._revision)


class MultiLabelTransformersAdapter:
    """Local multi-label threat classifier with per-category temperature calibration.

    Serves the artifact produced by scripts/train_layer2_multilabel.py: a DistilBERT
    head over the five Echelon threat categories with sigmoid outputs. Never downloads
    implicitly (local_files_only). No prompt text or raw logits are retained.
    """

    def __init__(self, model_dir: Path, *, max_length: int = 256, local_files_only: bool = True):
        import json

        if not model_dir.exists():
            raise FileNotFoundError(f"Layer 2 model directory does not exist: {model_dir}")
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("torch and transformers are required for the local Layer 2 adapter") from exc
        self._torch = torch
        self._tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=local_files_only)
        self._model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=local_files_only)
        self._model.eval()
        self._max_length = max_length
        self._model_id = str(model_dir)
        self._revision = str(getattr(self._model.config, "_commit_hash", None) or "local")
        self._id2label = {int(i): str(label) for i, label in self._model.config.id2label.items()}
        known = {category.value for category in ThreatCategory}
        if set(self._id2label.values()) - known:
            raise ValueError(f"model labels are not Echelon threat categories: {sorted(self._id2label.values())}")
        calibration_path = model_dir / "calibration.json"
        self._temperatures = {}
        if calibration_path.is_file():
            payload = json.loads(calibration_path.read_text())
            self._temperatures = {str(k): float(v) for k, v in payload.get("temperatures", {}).items()}
        self._calibrated = bool(self._temperatures)

    def predict(self, text: str) -> ModelOutput:
        if not isinstance(text, str):
            raise TypeError("prompt must be a string")
        inputs = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=self._max_length)
        with self._torch.inference_mode():
            logits = self._model(**inputs).logits[0].tolist()
        scores: dict[str, float] = {}
        for index, logit in enumerate(logits):
            category = self._id2label[index]
            temperature = self._temperatures.get(category, 1.0)
            scaled = max(-60.0, min(60.0, float(logit) / temperature))
            scores[category] = 1.0 / (1.0 + math.exp(-scaled))
        return ModelOutput(scores, calibrated=self._calibrated, model_id=self._model_id, model_revision=self._revision)


@dataclass(frozen=True, slots=True)
class Layer2Config:
    thresholds: ThresholdPolicy = ThresholdPolicy()
    minimum_evidence_score: float = 0.10

    def __post_init__(self) -> None:
        _bounded_probability(self.minimum_evidence_score, "minimum_evidence_score")


class TemperatureCalibrator:
    """Small deterministic binary temperature scaler for validation-time fitting."""

    def __init__(self, temperature: float = 1.0):
        if not 0.05 <= temperature <= 20.0:
            raise ValueError("temperature must be between 0.05 and 20")
        self.temperature = float(temperature)

    def probability(self, logit: float) -> float:
        scaled = max(-60.0, min(60.0, float(logit) / self.temperature))
        return 1.0 / (1.0 + math.exp(-scaled))

    def fit(self, logits: list[float], labels: list[int]) -> "TemperatureCalibrator":
        if len(logits) != len(labels) or not logits:
            raise ValueError("logits and labels must be non-empty and equal length")
        if any(label not in (0, 1) for label in labels):
            raise ValueError("binary labels must be 0 or 1")
        best_temperature, best_loss = self.temperature, float("inf")
        for step in range(1, 400):
            candidate = 0.05 * step
            loss = 0.0
            for logit, label in zip(logits, labels):
                probability = min(1 - 1e-7, max(1e-7, TemperatureCalibrator(candidate).probability(logit)))
                loss -= label * math.log(probability) + (1 - label) * math.log(1 - probability)
            if loss < best_loss:
                best_temperature, best_loss = candidate, loss
        self.temperature = best_temperature
        return self


class Layer2Classifier:
    def __init__(self, adapter: ModelAdapter, config: Layer2Config | None = None):
        self.adapter = adapter
        self.config = config or Layer2Config()

    def analyze(self, text: str) -> Layer2Result:
        started = time.perf_counter_ns()
        output = self.adapter.predict(text)
        scores = {category: 0.0 for category in (category.value for category in ThreatCategory)}
        for category, value in output.category_scores.items():
            if category not in scores:
                raise ValueError(f"model returned unknown threat category: {category}")
            scores[category] = _bounded_probability(value, f"category_scores[{category}]")
        risk = max(scores.values(), default=0.0)
        evidence = tuple(
            Evidence(
                code=f"model_{category}", category=ThreatCategory(category), weight=value,
                source="layer2_model", correlation_group="layer2_model",
            )
            for category, value in sorted(scores.items())
            if value >= self.config.minimum_evidence_score
        )
        duration = max(1, (time.perf_counter_ns() - started) // 1_000)
        return Layer2Result(
            layer="semantic_v1", risk_score=round(risk, 6), category_scores=scores,
            route=self.config.thresholds.route(risk), evidence=evidence,
            calibrated=output.calibrated, model_id=output.model_id,
            model_revision=output.model_revision, duration_us=duration,
        )
