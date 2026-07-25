"""Dependency-light metrics and threshold selection for Layer 2 validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True, slots=True)
class BinaryMetrics:
    threshold: float
    tp: int
    tn: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    benign_fpr: float
    brier: float


def _check(labels: list[int], scores: list[float]) -> None:
    if not labels or len(labels) != len(scores):
        raise ValueError("labels and scores must be non-empty and equal length")
    if any(label not in (0, 1) for label in labels):
        raise ValueError("labels must contain only 0 or 1")
    if any(not 0.0 <= score <= 1.0 for score in scores):
        raise ValueError("scores must be between 0 and 1")


def binary_metrics(labels: Iterable[int], scores: Iterable[float], threshold: float = 0.5) -> BinaryMetrics:
    labels, scores = list(labels), list(scores)
    _check(labels, scores)
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")
    predictions = [int(score >= threshold) for score in scores]
    tp = sum(label == prediction == 1 for label, prediction in zip(labels, predictions))
    tn = sum(label == prediction == 0 for label, prediction in zip(labels, predictions))
    fp = sum(label == 0 and prediction == 1 for label, prediction in zip(labels, predictions))
    fn = sum(label == 1 and prediction == 0 for label, prediction in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    benign_fpr = fp / (fp + tn) if fp + tn else 0.0
    brier = sum((score - label) ** 2 for label, score in zip(labels, scores)) / len(labels)
    return BinaryMetrics(threshold, tp, tn, fp, fn, precision, recall, f1, benign_fpr, brier)


def expected_calibration_error(labels: Iterable[int], scores: Iterable[float], bins: int = 10) -> float:
    labels, scores = list(labels), list(scores)
    _check(labels, scores)
    if not 2 <= bins <= 100:
        raise ValueError("bins must be between 2 and 100")
    total = len(labels)
    error = 0.0
    for index in range(bins):
        lower, upper = index / bins, (index + 1) / bins
        members = [i for i, score in enumerate(scores) if lower <= score < upper or (index == bins - 1 and score <= upper)]
        if members:
            confidence = sum(scores[i] for i in members) / len(members)
            accuracy = sum(labels[i] for i in members) / len(members)
            error += len(members) / total * abs(confidence - accuracy)
    return error


def select_threshold(
    labels: Iterable[int], scores: Iterable[float], *, minimum_recall: float = 0.95,
    maximum_benign_fpr: float = 0.05,
) -> BinaryMetrics:
    labels, scores = list(labels), list(scores)
    _check(labels, scores)
    if not 0.0 <= minimum_recall <= 1.0 or not 0.0 <= maximum_benign_fpr <= 1.0:
        raise ValueError("threshold constraints must be between 0 and 1")
    candidates = sorted({0.0, 1.0, *scores})
    valid = [
        binary_metrics(labels, scores, threshold)
        for threshold in candidates
        if binary_metrics(labels, scores, threshold).recall >= minimum_recall
        and binary_metrics(labels, scores, threshold).benign_fpr <= maximum_benign_fpr
    ]
    if not valid:
        raise ValueError("no threshold satisfies recall and benign false-positive constraints")
    return max(valid, key=lambda metric: (metric.f1, metric.precision, -metric.threshold))


def slice_metrics(
    labels: Iterable[int], scores: Iterable[float], slices: Iterable[str], threshold: float,
) -> dict[str, BinaryMetrics]:
    labels, scores, slices = list(labels), list(scores), list(slices)
    _check(labels, scores)
    if len(slices) != len(labels):
        raise ValueError("slices must have one value per row")
    output: dict[str, BinaryMetrics] = {}
    for name in sorted(set(slices)):
        indexes = [index for index, value in enumerate(slices) if value == name]
        output[name] = binary_metrics([labels[i] for i in indexes], [scores[i] for i in indexes], threshold)
    return output
