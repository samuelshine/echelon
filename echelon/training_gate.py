"""Fail-closed checks preventing unreviewed or leakage-prone data from training."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class TrainingGateError(ValueError):
    pass


REQUIRED_TRUE_FLAGS = ("human_review_complete", "semantic_split_verified", "privacy_review_complete")


def validate_training_manifest(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrainingGateError(f"cannot read training manifest: {path}") from exc
    if not isinstance(manifest, dict):
        raise TrainingGateError("training manifest must be an object")
    if manifest.get("eligible_for_training") is not True:
        raise TrainingGateError("training manifest is not marked eligible_for_training")
    for flag in REQUIRED_TRUE_FLAGS:
        if manifest.get(flag) is not True:
            raise TrainingGateError(f"training manifest missing required approval: {flag}")
    if not isinstance(manifest.get("dataset_sha256"), str) or len(manifest["dataset_sha256"]) != 64:
        raise TrainingGateError("training manifest requires a dataset_sha256")
    if not isinstance(manifest.get("rows"), int) or manifest["rows"] <= 0:
        raise TrainingGateError("training manifest requires a positive row count")
    if not isinstance(manifest.get("splits"), dict) or set(("train", "validation", "test")) - set(manifest["splits"]):
        raise TrainingGateError("training manifest requires train/validation/test split counts")
    return manifest
