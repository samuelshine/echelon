"""Validation for group-safe, reviewed split rows before tokenizer/model work."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable


def validate_split_rows(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    rows = list(rows)
    if not rows:
        raise ValueError("split rows cannot be empty")
    group_splits: dict[str, set[str]] = defaultdict(set)
    counts: dict[str, int] = defaultdict(int)
    required = {"record_id", "split", "semantic_cluster_id", "training_eligible"}
    for index, row in enumerate(rows, 1):
        if not required <= set(row):
            raise ValueError(f"row {index} is missing required split/provenance fields")
        if row["training_eligible"] is not True:
            raise ValueError(f"row {index} is not training eligible")
        split, group = row["split"], row["semantic_cluster_id"]
        if split not in {"train", "validation", "test"} or not isinstance(group, str) or not group:
            raise ValueError(f"row {index} has invalid split or semantic cluster")
        group_splits[group].add(split)
        counts[split] += 1
    leaking = [group for group, splits in group_splits.items() if len(splits) > 1]
    if leaking:
        raise ValueError(f"semantic clusters cross split boundaries: {len(leaking)}")
    if set(counts) != {"train", "validation", "test"}:
        raise ValueError("all train, validation, and test splits are required")
    return dict(sorted(counts.items()))
