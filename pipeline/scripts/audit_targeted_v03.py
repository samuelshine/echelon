#!/usr/bin/env python3
"""Semantic/lexical diversity audit + full-coverage review queue for v0.3.

Adapted from audit_targeted_candidates.py (v0.1/v0.2) with one deliberate
change: this round is reviewed with AI-assisted dual review at 100% coverage
(see docs/LAYER2_RETRAIN_PLAN.md and CURRENT_PROGRESS.md's v0.3 entry for why
that's a defensible substitute for the stratified ~100/family human-review
sample audit_targeted_candidates.py used, when human reviewer bandwidth is
not the constraint), so the review queue below is every candidate, not a
stratified subsample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

try:
    from scripts.build_semantic_splits import MODEL_ID, MODEL_REVISION, UnionFind, components, load_jsonl
except ModuleNotFoundError:
    from build_semantic_splits import MODEL_ID, MODEL_REVISION, UnionFind, components, load_jsonl
try:
    from scripts.audit_targeted_candidates import (
        build_candidate_groups, cached_embeddings, lexical_metrics, overlap_bucket,
    )
except ModuleNotFoundError:
    from audit_targeted_candidates import (
        build_candidate_groups, cached_embeddings, lexical_metrics, overlap_bucket,
    )

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = PROJECT_ROOT / "data" / "raw_v2" / "echelon_targeted_v0_3" / "candidates.jsonl"
EXISTING_PATH = PROJECT_ROOT / "data" / "normalized_v2" / "eligible.jsonl"
EXISTING_CACHE = PROJECT_ROOT / "data" / "normalized_v2" / "semantic_embeddings.npz"
CANDIDATE_CACHE = PROJECT_ROOT / "data" / "normalized_v2" / "targeted_v0_3_embeddings.npz"
AUDIT_REPORT = PROJECT_ROOT / "data" / "reports" / "targeted_v03_semantic_audit_report.json"
QUEUE_REPORT = PROJECT_ROOT / "data" / "reports" / "targeted_v03_review_queue_report.json"
REVIEW_QUEUE = PROJECT_ROOT / "data" / "review_v2" / "targeted_v0_3_review.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, default=CANDIDATE_PATH)
    parser.add_argument("--existing", type=Path, default=EXISTING_PATH)
    parser.add_argument("--existing-cache", type=Path, default=EXISTING_CACHE)
    parser.add_argument("--candidate-cache", type=Path, default=CANDIDATE_CACHE)
    parser.add_argument("--audit-report", type=Path, default=AUDIT_REPORT)
    parser.add_argument("--queue-report", type=Path, default=QUEUE_REPORT)
    parser.add_argument("--review-queue", type=Path, default=REVIEW_QUEUE)
    parser.add_argument("--threshold", type=float, default=0.94)
    parser.add_argument("--batch-size", type=int, default=64)
    args = parser.parse_args()

    from sklearn.neighbors import NearestNeighbors

    candidates = load_jsonl(args.candidates)
    existing = load_jsonl(args.existing)
    candidate_embeddings = cached_embeddings(candidates, args.candidates, args.candidate_cache, MODEL_ID, MODEL_REVISION, args.batch_size)
    # The stored cache predates the current eligible.jsonl (33,063 vs 32,465 rows) --
    # go through cached_embeddings (digest-checked) instead of a raw np.load so a stale
    # cache is transparently rebuilt rather than silently mismatched or hard-failing.
    existing_embeddings = cached_embeddings(existing, args.existing, args.existing_cache, MODEL_ID, MODEL_REVISION, args.batch_size)

    existing_nn = NearestNeighbors(n_neighbors=1, metric="cosine", algorithm="brute", n_jobs=-1).fit(existing_embeddings)
    existing_distances, existing_indices = existing_nn.kneighbors(candidate_embeddings)
    nearest_existing = []
    for distance, index in zip(existing_distances[:, 0], existing_indices[:, 0]):
        row = existing[int(index)]
        nearest_existing.append({
            "record_id": row["record_id"], "source_id": row["source_id"],
            "labels": row["labels"], "text": row["text"],
            "similarity": round(1.0 - float(distance), 8),
        })

    internal_nn = NearestNeighbors(n_neighbors=8, metric="cosine", algorithm="brute", n_jobs=-1).fit(candidate_embeddings)
    internal_distances, internal_indices = internal_nn.kneighbors(candidate_embeddings)
    groups = build_candidate_groups(candidates, internal_distances, internal_indices, args.threshold)
    mixed_groups = [group for group in groups if len({"benign" in candidates[index]["proposed_labels"] for index in group}) > 1]
    existing_buckets = Counter(overlap_bucket(item["similarity"]) for item in nearest_existing)
    cross_label_at_threshold = sum(
        item["similarity"] >= args.threshold
        and (("benign" in candidates[index]["proposed_labels"]) != ("benign" in item["labels"]))
        for index, item in enumerate(nearest_existing)
    )
    internal_best = 1.0 - internal_distances[:, 1]
    largest_group = max(map(len, groups), default=0)
    gate_reasons = []
    if largest_group / max(len(candidates), 1) > 0.10:
        gate_reasons.append("largest_semantic_component_exceeds_10_percent")
    if mixed_groups:
        gate_reasons.append("mixed_benign_malicious_semantic_components")
    audit = {
        "report_version": "0.3.0", "candidates": len(candidates),
        "model": MODEL_ID, "model_revision": MODEL_REVISION, "threshold": args.threshold,
        "nearest_existing_overlap_buckets": dict(sorted(existing_buckets.items())),
        "nearest_existing_similarity": {
            "min": round(float(existing_distances[:, 0].max() * -1 + 1), 8),
            "max": round(float(1.0 - existing_distances[:, 0].min()), 8),
            "mean": round(float(np.mean(1.0 - existing_distances[:, 0])), 8),
        },
        "cross_label_existing_neighbors_at_threshold": cross_label_at_threshold,
        "internal_nearest_similarity": {
            "min": round(float(internal_best.min()), 8), "max": round(float(internal_best.max()), 8),
            "mean": round(float(internal_best.mean()), 8),
        },
        "semantic_parent_groups": len(groups), "multi_record_groups": sum(len(group) > 1 for group in groups),
        "largest_group": largest_group,
        "largest_group_fraction": round(largest_group / max(len(candidates), 1), 6),
        "mixed_safety_groups": len(mixed_groups), "mixed_safety_rows": sum(map(len, mixed_groups)),
        "lexical_by_family": {family: lexical_metrics([row for row in candidates if row["family"] == family])
                              for family in sorted({row["family"] for row in candidates})},
        "admission_gate": {"passed": not gate_reasons, "reasons": gate_reasons},
        "status": "failed_semantic_diversity_gate" if gate_reasons else "pending_review",
    }
    args.audit_report.parent.mkdir(parents=True, exist_ok=True)
    args.audit_report.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Full-coverage queue: every candidate, not a stratified sample (see module docstring).
    args.review_queue.parent.mkdir(parents=True, exist_ok=True)
    with args.review_queue.open("w", encoding="utf-8") as handle:
        for index, row in enumerate(candidates):
            review = dict(row)
            review["nearest_existing"] = nearest_existing[index]
            review["review"] = {
                "reviewer_id": None, "naturalness": None, "intent_correct": None,
                "labels_correct": None, "non_operational": None, "accept": None, "notes": None,
            }
            handle.write(json.dumps(review, ensure_ascii=False, sort_keys=True) + "\n")
    queue_report = {
        "report_version": "0.3.0", "queue_rows": len(candidates), "coverage": "full (100%)",
        "by_family": dict(sorted(Counter(row["family"] for row in candidates).items())),
        "by_transformation": dict(sorted(Counter(str(row.get("transformation") or "none") for row in candidates).items())),
        "by_overlap_bucket": dict(sorted(Counter(overlap_bucket(item["similarity"]) for item in nearest_existing).items())),
        "required_review_fields": ["naturalness", "intent_correct", "labels_correct", "non_operational", "accept"],
        "training_eligible": False,
    }
    args.queue_report.parent.mkdir(parents=True, exist_ok=True)
    args.queue_report.write_text(json.dumps(queue_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"audit": audit, "queue": queue_report}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
