#!/usr/bin/env python3
"""Semantic, template-diversity, and review-sampling audit for targeted candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

try:
    from scripts.build_semantic_splits import MODEL_ID, MODEL_REVISION, UnionFind, components, load_jsonl
except ModuleNotFoundError:  # Direct execution places scripts/ on sys.path.
    from build_semantic_splits import MODEL_ID, MODEL_REVISION, UnionFind, components, load_jsonl

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = PROJECT_ROOT / "data" / "raw_v2" / "echelon_targeted_v0_1" / "candidates.jsonl"
EXISTING_PATH = PROJECT_ROOT / "data" / "normalized_v2" / "eligible.jsonl"
EXISTING_CACHE = PROJECT_ROOT / "data" / "normalized_v2" / "semantic_embeddings.npz"
CANDIDATE_CACHE = PROJECT_ROOT / "data" / "normalized_v2" / "targeted_v0_1_embeddings.npz"
AUDIT_REPORT = PROJECT_ROOT / "data" / "reports" / "targeted_semantic_audit_report.json"
QUEUE_REPORT = PROJECT_ROOT / "data" / "reports" / "targeted_review_queue_report.json"
REVIEW_QUEUE = PROJECT_ROOT / "data" / "review_v2" / "targeted_v0_1_review.jsonl"


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def overlap_bucket(similarity: float) -> str:
    if similarity >= 0.97:
        return "very_high_0.97_plus"
    if similarity >= 0.94:
        return "high_0.94_0.97"
    if similarity >= 0.90:
        return "boundary_0.90_0.94"
    return "novel_below_0.90"


def token_words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_\[\]-]+", text.casefold())


def lexical_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tokens = [token for row in rows for token in token_words(row["text"])]
    bigrams = [pair for row in rows for pair in zip(token_words(row["text"]), token_words(row["text"])[1:])]
    prefix_signatures = {tuple(token_words(row["text"])[:8]) for row in rows}
    return {
        "tokens": len(tokens), "unique_tokens": len(set(tokens)),
        "type_token_ratio": round(len(set(tokens)) / max(len(tokens), 1), 6),
        "bigrams": len(bigrams), "unique_bigrams": len(set(bigrams)),
        "distinct_2": round(len(set(bigrams)) / max(len(bigrams), 1), 6),
        "unique_first_8_token_prefixes": len(prefix_signatures),
    }


def cached_embeddings(
    rows: list[dict[str, Any]], source_path: Path, cache_path: Path,
    model_id: str, model_revision: str, batch_size: int,
) -> np.ndarray:
    digest = file_digest(source_path)
    if cache_path.is_file():
        cache = np.load(cache_path, allow_pickle=False)
        if str(cache["input_sha256"]) == digest and str(cache["model_revision"]) == model_revision:
            return cache["embeddings"].astype(np.float32, copy=False)
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer(model_id, revision=model_revision)
    embeddings = model.encode(
        [row["text"] for row in rows], batch_size=batch_size, show_progress_bar=True,
        normalize_embeddings=True, convert_to_numpy=True,
    ).astype(np.float32, copy=False)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez(cache_path, embeddings=embeddings, input_sha256=digest, model_revision=model_revision)
    return embeddings


def build_candidate_groups(rows: list[dict[str, Any]], distances: np.ndarray, indices: np.ndarray, threshold: float) -> list[list[int]]:
    union_find = UnionFind(len(rows))
    id_to_index = {row["candidate_id"]: index for index, row in enumerate(rows)}
    for left, (row_distances, row_indices) in enumerate(zip(distances, indices)):
        for distance, right in zip(row_distances[1:], row_indices[1:]):
            if 1.0 - float(distance) >= threshold:
                union_find.union(left, int(right))
    for index, row in enumerate(rows):
        parent = row.get("parent_id")
        if parent in id_to_index:
            union_find.union(index, id_to_index[parent])
    return components(union_find, len(rows))


def deterministic_rank(item_id: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}\x1f{item_id}".encode()).hexdigest()


def stratified_review_sample(
    rows: list[dict[str, Any]], nearest_existing: list[dict[str, Any]],
    per_family: int = 100,
) -> list[dict[str, Any]]:
    by_family: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        by_family[row["family"]].append(index)
    selected: list[int] = []
    for family, indexes in sorted(by_family.items()):
        transformations = sorted({rows[index].get("transformation") for index in indexes if rows[index].get("transformation")})
        if transformations:
            per_transform = per_family // len(transformations)
            family_selected = []
            for transformation in transformations:
                eligible = [index for index in indexes if rows[index].get("transformation") == transformation]
                eligible.sort(key=lambda index: (
                    overlap_bucket(nearest_existing[index]["similarity"]),
                    deterministic_rank(rows[index]["candidate_id"], transformation),
                ))
                family_selected.extend(eligible[:per_transform])
            selected.extend(family_selected[:per_family])
            continue
        strata: dict[tuple[str, str, str], list[int]] = defaultdict(list)
        lengths = sorted(len(rows[index]["text"]) for index in indexes)
        short_cut = lengths[len(lengths) // 3]
        long_cut = lengths[(2 * len(lengths)) // 3]
        for index in indexes:
            length = len(rows[index]["text"])
            length_band = "short" if length <= short_cut else "medium" if length <= long_cut else "long"
            transform = rows[index].get("transformation") or "none"
            strata[(overlap_bucket(nearest_existing[index]["similarity"]), transform, length_band)].append(index)
        family_selected: list[int] = []
        ordered_strata = sorted(strata)
        cursor = 0
        while len(family_selected) < min(per_family, len(indexes)) and ordered_strata:
            key = ordered_strata[cursor % len(ordered_strata)]
            available = sorted(strata[key], key=lambda index: deterministic_rank(rows[index]["candidate_id"], family))
            already = set(family_selected)
            choice = next((index for index in available if index not in already), None)
            if choice is not None:
                family_selected.append(choice)
            elif all(all(index in already for index in strata[item]) for item in ordered_strata):
                break
            cursor += 1
        if len(family_selected) < min(per_family, len(indexes)):
            remaining = sorted(set(indexes) - set(family_selected), key=lambda index: deterministic_rank(rows[index]["candidate_id"], "fill"))
            family_selected.extend(remaining[:per_family - len(family_selected)])
        selected.extend(family_selected)
    return [rows[index] | {"nearest_existing": nearest_existing[index]} for index in selected]


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
    existing_cache = np.load(args.existing_cache, allow_pickle=False)
    existing_embeddings = existing_cache["embeddings"].astype(np.float32, copy=False)
    if len(existing_embeddings) != len(existing):
        raise RuntimeError("existing embedding cache row count does not match normalized corpus")

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
        "report_version": "0.1.0", "candidates": len(candidates),
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
        "status": "failed_semantic_diversity_gate" if gate_reasons else "pending_human_review",
    }
    args.audit_report.parent.mkdir(parents=True, exist_ok=True)
    args.audit_report.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    queue = stratified_review_sample(candidates, nearest_existing)
    args.review_queue.parent.mkdir(parents=True, exist_ok=True)
    with args.review_queue.open("w", encoding="utf-8") as handle:
        for row in queue:
            review = dict(row)
            review["review"] = {
                "reviewer_id": None, "naturalness": None, "intent_correct": None,
                "labels_correct": None, "non_operational": None, "accept": None, "notes": None,
            }
            handle.write(json.dumps(review, ensure_ascii=False, sort_keys=True) + "\n")
    queue_report = {
        "report_version": "0.1.0", "queue_rows": len(queue),
        "by_family": dict(sorted(Counter(row["family"] for row in queue).items())),
        "by_transformation": dict(sorted(Counter(str(row.get("transformation") or "none") for row in queue).items())),
        "by_overlap_bucket": dict(sorted(Counter(overlap_bucket(row["nearest_existing"]["similarity"]) for row in queue).items())),
        "required_review_fields": ["naturalness", "intent_correct", "labels_correct", "non_operational", "accept"],
        "training_eligible": False,
    }
    args.queue_report.parent.mkdir(parents=True, exist_ok=True)
    args.queue_report.write_text(json.dumps(queue_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"audit": audit, "queue": queue_report}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
