#!/usr/bin/env python3
"""Build leakage-resistant semantic groups and deterministic split manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = PROJECT_ROOT / "data" / "normalized_v2" / "eligible.jsonl"
REPORT_PATH = PROJECT_ROOT / "data" / "reports" / "semantic_split_report.json"
MANIFEST_PATH = PROJECT_ROOT / "data" / "manifests" / "semantic_split_manifest.json"
SPLIT_ROOT = PROJECT_ROOT / "data" / "splits_v2"
REVIEW_PATH = PROJECT_ROOT / "data" / "review_v2" / "semantic_conflicts.jsonl"
PAIR_REVIEW_PATH = PROJECT_ROOT / "data" / "review_v2" / "semantic_pair_calibration.jsonl"
PAIR_REPORT_PATH = PROJECT_ROOT / "data" / "reports" / "semantic_calibration_queue_report.json"
EMBEDDING_CACHE_PATH = PROJECT_ROOT / "data" / "normalized_v2" / "semantic_embeddings.npz"
MODEL_ID = "BAAI/bge-small-en-v1.5"
MODEL_REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"


class UnionFind:
    def __init__(self, size: int):
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root == right_root:
            return
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1


def embedding_view(text: str, max_chars: int = 2400) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    half = max_chars // 2
    return text[:half] + "\n[...TRUNCATED FOR SEMANTIC FINGERPRINT...]\n" + text[-half:], True


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    # splitlines() also splits U+2028/U+2029, which are valid inside JSON strings.
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line]


def project_relative(path: Path) -> str:
    """Report a path relative to the project root, given absolute or relative.

    Reports are read as project-relative paths, but these scripts are routinely
    invoked with relative --flags from the project directory, where a bare
    Path.relative_to(PROJECT_ROOT) raises.
    """
    resolved = path if path.is_absolute() else (Path.cwd() / path)
    try:
        return str(resolved.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def input_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pair_kind(left: dict[str, Any], right: dict[str, Any]) -> str:
    left_benign = "benign" in left["labels"]
    right_benign = "benign" in right["labels"]
    if left_benign and right_benign:
        return "benign_benign"
    if not left_benign and not right_benign:
        return "malicious_malicious"
    return "mixed_safety"


def calibration_band(similarity: float) -> str | None:
    for lower, upper, label in (
        (0.90, 0.92, "0.90-0.92"), (0.92, 0.94, "0.92-0.94"),
        (0.94, 0.96, "0.94-0.96"), (0.96, 0.98, "0.96-0.98"),
        (0.98, 1.000001, "0.98-1.00"),
    ):
        if lower <= similarity < upper:
            return label
    return None


def sample_calibration_pairs(
    records: list[dict[str, Any]], distances: np.ndarray, indices: np.ndarray,
    per_band_kind: int = 30,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    seen: set[tuple[int, int]] = set()
    for left, (row_distances, row_indices) in enumerate(zip(distances, indices)):
        for distance, right_value in zip(row_distances[1:], row_indices[1:]):
            right = int(right_value)
            key = (min(left, right), max(left, right))
            if key in seen:
                continue
            seen.add(key)
            similarity = 1.0 - float(distance)
            band = calibration_band(similarity)
            if not band:
                continue
            kind = pair_kind(records[left], records[right])
            pair_id = "pair_" + hashlib.sha256(
                "\x1f".join(sorted((records[left]["record_id"], records[right]["record_id"]))).encode()
            ).hexdigest()[:20]
            candidates[(band, kind)].append({
                "pair_id": pair_id, "band": band, "pair_kind": kind,
                "cosine_similarity": round(similarity, 8),
                "left": {"record_id": records[left]["record_id"], "text": records[left]["text"], "labels": records[left]["labels"]},
                "right": {"record_id": records[right]["record_id"], "text": records[right]["text"], "labels": records[right]["labels"]},
                "review": {"semantic_relation": None, "safety_relation": None, "reviewer_id": None, "notes": None},
            })
    selected = []
    availability = {}
    for key in sorted(candidates):
        rows = sorted(candidates[key], key=lambda row: hashlib.sha256(row["pair_id"].encode()).hexdigest())
        selected.extend(rows[:per_band_kind])
        availability["/".join(key)] = len(rows)
    selected.sort(key=lambda row: (row["band"], row["pair_kind"], row["pair_id"]))
    return selected, availability


def add_declared_group_edges(records: list[dict[str, Any]], union_find: UnionFind) -> int:
    owners: dict[tuple[str, str], int] = {}
    edges = 0
    for index, record in enumerate(records):
        for field in ("template_family", "transformation_parent_id", "conversation_id"):
            value = record.get(field)
            if not value:
                continue
            key = (field, f"{record['source_id']}:{value}")
            if key in owners:
                union_find.union(index, owners[key])
                edges += 1
            else:
                owners[key] = index
    return edges


def components(union_find: UnionFind, size: int) -> list[list[int]]:
    grouped: dict[int, list[int]] = defaultdict(list)
    for index in range(size):
        grouped[union_find.find(index)].append(index)
    return list(grouped.values())


def cluster_id(records: list[dict[str, Any]], members: list[int]) -> str:
    material = "\x1f".join(sorted(records[index]["record_id"] for index in members))
    return "sem_" + hashlib.sha256(material.encode()).hexdigest()[:20]


def is_mixed_safety(records: list[dict[str, Any]], members: list[int]) -> bool:
    return len({"benign" in records[index]["labels"] for index in members}) > 1


# Rows generated by this project's own targeted/response generators. Kept in step
# with scripts/evaluate_layer2_v03.py, which slices the same way to report
# real-vs-synthetic performance.
SYNTHETIC_SOURCE_PREFIXES = ("echelon_targeted_", "echelon_response_")


def source_kind(record: dict[str, Any]) -> str:
    return "synthetic" if str(record.get("source_id", "")).startswith(SYNTHETIC_SOURCE_PREFIXES) else "real"


def group_profile(records: list[dict[str, Any]], group: list[int]) -> Counter:
    """Rows, benign rows, and per-category positives a group would contribute.

    These are the dimensions split allocation balances on. Before v0.2.0 of this
    manifest only `rows` and `benign` were balanced, which let whole categories
    land in one or two splits: the v0.3 corpus ended up with 852 `malicious_code`
    rows in train, 148 in test, and *zero* in validation -- so that head's
    temperature was calibrated on negatives only and its per-epoch validation F1
    was a constant 0 during model selection.

    Categories are also split by source kind, because balancing the category
    alone is not enough once it contains two distinct sub-populations. When the
    first real `malicious_code` rows were merged into a corpus already holding
    ~900 synthetic ones, category-only stratification hit 80/10/10 on the total
    while putting *all 153* real rows in validation and test and none in train --
    training would have stayed exactly as blind to real malicious code as before,
    against a test set made artificially hard. Real and synthetic positives are
    therefore balanced as separate dimensions.
    """
    profile: Counter = Counter()
    profile["rows"] = len(group)
    for index in group:
        record = records[index]
        kind = source_kind(record)
        for label in record["labels"]:
            profile[label] += 1
            profile[f"{label}@{kind}"] += 1
    return profile


def assign_splits(
    records: list[dict[str, Any]], groups: list[list[int]],
    ratios: dict[str, float] | None = None,
    preserve_publisher_holdouts: bool = False,
    stratify_labels: bool = True,
) -> dict[str, list[list[int]]]:
    ratios = ratios or {"train": 0.8, "validation": 0.1, "test": 0.1}
    profiles = [group_profile(records, group) for group in groups]
    totals: Counter = Counter()
    for profile in profiles:
        totals.update(profile)
    if not stratify_labels:
        totals = Counter({key: totals[key] for key in ("rows", "benign")})
    targets = {
        split: {key: value * ratio for key, value in totals.items()}
        for split, ratio in ratios.items()
    }
    assigned: dict[str, list[list[int]]] = {split: [] for split in ratios}
    counts = {split: Counter() for split in ratios}

    fixed, flexible = [], []
    for position, group in enumerate(groups):
        publisher_splits = {records[index]["split"] for index in group}
        if preserve_publisher_holdouts and "test" in publisher_splits:
            fixed.append(("test", position))
        elif preserve_publisher_holdouts and "validation" in publisher_splits:
            fixed.append(("validation", position))
        else:
            flexible.append(position)

    def add(split: str, position: int) -> None:
        assigned[split].append(groups[position])
        counts[split].update(profiles[position])

    def deficit(split: str, keys: list[str]) -> float:
        """Mean shortfall against target, normalized per dimension.

        Only the dimensions this group actually contributes to are scored, so a
        sparse-category group is steered by that category's deficit instead of
        being drowned out by the two bulk dimensions.
        """
        return sum(
            (targets[split][key] - counts[split][key]) / max(targets[split][key], 1)
            for key in keys
        ) / len(keys)

    def scored_keys(position: int) -> list[str]:
        keys = [key for key, value in profiles[position].items() if value and key in totals]
        return keys or ["rows"]

    def scarcity(position: int) -> int:
        """Global size of the rarest dimension this group carries."""
        keys = [key for key in scored_keys(position) if key != "rows"]
        return min((totals[key] for key in keys), default=totals.get("rows", 0))

    for split, position in fixed:
        add(split, position)
    # Scarcest dimensions first, then largest. Ordering by size alone spends the
    # bulk categories' budget before a rare category is ever considered, and a
    # rare category may live in too few semantic groups to recover: the 153 real
    # malicious_code rows merged for v0.5 collapsed into just *two* groups, so by
    # the time size ordering reached them every split's row deficit was already
    # settled and both landed outside train.
    flexible.sort(key=lambda position: (
        scarcity(position), -len(groups[position]), cluster_id(records, groups[position]),
    ))
    for position in flexible:
        keys = scored_keys(position)
        # Ties break toward the split with the largest absolute target, so the
        # first (largest) group of a scarce category goes to train rather than to
        # whichever split sorts last alphabetically.
        best_split = max(ratios, key=lambda split: (deficit(split, keys), targets[split]["rows"], split))
        add(best_split, position)
    return assigned


def split_label_balance(
    records: list[dict[str, Any]], assigned: dict[str, list[list[int]]],
) -> dict[str, Any]:
    """Per-split label counts plus any category missing from a split entirely."""
    per_split = {
        split: dict(sorted(Counter(
            label for group in groups for index in group
            for label in records[index]["labels"]
        ).items()))
        for split, groups in assigned.items()
    }
    every_label = sorted({label for counts in per_split.values() for label in counts})
    missing = {
        split: [label for label in every_label if not per_split[split].get(label)]
        for split in sorted(per_split)
    }
    return {
        "label_occurrences": per_split,
        "categories_absent_from_split": {k: v for k, v in missing.items() if v},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=INPUT_PATH)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--split-root", type=Path, default=SPLIT_ROOT)
    parser.add_argument("--review-queue", type=Path, default=REVIEW_PATH)
    parser.add_argument("--pair-review-queue", type=Path, default=PAIR_REVIEW_PATH)
    parser.add_argument("--pair-report", type=Path, default=PAIR_REPORT_PATH)
    parser.add_argument("--embedding-cache", type=Path, default=EMBEDDING_CACHE_PATH)
    parser.add_argument("--model", default=MODEL_ID)
    parser.add_argument("--model-revision", default=MODEL_REVISION)
    parser.add_argument("--threshold", type=float, default=0.94)
    parser.add_argument("--neighbors", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument(
        "--no-label-stratification", dest="stratify_labels", action="store_false",
        help="balance splits on row/benign counts only, reproducing pre-v0.2.0 allocation",
    )
    args = parser.parse_args()

    from sentence_transformers import SentenceTransformer
    from sklearn.neighbors import NearestNeighbors

    records = load_jsonl(args.input)
    views, truncated = [], 0
    for record in records:
        view, was_truncated = embedding_view(record["text"])
        views.append(view)
        truncated += was_truncated
    source_digest = input_digest(args.input)
    embeddings = None
    if args.embedding_cache.is_file():
        cached = np.load(args.embedding_cache, allow_pickle=False)
        if str(cached["input_sha256"]) == source_digest and str(cached["model_revision"]) == args.model_revision:
            embeddings = cached["embeddings"].astype(np.float32, copy=False)
    if embeddings is None:
        model = SentenceTransformer(args.model, revision=args.model_revision)
        embeddings = model.encode(
            views, batch_size=args.batch_size, show_progress_bar=True,
            normalize_embeddings=True, convert_to_numpy=True,
        ).astype(np.float32, copy=False)
        args.embedding_cache.parent.mkdir(parents=True, exist_ok=True)
        np.savez(args.embedding_cache, embeddings=embeddings, input_sha256=source_digest, model_revision=args.model_revision)

    neighbors = NearestNeighbors(n_neighbors=min(args.neighbors, len(records)), metric="cosine", algorithm="brute", n_jobs=-1)
    neighbors.fit(embeddings)
    distances, indices = neighbors.kneighbors(embeddings, return_distance=True)
    calibration_pairs, pair_availability = sample_calibration_pairs(records, distances, indices)
    args.pair_review_queue.parent.mkdir(parents=True, exist_ok=True)
    with args.pair_review_queue.open("w", encoding="utf-8") as handle:
        for pair in calibration_pairs:
            handle.write(json.dumps(pair, ensure_ascii=False, sort_keys=True) + "\n")
    pair_report = {
        "report_version": "0.1.0", "queue_pairs": len(calibration_pairs),
        "target_per_band_and_pair_kind": 30, "available_candidates": pair_availability,
        "bands": ["0.90-0.92", "0.92-0.94", "0.94-0.96", "0.96-0.98", "0.98-1.00"],
        "pair_kinds": ["benign_benign", "malicious_malicious", "mixed_safety"],
        "required_judgments": ["semantic_relation", "safety_relation"],
    }
    args.pair_report.parent.mkdir(parents=True, exist_ok=True)
    args.pair_report.write_text(json.dumps(pair_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    union_find = UnionFind(len(records))
    semantic_edges = 0
    for left, (row_distances, row_indices) in enumerate(zip(distances, indices)):
        for distance, right in zip(row_distances[1:], row_indices[1:]):
            if 1.0 - float(distance) >= args.threshold:
                union_find.union(left, int(right))
                semantic_edges += 1
    declared_edges = add_declared_group_edges(records, union_find)
    all_groups = components(union_find, len(records))
    mixed_groups = [group for group in all_groups if is_mixed_safety(records, group)]
    eligible_groups = [group for group in all_groups if not is_mixed_safety(records, group)]

    args.review_queue.parent.mkdir(parents=True, exist_ok=True)
    with args.review_queue.open("w", encoding="utf-8") as handle:
        for group in mixed_groups:
            handle.write(json.dumps({
                "semantic_cluster_id": cluster_id(records, group),
                "members": [{
                    "record_id": records[index]["record_id"], "text": records[index]["text"],
                    "source_id": records[index]["source_id"], "labels": records[index]["labels"],
                } for index in group],
            }, ensure_ascii=False, sort_keys=True) + "\n")

    assigned = assign_splits(records, eligible_groups, stratify_labels=args.stratify_labels)
    balance = split_label_balance(records, assigned)
    args.split_root.mkdir(parents=True, exist_ok=True)
    manifest_splits: dict[str, list[str]] = {}
    split_stats: dict[str, Any] = {}
    for split, groups in assigned.items():
        rows = []
        for group in groups:
            semantic_id = cluster_id(records, group)
            for index in group:
                row = dict(records[index])
                row["semantic_cluster_id"] = semantic_id
                row["split"] = split
                rows.append(row)
        rows.sort(key=lambda row: row["record_id"])
        with (args.split_root / f"{split}.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        manifest_splits[split] = [row["record_id"] for row in rows]
        split_stats[split] = {
            "rows": len(rows),
            "groups": len(groups),
            "benign": sum("benign" in row["labels"] for row in rows),
            "malicious": sum("benign" not in row["labels"] for row in rows),
            "label_occurrences": dict(sorted(Counter(label for row in rows for label in row["labels"]).items())),
        }

    manifest = {
        "manifest_version": "0.2.0", "embedding_model": args.model,
        "embedding_model_revision": args.model_revision, "cosine_threshold": args.threshold,
        "input_sha256": source_digest,
        "label_stratified_allocation": args.stratify_labels,
        "splits": manifest_splits,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = {
        "report_version": "0.2.0", "input_records": len(records),
        "label_stratified_allocation": args.stratify_labels,
        "split_label_balance": balance,
        "embedding_model": args.model, "embedding_model_revision": args.model_revision,
        "embedding_license": "MIT", "cosine_threshold": args.threshold,
        "embedding_views_truncated_head_tail": truncated, "semantic_edges": semantic_edges,
        "semantic_calibration_queue_pairs": len(calibration_pairs),
        "declared_group_edges": declared_edges, "total_groups": len(all_groups),
        "multi_record_groups": sum(len(group) > 1 for group in all_groups),
        "largest_group": max(map(len, all_groups), default=0),
        "mixed_safety_groups_quarantined": len(mixed_groups),
        "mixed_safety_rows_quarantined": sum(map(len, mixed_groups)),
        "split_stats": split_stats,
        "leakage_check": {
            "semantic_cluster_ids_crossing_splits": 0,
            "publisher_splits": "repartitioned_by_complete_semantic_group"
        },
        "status": "materialized_pending_human_review"
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    absent = balance["categories_absent_from_split"]
    if absent:
        # Not fatal here -- materialization still succeeds -- but a category with no
        # validation positives silently degrades temperature calibration and per-epoch
        # model selection for that head, so it must never pass unnoticed.
        print(
            "WARNING: categories absent from a split: "
            + json.dumps(absent, sort_keys=True),
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
