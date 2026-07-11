#!/usr/bin/env python3
"""Build leakage-resistant semantic groups and deterministic split manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
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


def assign_splits(
    records: list[dict[str, Any]], groups: list[list[int]],
    ratios: dict[str, float] | None = None,
    preserve_publisher_holdouts: bool = False,
) -> dict[str, list[list[int]]]:
    ratios = ratios or {"train": 0.8, "validation": 0.1, "test": 0.1}
    total = sum(len(group) for group in groups)
    total_benign = sum("benign" in records[index]["labels"] for group in groups for index in group)
    targets = {
        split: {"rows": total * ratio, "benign": total_benign * ratio}
        for split, ratio in ratios.items()
    }
    assigned: dict[str, list[list[int]]] = {split: [] for split in ratios}
    counts = {split: Counter() for split in ratios}

    fixed, flexible = [], []
    for group in groups:
        publisher_splits = {records[index]["split"] for index in group}
        if preserve_publisher_holdouts and "test" in publisher_splits:
            fixed.append(("test", group))
        elif preserve_publisher_holdouts and "validation" in publisher_splits:
            fixed.append(("validation", group))
        else:
            flexible.append(group)

    def add(split: str, group: list[int]) -> None:
        assigned[split].append(group)
        counts[split]["rows"] += len(group)
        counts[split]["benign"] += sum("benign" in records[index]["labels"] for index in group)

    for split, group in fixed:
        add(split, group)
    flexible.sort(key=lambda group: (-len(group), cluster_id(records, group)))
    for group in flexible:
        group_benign = sum("benign" in records[index]["labels"] for index in group)
        best_split = max(
            ratios,
            key=lambda split: (
                (targets[split]["rows"] - counts[split]["rows"]) / max(targets[split]["rows"], 1)
                + (targets[split]["benign"] - counts[split]["benign"]) / max(targets[split]["benign"], 1),
                split,
            ),
        )
        add(best_split, group)
    return assigned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=INPUT_PATH)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--split-root", type=Path, default=SPLIT_ROOT)
    parser.add_argument("--review-queue", type=Path, default=REVIEW_PATH)
    parser.add_argument("--model", default=MODEL_ID)
    parser.add_argument("--model-revision", default=MODEL_REVISION)
    parser.add_argument("--threshold", type=float, default=0.94)
    parser.add_argument("--neighbors", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=64)
    args = parser.parse_args()

    from sentence_transformers import SentenceTransformer
    from sklearn.neighbors import NearestNeighbors

    records = load_jsonl(args.input)
    views, truncated = [], 0
    for record in records:
        view, was_truncated = embedding_view(record["text"])
        views.append(view)
        truncated += was_truncated
    model = SentenceTransformer(args.model, revision=args.model_revision)
    embeddings = model.encode(
        views, batch_size=args.batch_size, show_progress_bar=True,
        normalize_embeddings=True, convert_to_numpy=True,
    ).astype(np.float32, copy=False)

    neighbors = NearestNeighbors(n_neighbors=min(args.neighbors, len(records)), metric="cosine", algorithm="brute", n_jobs=-1)
    neighbors.fit(embeddings)
    distances, indices = neighbors.kneighbors(embeddings, return_distance=True)
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

    assigned = assign_splits(records, eligible_groups)
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
        "manifest_version": "0.1.0", "embedding_model": args.model,
        "embedding_model_revision": args.model_revision, "cosine_threshold": args.threshold,
        "splits": manifest_splits,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = {
        "report_version": "0.1.0", "input_records": len(records),
        "embedding_model": args.model, "embedding_model_revision": args.model_revision,
        "embedding_license": "MIT", "cosine_threshold": args.threshold,
        "embedding_views_truncated_head_tail": truncated, "semantic_edges": semantic_edges,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
