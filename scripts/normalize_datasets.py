#!/usr/bin/env python3
"""Normalize approved raw sources into provenance-rich Echelon JSONL.

Only prompt fields are emitted. Assistant responses are never copied. Rows with
unverified upstream provenance or known benchmark contamination are quarantined
in aggregate reports and are not written to the training-eligible JSONL.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_ROOT = PROJECT_ROOT / "data" / "raw_v2"
OUTPUT_ROOT = PROJECT_ROOT / "data" / "normalized_v2"
REPORT_PATH = PROJECT_ROOT / "data" / "reports" / "normalization_report.json"
REGISTRY_PATH = PROJECT_ROOT / "configs" / "dataset_registry.json"

NEURALCHEMY_QUARANTINE = {
    "harmbench": "evaluation_contamination",
    "harmbench_benign": "evaluation_contamination",
    "wildguard_judgecomp": "gated_upstream_unverified",
    "hackaprompt": "upstream_license_unverified",
}
LEAKAGE_CATEGORIES = {"training_extraction", "prompt_extraction", "system_extraction", "prompt_leak"}
OBFUSCATION_CATEGORIES = {"encoding", "encoding_obfuscation", "token_smuggling", "token_injection"}
VALID_SEVERITIES = {"none", "low", "medium", "high", "critical"}
SOURCE_PRIORITY = {
    "aegis_safety_2": 0,
    "jackhhao_jailbreak_classification": 1,
    "do_not_answer": 2,
    "neuralchemy_prompt_injection": 3,
}
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def fingerprint(text: str) -> str:
    canonical = unicodedata.normalize("NFKC", text).casefold()
    canonical = re.sub(r"\s+", " ", canonical).strip()
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_id(source_id: str, revision: str, split: str, source_item_id: str) -> str:
    material = "\x1f".join((source_id, revision, split, source_item_id))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def base_record(
    *, source_id: str, revision: str, split: str, source_item_id: str,
    text: str, labels: list[str], severity: str, license_spdx: str,
    template_family: str | None = None, transformation_parent_id: str | None = None,
    transformations: list[str] | None = None, context: str = "unknown",
    annotation_confidence: float = 1.0, notes: str | None = None,
) -> dict[str, Any]:
    return {
        "record_id": record_id(source_id, revision, split, source_item_id),
        "text": text.strip(),
        "source_id": source_id,
        "source_item_id": source_item_id,
        "source_revision": revision,
        "split": "validation" if split in {"val", "validation"} else split,
        "language": "en",
        "labels": labels,
        "severity": severity,
        "annotation_confidence": annotation_confidence,
        "template_family": template_family,
        "semantic_cluster_id": None,
        "conversation_id": None,
        "transformation_parent_id": transformation_parent_id,
        "transformations": transformations or [],
        "context": context,
        "license_spdx": license_spdx,
        "annotation_notes": notes,
    }


def labels_for_neuralchemy(label: int, category: str) -> list[str]:
    if int(label) == 0:
        return ["benign"]
    labels = ["prompt_injection"]
    if category in LEAKAGE_CATEGORIES:
        labels.append("system_prompt_leakage")
    if category in OBFUSCATION_CATEGORIES:
        labels.append("adversarial_obfuscation")
    return labels


def normalize_severity(value: Any, benign: bool) -> str:
    if benign:
        return "none"
    normalized = str(value or "medium").strip().lower() or "medium"
    return normalized if normalized in VALID_SEVERITIES - {"none"} else "medium"


def iter_neuralchemy(root: Path, revision: str) -> Iterator[tuple[dict[str, Any] | None, str | None]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError("PyArrow is required for neuralchemy Parquet normalization") from exc
    for path in sorted((root / "neuralchemy_prompt_injection" / revision / "full").glob("*.parquet")):
        split = path.name.split("-", 1)[0]
        for index, row in enumerate(pq.read_table(path).to_pylist()):
            upstream = str(row.get("source") or "unknown")
            if upstream in NEURALCHEMY_QUARANTINE:
                yield None, NEURALCHEMY_QUARANTINE[upstream]
                continue
            text = str(row.get("text") or "").strip()
            if not text:
                yield None, "empty_text"
                continue
            category = str(row.get("category") or "unknown")
            benign = int(row["label"]) == 0
            group_id = str(row.get("group_id") or f"ungrouped:{split}:{index}")
            augmented = bool(row.get("augmented"))
            transformations = ["publisher_augmentation"] if augmented else []
            yield base_record(
                source_id="neuralchemy_prompt_injection", revision=revision, split=split,
                source_item_id=f"{split}:{index}", text=text,
                labels=labels_for_neuralchemy(row["label"], category),
                severity=normalize_severity(row.get("severity"), benign), license_spdx="Apache-2.0",
                template_family=group_id, transformation_parent_id=group_id if augmented else None,
                transformations=transformations, context="benign" if benign else "malicious",
                notes=f"publisher_category={category};upstream_source={upstream}",
            ), None


def iter_aegis(root: Path, revision: str) -> Iterator[tuple[dict[str, Any] | None, str | None]]:
    directory = root / "aegis_safety_2" / revision
    for path in sorted(directory.glob("*.json")):
        split = path.stem
        for index, row in enumerate(json.loads(path.read_text(encoding="utf-8"))):
            text = str(row.get("prompt") or "").strip()
            if not text or text == "REDACTED":
                yield None, "redacted_or_empty"
                continue
            safe = str(row.get("prompt_label")).casefold() == "safe"
            categories = str(row.get("violated_categories") or "").strip()
            yield base_record(
                source_id="aegis_safety_2", revision=revision, split=split,
                source_item_id=str(row.get("id") or f"{split}:{index}"), text=text,
                labels=["benign"] if safe else ["toxicity_harm"],
                severity="none" if safe else "high", license_spdx="CC-BY-4.0",
                context="benign" if safe else "malicious", annotation_confidence=1.0,
                notes=f"publisher_categories={categories}" if categories else None,
            ), None


def iter_jackhhao(root: Path, revision: str) -> Iterator[tuple[dict[str, Any] | None, str | None]]:
    directory = root / "jackhhao_jailbreak_classification" / revision / "balanced"
    for path in sorted(directory.glob("*dataset_*_balanced.csv")):
        if "full" in path.name:
            continue
        split = "train" if "train" in path.name else "test"
        with path.open("r", encoding="utf-8", newline="") as handle:
            for index, row in enumerate(csv.DictReader(handle)):
                text = str(row.get("prompt") or "").strip()
                if not text:
                    yield None, "empty_text"
                    continue
                benign = str(row.get("type")).casefold() == "benign"
                yield base_record(
                    source_id="jackhhao_jailbreak_classification", revision=revision, split=split,
                    source_item_id=f"{split}:{index}", text=text,
                    labels=["benign"] if benign else ["prompt_injection"],
                    severity="none" if benign else "high", license_spdx="Apache-2.0",
                    context="benign" if benign else "malicious",
                ), None


def iter_do_not_answer(root: Path, revision: str) -> Iterator[tuple[dict[str, Any] | None, str | None]]:
    path = root / "do_not_answer" / revision / "data_en.csv"
    with path.open("r", encoding="utf-8", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle)):
            text = str(row.get("question") or "").strip()
            if not text:
                yield None, "empty_text"
                continue
            risk_area = str(row.get("risk_area") or "unknown")
            yield base_record(
                source_id="do_not_answer", revision=revision, split="train",
                source_item_id=str(row.get("id") or index), text=text,
                labels=["toxicity_harm"], severity="high", license_spdx="Apache-2.0",
                context="malicious", annotation_confidence=0.9,
                notes=f"publisher_risk_area={risk_area}",
            ), None


def deduplicate_records(records: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        groups[fingerprint(row["text"])].append(row)
    kept: list[dict[str, Any]] = []
    stats = Counter()
    for rows in groups.values():
        benign_states = {"benign" in row["labels"] for row in rows}
        if len(benign_states) > 1:
            stats["conflicting_groups_quarantined"] += 1
            stats["conflicting_rows_quarantined"] += len(rows)
            continue
        canonical = min(rows, key=lambda row: (SOURCE_PRIORITY.get(row["source_id"], 99), row["record_id"]))
        if len(rows) > 1:
            stats["consistent_duplicate_groups_collapsed"] += 1
            stats["consistent_duplicate_rows_removed"] += len(rows) - 1
            if not next(iter(benign_states)):
                canonical["labels"] = sorted({label for row in rows for label in row["labels"]})
                canonical["severity"] = max((row["severity"] for row in rows), key=SEVERITY_RANK.get)
            duplicate_sources = sorted({row["source_id"] for row in rows})
            note = canonical.get("annotation_notes") or ""
            canonical["annotation_notes"] = (note + ";" if note else "") + "duplicate_sources=" + ",".join(duplicate_sources)
        kept.append(canonical)
    stats["candidate_rows"] = sum(len(rows) for rows in groups.values())
    stats["deduplicated_rows"] = len(kept)
    return kept, dict(sorted(stats.items()))


def build_report(
    candidate_records: Iterable[dict[str, Any]], records: Iterable[dict[str, Any]],
    quarantined: Counter[str], deduplication: dict[str, int],
) -> dict[str, Any]:
    candidate_records = list(candidate_records)
    records = list(records)
    by_source = Counter(row["source_id"] for row in records)
    benign_by_source = Counter(row["source_id"] for row in records if "benign" in row["labels"])
    by_split = Counter(row["split"] for row in records)
    by_label = Counter(label for row in records for label in row["labels"])
    fingerprints: dict[str, list[dict[str, Any]]] = defaultdict(list)
    group_splits: dict[str, set[str]] = defaultdict(set)
    for row in candidate_records:
        fingerprints[fingerprint(row["text"])].append(row)
    for row in records:
        group = f"{row['source_id']}:{row['template_family']}" if row["template_family"] else row["record_id"]
        group_splits[group].add(row["split"])
    duplicate_groups = [rows for rows in fingerprints.values() if len(rows) > 1]
    cross_source = sum(1 for rows in duplicate_groups if len({row["source_id"] for row in rows}) > 1)
    conflicting_labels = sum(1 for rows in duplicate_groups if len({tuple(row["labels"]) for row in rows}) > 1)
    return {
        "report_version": "0.1.0",
        "eligible_records": len(records),
        "benign_records": by_label["benign"],
        "benign_fraction": round(by_label["benign"] / len(records), 6) if records else 0.0,
        "benign_by_source": dict(sorted(benign_by_source.items())),
        "malicious_records": len(records) - by_label["benign"],
        "by_source": dict(sorted(by_source.items())),
        "by_publisher_split": dict(sorted(by_split.items())),
        "label_occurrences": dict(sorted(by_label.items())),
        "quarantined": dict(sorted(quarantined.items())),
        "deduplication": deduplication,
        "normalized_duplicate_groups": len(duplicate_groups),
        "cross_source_duplicate_groups": cross_source,
        "duplicate_groups_with_any_label_difference": conflicting_labels,
        "template_groups_crossing_publisher_splits": sum(1 for splits in group_splits.values() if len(splits) > 1),
        "split_design": {
            "status": "proposed_not_materialized",
            "group_keys": ["semantic_cluster_id", "template_family", "transformation_parent_id", "conversation_id", "normalized_fingerprint"],
            "constraints": [
                "all related group members stay in one split",
                "evaluation-only sources never enter train or validation",
                "benign and malicious category distributions are stratified at group level",
                "English native-speaker gold records are test-only",
                "cross-source duplicates are assigned once after label adjudication"
            ]
        }
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-root", type=Path, default=RAW_ROOT)
    parser.add_argument("--output", type=Path, default=OUTPUT_ROOT / "eligible.jsonl")
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    args = parser.parse_args(argv)

    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    revisions = {item["id"]: item["revision"] for item in registry["datasets"] if item.get("review_state") == "approved"}
    iterators = [
        iter_neuralchemy(args.raw_root, revisions["neuralchemy_prompt_injection"]),
        iter_jackhhao(args.raw_root, revisions["jackhhao_jailbreak_classification"]),
        iter_aegis(args.raw_root, revisions["aegis_safety_2"]),
        iter_do_not_answer(args.raw_root, revisions["do_not_answer"]),
    ]
    candidate_records: list[dict[str, Any]] = []
    quarantined: Counter[str] = Counter()
    for iterator in iterators:
        for record, reason in iterator:
            if reason:
                quarantined[reason] += 1
            elif record:
                candidate_records.append(record)

    records, deduplication = deduplicate_records(candidate_records)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".part")
    with temporary.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    temporary.replace(args.output)

    report = build_report(candidate_records, records, quarantined, deduplication)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
