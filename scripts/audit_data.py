#!/usr/bin/env python3
"""Audit Echelon dataset governance and local processed CSV integrity.

The command is intentionally read-only and never prints prompt text. It exits 0
only when no errors are found; warnings identify migration work that does not
make the registry structurally invalid.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = PROJECT_ROOT / "configs" / "dataset_registry.json"
DEFAULT_DATA_DIR = PROJECT_ROOT / "data" / "processed"
MAX_CSV_FIELD_BYTES = 10 * 1024 * 1024

REQUIRED_REGISTRY_FIELDS = {
    "id", "uri", "role", "threat_coverage", "languages", "revision",
    "license_spdx", "review_state", "holdout", "notes",
}
KNOWN_LABELS = {
    "prompt_injection", "system_prompt_leakage", "malicious_code",
    "toxicity_harm", "adversarial_obfuscation", "benign",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    location: str
    message: str


def normalized_fingerprint(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip().casefold())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_registry(path: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [Finding("error", "registry_unreadable", str(path), str(exc))], {}

    datasets = registry.get("datasets")
    if not isinstance(datasets, list):
        return [Finding("error", "datasets_not_list", str(path), "datasets must be a list")], registry

    ids: Counter[str] = Counter()
    for index, dataset in enumerate(datasets):
        location = f"{path}:datasets[{index}]"
        if not isinstance(dataset, dict):
            findings.append(Finding("error", "dataset_not_object", location, "entry must be an object"))
            continue
        missing = sorted(REQUIRED_REGISTRY_FIELDS - dataset.keys())
        if missing:
            findings.append(Finding("error", "registry_fields_missing", location, ", ".join(missing)))
            continue
        ids[dataset["id"]] += 1
        if dataset["role"] not in registry.get("policy", {}).get("allowed_roles", []):
            findings.append(Finding("error", "invalid_role", location, str(dataset["role"])))
        unknown = set(dataset["threat_coverage"]) - KNOWN_LABELS
        if unknown:
            findings.append(Finding("error", "unknown_threat_labels", location, ", ".join(sorted(unknown))))
        if dataset["role"] == "evaluation_only" and not dataset["holdout"]:
            findings.append(Finding("error", "evaluation_not_holdout", location, "evaluation_only must set holdout=true"))
        if dataset["review_state"] == "approved":
            if not dataset["revision"]:
                findings.append(Finding("error", "approved_without_revision", location, "approved data needs an immutable revision"))
            if not dataset["license_spdx"]:
                findings.append(Finding("error", "approved_without_license", location, "approved data needs an SPDX license"))
        elif not dataset["revision"] or not dataset["license_spdx"]:
            findings.append(Finding("warning", "governance_pending", location, "revision/license review incomplete"))

    for dataset_id, count in ids.items():
        if count > 1:
            findings.append(Finding("error", "duplicate_dataset_id", str(path), f"{dataset_id}: {count}"))
    return findings, registry


def audit_csv_files(data_dir: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    summary: dict[str, Any] = {"files": {}, "cross_split_duplicate_groups": 0}
    fingerprints: dict[str, set[str]] = defaultdict(set)
    files = sorted(data_dir.glob("*.csv"))
    if not files:
        return [Finding("warning", "no_csv_files", str(data_dir), "no processed CSV files found")], summary

    csv.field_size_limit(MAX_CSV_FIELD_BYTES)
    for path in files:
        counts: Counter[str] = Counter()
        row_count = 0
        empty_count = 0
        malformed_labels = 0
        oversized_for_model = 0
        duplicate_count = 0
        seen: set[str] = set()
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            columns = reader.fieldnames or []
            missing = sorted({"text", "label"} - set(columns))
            if missing:
                findings.append(Finding("error", "csv_columns_missing", str(path), ", ".join(missing)))
                continue
            provenance_fields = {"source_id", "source_item_id", "source_revision", "language", "labels"}
            missing_provenance = sorted(provenance_fields - set(columns))
            if missing_provenance:
                findings.append(Finding("warning", "legacy_schema", str(path), "missing " + ", ".join(missing_provenance)))
            for row_number, row in enumerate(reader, start=2):
                row_count += 1
                text = (row.get("text") or "").strip()
                label = (row.get("label") or "").strip()
                if not text:
                    empty_count += 1
                    continue
                if len(text.encode("utf-8")) > 128 * 1024:
                    oversized_for_model += 1
                if label not in {"0", "1"}:
                    malformed_labels += 1
                else:
                    counts[label] += 1
                fingerprint = normalized_fingerprint(text)
                if fingerprint in seen:
                    duplicate_count += 1
                seen.add(fingerprint)
                fingerprints[fingerprint].add(path.stem)
        if empty_count:
            findings.append(Finding("error", "empty_text", str(path), str(empty_count)))
        if malformed_labels:
            findings.append(Finding("error", "invalid_binary_label", str(path), str(malformed_labels)))
        if duplicate_count:
            findings.append(Finding("warning", "within_split_duplicates", str(path), str(duplicate_count)))
        if oversized_for_model:
            findings.append(Finding("warning", "oversized_prompt", str(path), str(oversized_for_model)))
        summary["files"][path.name] = {
            "sha256": file_sha256(path),
            "rows": row_count,
            "binary_label_counts": dict(sorted(counts.items())),
            "empty_text_rows": empty_count,
            "invalid_binary_label_rows": malformed_labels,
            "normalized_duplicates": duplicate_count,
            "prompts_over_128kib": oversized_for_model,
        }

    cross_split = sum(1 for splits in fingerprints.values() if len(splits) > 1)
    summary["cross_split_duplicate_groups"] = cross_split
    if cross_split:
        findings.append(Finding("error", "cross_split_duplicates", str(data_dir), str(cross_split)))
    return findings, summary


def render_human(findings: Iterable[Finding], summary: dict[str, Any]) -> None:
    for finding in findings:
        print(f"{finding.severity.upper():7} {finding.code:30} {finding.location} — {finding.message}")
    print(json.dumps(summary, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    registry_findings, registry = audit_registry(args.registry)
    data_findings, data_summary = audit_csv_files(args.data_dir)
    findings = registry_findings + data_findings
    summary = {
        "registry_version": registry.get("registry_version"),
        "dataset_count": len(registry.get("datasets", [])),
        "data": data_summary,
        "finding_counts": dict(Counter(item.severity for item in findings)),
    }
    if args.json:
        print(json.dumps({"findings": [asdict(item) for item in findings], "summary": summary}, indent=2, sort_keys=True))
    else:
        render_human(findings, summary)
    return 1 if any(item.severity == "error" for item in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
