#!/usr/bin/env python3
"""Normalize real-source malicious-code prompts into training-eligible records.

The v0.3 corpus contains 852 synthetic `malicious_code` rows and zero real ones.
The held-out benchmark showed what that costs: recall 0.209 even on real prompts
matched to the synthetic rows' length and register. This ingests the first real
`malicious_code` training data the corpus has ever had.

Two constraints shape it, both enforced here rather than left to reviewer care:

1. **The registry's `ingestion_filter` is mandatory.** RedTeam_2K is an
   aggregate; its own `from` column attributes 558/2000 rows to BeaverTails,
   which this registry rejected as CC-BY-NC, and 67 to AdvBench, which overlaps
   the frozen holdout. Taking the file wholesale would launder an excluded
   license and contaminate the evaluation set. Rows are kept only if the
   publisher's own provenance field is on the registry's allow-list.
2. **Publisher category fields decide labels**, as in the holdout normalizer --
   CatQA's `Category`, RedTeam_2K's `policy`. No text-derived labelling.

Harmful non-code rows are kept as `toxicity_harm` rather than dropped: they come
from the same distribution as the malicious-code rows, so they teach the model
that "harmful" and "malicious code" are different axes. Dropping them would
leave topic as a shortcut for the malicious_code head.

Output is training-eligible but NOT yet merged or split. It must pass
`scan_holdout_contamination.py` against the holdout set first.

Usage:
  python -m scripts.normalize_real_code_sources \
     --manifest data/manifests/acquisition_manifest_realcode.json \
     --output data/normalized_v2/real_code_sources.jsonl
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_semantic_splits import project_relative

DEFAULT_REGISTRY = PROJECT_ROOT / "configs" / "dataset_registry.json"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "manifests" / "acquisition_manifest_realcode.json"
DEFAULT_RAW_ROOT = PROJECT_ROOT / "data" / "raw_v2"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "normalized_v2" / "real_code_sources.jsonl"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "reports" / "real_code_sources_normalization.json"

# Publisher category -> our taxonomy. Only the explicitly malware/virus
# categories become malicious_code; the rest are harmful-request prompts.
CATQA_MALICIOUS_CODE = {"Malware Viruses"}
REDTEAM_MALICIOUS_CODE = {"Malware"}


# Real, independently-authored rows have NO template lineage, so template_family
# must stay None. build_semantic_splits treats a shared (source_id,
# template_family) as a declared group that may not cross splits -- correct for
# generated rows sharing a frame, badly wrong here: setting it to a publisher
# CATEGORY name fuses every row of that category into one block that lands
# wholly in a single split. In v0.6 that put all 1,600 wildguard benign controls
# in test and zero in train, so the matched controls the round existed to add
# never reached the model. The publisher category is already preserved in
# annotation_notes, which is where it belongs: metadata, not lineage.


class NormalizationError(RuntimeError):
    pass


def record_id(source_id: str, item_id: str, text: str) -> str:
    return hashlib.sha256("\x1f".join((source_id, item_id, text)).encode("utf-8")).hexdigest()


def make_record(
    *, source_id: str, revision: str, item_id: str, text: str, labels: list[str],
    license_spdx: str, notes: str, template_family: str | None,
) -> dict[str, Any]:
    text = text.strip()
    if not text:
        raise NormalizationError(f"{source_id}:{item_id} has empty text")
    return {
        "record_id": record_id(source_id, item_id, text),
        "text": text,
        "source_id": source_id,
        "source_item_id": item_id,
        "source_revision": revision,
        "split": "train",
        "language": "en",
        "labels": sorted(set(labels)),
        "severity": "high",
        "annotation_confidence": 1.0,
        "template_family": template_family,
        "semantic_cluster_id": None,
        "conversation_id": None,
        "transformation_parent_id": None,
        "transformations": [],
        "context": "malicious",
        "license_spdx": license_spdx,
        "annotation_notes": notes,
        "training_eligible": True,
    }


def normalize_catqa(root: Path, revision: str, license_spdx: str, source: dict, counters: Counter) -> Iterator[dict]:
    path = root / "data" / "catqa_english.json"
    # Published as JSON Lines despite the .json extension.
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]
    for index, row in enumerate(rows):
        category = row["Category"]
        labels = ["malicious_code"] if category in CATQA_MALICIOUS_CODE else ["toxicity_harm"]
        counters[f"catqa_english:{labels[0]}"] += 1
        yield make_record(
            source_id="catqa_english", revision=revision, item_id=f"row-{index}",
            text=row["Question"], labels=labels, license_spdx=license_spdx,
            notes=f"publisher_category={category};publisher_subcategory={row.get('Subcategory')}",
            template_family=None,
        )


def normalize_redteam_2k(root: Path, revision: str, license_spdx: str, source: dict, counters: Counter) -> Iterator[dict]:
    ingestion_filter = source.get("ingestion_filter")
    if not ingestion_filter:
        raise NormalizationError(
            "jailbreakv_redteam_2k requires an ingestion_filter in the registry; refusing to ingest "
            "an aggregate whose upstream provenance has not been constrained"
        )
    field, allowed = ingestion_filter["field"], set(ingestion_filter["allow"])
    path = root / "JailBreakV_28K" / "RedTeam_2K.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            provenance = row.get(field)
            if provenance not in allowed:
                counters[f"jailbreakv_redteam_2k:filtered_out:{provenance}"] += 1
                continue
            policy = row["policy"]
            labels = ["malicious_code"] if policy in REDTEAM_MALICIOUS_CODE else ["toxicity_harm"]
            counters[f"jailbreakv_redteam_2k:{labels[0]}"] += 1
            yield make_record(
                source_id="jailbreakv_redteam_2k", revision=revision, item_id=f"row-{row['id']}",
                text=row["question"], labels=labels, license_spdx=license_spdx,
                notes=f"publisher_category={policy};publisher_provenance={provenance}",
                template_family=None,
            )


NORMALIZERS = {
    "catqa_english": normalize_catqa,
    "jailbreakv_redteam_2k": normalize_redteam_2k,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    registry = {item["id"]: item for item in json.loads(args.registry.read_text(encoding="utf-8"))["datasets"]}
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    counters: Counter = Counter()
    records: list[dict[str, Any]] = []
    for acquired in manifest["sources"]:
        normalizer = NORMALIZERS.get(acquired["id"])
        if normalizer is None:
            raise NormalizationError(f"no normalizer for acquired source: {acquired['id']}")
        root = args.raw_root / acquired["id"] / acquired["revision"]
        records.extend(normalizer(
            root, acquired["revision"], acquired["license_spdx"],
            registry[acquired["id"]], counters,
        ))

    seen: dict[str, dict] = {}
    duplicates = 0
    for record in records:
        if record["record_id"] in seen:
            duplicates += 1
            continue
        seen[record["record_id"]] = record
    records = sorted(seen.values(), key=lambda row: row["record_id"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    report = {
        "report_version": "0.1.0",
        "acquisition_manifest": project_relative(args.manifest),
        "output": project_relative(args.output),
        "rows": len(records),
        "exact_duplicate_rows_collapsed": duplicates,
        "rows_by_source": dict(sorted(Counter(r["source_id"] for r in records).items())),
        "label_occurrences": dict(sorted(Counter(l for r in records for l in r["labels"]).items())),
        "counters": dict(sorted(counters.items())),
        "labelling_policy": "publisher-declared category fields only; no text-derived labels",
        "status": "normalized_pending_contamination_scan",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
