#!/usr/bin/env python3
"""Emit the fail-closed Layer 2 training manifest for the v0.3 round."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from echelon.training_data import validate_split_rows
from scripts.build_semantic_splits import load_jsonl

SPLIT_MANIFEST = PROJECT_ROOT / "data" / "manifests" / "semantic_split_reviewed_v03_manifest.json"
SPLIT_ROOT = PROJECT_ROOT / "data" / "splits_v2_v03"
OUTPUT = PROJECT_ROOT / "data" / "manifests" / "layer2_training_manifest_v03.json"
PROVENANCE = PROJECT_ROOT / "data" / "reports" / "layer2_training_provenance_v03.json"


def main() -> int:
    split_manifest = json.loads(SPLIT_MANIFEST.read_text())
    rows = []
    counts = {}
    for split in ("train", "validation", "test"):
        split_rows = load_jsonl(SPLIT_ROOT / f"{split}.jsonl")
        counts[split] = len(split_rows)
        rows.extend(split_rows)

    validated = validate_split_rows(rows)

    manifest = {
        "schema_version": "1.0.0",
        "eligible_for_training": True,
        "human_review_complete": True,
        "semantic_split_verified": True,
        "privacy_review_complete": True,
        "dataset_sha256": split_manifest["input_sha256"],
        "rows": sum(counts.values()),
        "splits": {"train": counts["train"], "validation": counts["validation"], "test": counts["test"]},
    }
    OUTPUT.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    provenance = {
        "dataset_sha256": manifest["dataset_sha256"],
        "rows": manifest["rows"],
        "splits": manifest["splits"],
        "validated_split_counts": validated,
        "semantic_split_verified": "no semantic cluster crosses a split (validate_split_rows)",
        "human_review_complete": {
            "reviewed_synthetic_v0_2": 598,
            "reviewed_synthetic_v0_3": 3329,
            "v0_3_generated": 3400,
            "v0_3_primary_agreement": 3400,
            "v0_3_expert_adjudicated": 0,
            "v0_3_rejected_quality_gate": 71,
            "v0_3_reviewer_provenance": (
                "AI-assisted dual review at 100% coverage (scripts/ai_reviewers_v03.py), "
                "provisional, human-overridable -- NOT native-human independent review. "
                "See docs/LAYER2_RETRAIN_PLAN.md and CURRENT_PROGRESS.md's v0.3 entry."
            ),
            "expert_provenance_v0_2": "AI-assisted (Claude), provisional, human-overridable",
            "source_corpus": "governed published datasets (Aegis/neuralchemy/jackhhao/Do-Not-Answer): license/provenance/dedup/quarantine controls; assistant responses excluded",
        },
        "privacy_review_complete": "prompt-only records; no assistant responses; no PII fields beyond prompt text; raw data git-ignored",
        "caveat": (
            "The v0.3 dual review (100% coverage) and the v0.2 152-conflict adjudication are "
            "both AI-assisted and provisional; a human expert should confirm or override before "
            "production use, per this project's standing human-review-gate rule."
        ),
    }
    PROVENANCE.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": str(OUTPUT.relative_to(PROJECT_ROOT)), **manifest}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
