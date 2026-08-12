#!/usr/bin/env python3
"""Merge AI-reviewed accepted v0.3 rows into the eligible_reviewed (v0.2) corpus.

Builds on eligible_reviewed.jsonl (the v0.2 output: eligible.jsonl + v0.2's 598
reviewed rows, 33,063 total) rather than eligible.jsonl directly, so this round
is additive on top of the prior round rather than re-deriving it. See
scripts/build_training_corpus.py (v0.2) for the pattern this mirrors.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.normalize_datasets import base_record

ELIGIBLE = PROJECT_ROOT / "data" / "normalized_v2" / "eligible_reviewed.jsonl"
ACCEPTED = PROJECT_ROOT / "data" / "review_v2" / "targeted_v0_3_accepted.jsonl"
OUTPUT = PROJECT_ROOT / "data" / "normalized_v2" / "eligible_reviewed_v03.jsonl"
SOURCE_ID = "echelon_targeted_v0_3"
REVISION = "0.3.0"


def main() -> int:
    source = [json.loads(line) for line in ELIGIBLE.read_text().split("\n") if line]
    accepted = [json.loads(line) for line in ACCEPTED.read_text().split("\n") if line]

    reviewed = []
    for row in accepted:
        malicious = "benign" not in row["labels"]
        record = base_record(
            source_id=SOURCE_ID, revision=REVISION, split="train",
            source_item_id=row["candidate_id"], text=row["text"], labels=sorted(row["labels"]),
            severity="high" if malicious else "none",
            license_spdx="LicenseRef-Echelon-Synthetic-v0.3",
            template_family=row["template_lineage"],
            transformation_parent_id=row.get("parent_id"),
            transformations=[row["transformation"]] if row.get("transformation") else [],
            context=row.get("context", "unknown"),
            notes=f"review={row['review_status']};provenance=ai_assisted_dual_review_v03",
        )
        reviewed.append(record)

    merged = []
    for row in source:
        row = dict(row)
        row["training_eligible"] = True
        merged.append(row)
    for row in reviewed:
        row["training_eligible"] = True
        merged.append(row)

    OUTPUT.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in merged),
        encoding="utf-8",
    )
    print(json.dumps({
        "source_rows": len(source),
        "reviewed_rows_added": len(reviewed),
        "total_rows": len(merged),
        "output": str(OUTPUT.relative_to(PROJECT_ROOT)),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
