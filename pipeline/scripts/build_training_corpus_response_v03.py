#!/usr/bin/env python3
"""Blend Track B's reviewed response-shaped rows into the Track A v0.3 corpus.

Per docs/RESPONSE_CURATION_SPEC.md's resolved decision #5 (blended, not a
separate model): merges onto eligible_reviewed_v03.jsonl (Track A's output)
rather than replacing it, so one training manifest/run covers both tracks --
while `train_layer2_multilabel_v03.py`'s metrics_at() still reports Track A's
prompt-shaped and Track B's response-shaped malicious_code performance as
distinct slices (source_id="echelon_response_v0_3"), not one merged number.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.normalize_datasets import base_record

ELIGIBLE = PROJECT_ROOT / "data" / "normalized_v2" / "eligible_reviewed_v03.jsonl"
ACCEPTED = PROJECT_ROOT / "data" / "review_v2" / "response_v0_3_accepted.jsonl"
OUTPUT = PROJECT_ROOT / "data" / "normalized_v2" / "eligible_reviewed_v03_full.jsonl"
SOURCE_ID = "echelon_response_v0_3"
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
            notes=f"review={row['review_status']};provenance=ai_assisted_dual_review_response_v03;text_type=response",
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
        "response_rows_added": len(reviewed),
        "total_rows": len(merged),
        "output": str(OUTPUT.relative_to(PROJECT_ROOT)),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
