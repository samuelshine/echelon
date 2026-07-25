#!/usr/bin/env python3
"""Merge human/AI-reviewed accepted v0.2 rows into the eligible source corpus.

Produces a single normalized JSONL ready for semantic splitting. Every row is
tagged ``training_eligible: true`` (required by echelon.training_data). The v0.2
rows use their final adjudicated labels (see scripts/ai_adjudicate_v02.py) and
carry template/transformation lineage so leakage-safe grouping keeps siblings and
transformation families in one split.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.generate_targeted_v02 import generate
from scripts.normalize_datasets import base_record

ELIGIBLE = PROJECT_ROOT / "data" / "normalized_v2" / "eligible.jsonl"
ACCEPTED = PROJECT_ROOT / "data" / "review_v2" / "targeted_v0_2_accepted.jsonl"
OUTPUT = PROJECT_ROOT / "data" / "normalized_v2" / "eligible_reviewed.jsonl"
SOURCE_ID = "echelon_targeted_v0_2"
REVISION = "0.2.0"


def main() -> int:
    source = [json.loads(line) for line in ELIGIBLE.read_text().split("\n") if line]
    accepted = {json.loads(line)["candidate_id"]: json.loads(line)
                for line in ACCEPTED.read_text().split("\n") if line}
    candidates = {row["candidate_id"]: row for row in generate()}

    reviewed = []
    for cid, acc in accepted.items():
        cand = candidates[cid]
        malicious = acc["decision"] == "malicious"
        record = base_record(
            source_id=SOURCE_ID, revision=REVISION, split="train",
            source_item_id=cid, text=acc["text"], labels=sorted(acc["labels"]),
            severity="high" if malicious else "none",
            license_spdx="LicenseRef-Echelon-Synthetic-v0.2",
            template_family=cand["template_lineage"],
            transformation_parent_id=cand.get("parent_id"),
            transformations=[cand["transformation"]] if cand.get("transformation") else [],
            context=cand.get("context", "unknown"),
            notes=f"review={acc['resolution']};provenance={acc['review_provenance']}",
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
