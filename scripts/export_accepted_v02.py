#!/usr/bin/env python3
"""Export the accepted v0.2 rows (with recovered text + final labels) for training.

Resolves each reviewed item with the same logic the reviewer store uses
(``resolve_reviews``): primary agreement -> primary verdict; primary disagreement
-> expert verdict. Emits only accepted items (``accepted_by_agreement`` or
``accepted_by_expert``) joined with authentic candidate text recovered
deterministically from the generator.

Output contains prompt text and therefore lands under the git-ignored
``data/review_v2/`` tree. Expert decisions are AI-assisted/provisional
(see scripts/ai_adjudicate_v02.py).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from reviewer.store import resolve_reviews
from scripts.generate_targeted_v02 import generate

MANIFEST = PROJECT_ROOT / "data" / "manifests" / "targeted_v02_distributed_review_manifest.json"
SUBMISSIONS = PROJECT_ROOT / "review_submissions" / "v0.2"
OUTPUT = PROJECT_ROOT / "data" / "review_v2" / "targeted_v0_2_accepted.jsonl"
REPORT = PROJECT_ROOT / "data" / "reports" / "targeted_v02_human_review_report.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    subs = {
        name: json.loads((SUBMISSIONS / f"{name}.json").read_text())
        for name in ("reviewer_a", "reviewer_b", "ai_claude")
    }
    by_item = {name: {r["item_id"]: r for r in s["reviews"]} for name, s in subs.items()}
    candidates = {row["candidate_id"]: row for row in generate()}

    accepted = []
    status_counts: dict[str, int] = {}
    for item_id in manifest["item_ids"]:
        reviews = [by_item["reviewer_a"][item_id], by_item["reviewer_b"][item_id]]
        if item_id in by_item["ai_claude"]:
            reviews.append(by_item["ai_claude"][item_id])
        status, final = resolve_reviews(reviews)
        status_counts[status] = status_counts.get(status, 0) + 1
        if not status.startswith("accepted_") or final is None:
            continue
        cand = candidates[item_id]
        accepted.append({
            "candidate_id": item_id,
            "text": cand["text"],
            "decision": final["decision"],
            "labels": sorted(final["labels"]),
            "family": cand["family"],
            "transformation": cand.get("transformation"),
            "template_lineage": cand["template_lineage"],
            "language": cand["language"],
            "resolution": status,
            "review_provenance": "expert:ai_claude(provisional)" if status == "accepted_by_expert" else "primary_agreement",
        })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as handle:
        for row in sorted(accepted, key=lambda r: r["candidate_id"]):
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    report = {
        "report_version": "0.2.0",
        "reviewed_items": len(manifest["item_ids"]),
        "status_counts": dict(sorted(status_counts.items())),
        "accepted_total": len(accepted),
        "accepted_by_family": _count(accepted, "family"),
        "accepted_by_decision": _count(accepted, "decision"),
        "expert_provenance": "AI-assisted (Claude), provisional, human-overridable",
        "training_eligible": True,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _count(rows: list[dict], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        out[str(row[key])] = out.get(str(row[key]), 0) + 1
    return dict(sorted(out.items()))


if __name__ == "__main__":
    raise SystemExit(main())
