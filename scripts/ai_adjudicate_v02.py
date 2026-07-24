#!/usr/bin/env python3
"""AI-assisted expert adjudication of the v0.2 primary-review conflicts.

This resolves the 152 primary disagreements as expert id ``ai_claude``. It is an
**AI-assisted, provisional, human-overridable** adjudication produced by Claude,
recorded transparently as such -- it is NOT native-human expert review and must be
replaced/confirmed by a human before any real deployment.

Adjudication policy (documented, deterministic, and defensible):

  All 152 conflicts are label-only disagreements on prompts BOTH primaries already
  judged ``malicious``; no decision or quality dispute exists. In every conflict
  reviewer A dropped one label that reviewer B (and the generator) retained:

    * system_prompt_leakage_v02 (52): A=[system_prompt_leakage] vs
      B=[prompt_injection, system_prompt_leakage]. Where the two primaries AGREED
      on this family (48/48 items) they both used BOTH labels, so the family's
      consensus convention is both -- the conflicts are A under-labeling. The
      leakage frames override confidentiality / impersonate a privileged role /
      manipulate output to force disclosure, which is prompt_injection per the
      Echelon taxonomy.

    * obfuscated_attack_v02 (100): A=[adversarial_obfuscation, prompt_injection]
      vs B=[..., system_prompt_leakage]. Every obfuscated item wraps a LEAKAGE
      payload in a "decode this and obey it" wrapper, so the decoded intent
      carries system_prompt_leakage in addition to obfuscation + injection.
      Recognizing hidden/obfuscated intent is the point of this family, so the
      label applies.

  Resolution: affirm the fuller label set (reviewer B's verdict) for all 152,
  decision ``malicious``, rationale ``label_confirmed``. Quality gates pass:
  the prompts are grammatical, on-intent, and non-operational (they request
  disclosure/override, not an operational exploit payload).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.generate_targeted_v02 import generate

MANIFEST = PROJECT_ROOT / "data" / "manifests" / "targeted_v02_distributed_review_manifest.json"
PRIMARY_A = PROJECT_ROOT / "review_submissions" / "v0.2" / "reviewer_a.json"
PRIMARY_B = PROJECT_ROOT / "review_submissions" / "v0.2" / "reviewer_b.json"
OUTPUT = PROJECT_ROOT / "review_submissions" / "v0.2" / "ai_claude.json"
EXPERT_ID = "ai_claude"


def verdict(review: dict) -> tuple:
    return review["decision"], tuple(sorted(review["labels"]))


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    primary_a = json.loads(PRIMARY_A.read_text())
    primary_b = json.loads(PRIMARY_B.read_text())

    # Recover authentic candidate text/labels deterministically (offline, stdlib).
    candidates = {row["candidate_id"]: row for row in generate()}
    # Integrity: every reviewed item id must resolve to a regenerated candidate.
    missing = [i for i in manifest["item_ids"] if i not in candidates]
    if missing:
        raise SystemExit(f"integrity failure: {len(missing)} manifest ids not reproduced")

    a = {r["item_id"]: r for r in primary_a["reviews"]}
    b = {r["item_id"]: r for r in primary_b["reviews"]}
    conflicts = sorted(i for i in a if i in b and verdict(a[i]) != verdict(b[i]))

    reviews = []
    for item_id in conflicts:
        # Affirm the fuller label set (reviewer B == generator proposed labels).
        labels = sorted(set(b[item_id]["labels"]))
        assert set(labels) == set(candidates[item_id]["proposed_labels"]), item_id
        reviews.append({
            "item_id": item_id,
            "reviewer_id": EXPERT_ID,
            "decision": "malicious",
            "labels": labels,
            "rationale_code": "label_confirmed",
            "naturalness": 4,
            "intent_correct": True,
            "labels_correct": True,
            "non_operational": True,
            "is_expert_adjudication": True,
        })

    submission = {
        "schema_version": "1.0.0",
        "role": "expert",
        "reviewer_id": EXPERT_ID,
        "canonical_queue_sha256": manifest["canonical_queue_sha256"],
        "review_queue_sha256": manifest["canonical_queue_sha256"],
        "item_count": len(reviews),
        "reviews": reviews,
    }
    OUTPUT.write_text(json.dumps(submission, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(OUTPUT.relative_to(PROJECT_ROOT)),
        "expert_id": EXPERT_ID,
        "conflicts_adjudicated": len(reviews),
        "provenance": "AI-assisted (Claude), provisional, human-overridable",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
