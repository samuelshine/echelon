#!/usr/bin/env python3
"""Orchestrate the v0.3 AI-assisted dual review + expert adjudication.

Uses the SAME reviewer.store / reviewer.distributed library functions the
real human distributed-review workflow uses (docs/DISTRIBUTED_REVIEW.md) --
this produces byte-for-byte schema-identical kits/submissions, just driven
by scripts/ai_reviewers_v03.py's policies instead of a human via the Flask
review app. See that module's docstring for what "AI-assisted" means here
and its documented limitations.
"""

from __future__ import annotations

import json
from pathlib import Path

from reviewer.distributed import (
    build_expert_kit, build_primary_kit, build_public_manifest, export_submission,
    load_json, write_json,
)
from reviewer.store import connect, import_reviews, initialize_database, read_jsonl
from scripts.ai_reviewers_v03 import expert_adjudicate, reviewer_a_assess, reviewer_b_assess
from scripts.validate_adjudications import VALID_LABELS

PROJECT_ROOT = Path(__file__).resolve().parents[1]
QUEUE = PROJECT_ROOT / "data" / "review_v2" / "targeted_v0_3_review.jsonl"
WORK_ROOT = PROJECT_ROOT / "data" / "review_v2" / "ai_review_v03"
SUBMISSIONS = PROJECT_ROOT / "review_submissions" / "v0.3"
PUBLIC_MANIFEST = PROJECT_ROOT / "data" / "manifests" / "targeted_v03_distributed_review_manifest.json"

REVIEWER_A = "ai_reviewer_a"
REVIEWER_B = "ai_reviewer_b"
EXPERT = "ai_claude_expert"


def _review_record(item_id: str, reviewer_id: str, assessment: dict, *, is_expert: bool) -> dict:
    labels = assessment["labels"]
    assert set(labels) <= VALID_LABELS, f"{item_id}: invalid labels {labels}"
    return {
        "item_id": item_id, "reviewer_id": reviewer_id,
        "decision": assessment["decision"], "labels": labels,
        "rationale_code": assessment["rationale_code"],
        "naturalness": assessment["naturalness"],
        "intent_correct": assessment["intent_correct"],
        "labels_correct": assessment["labels_correct"],
        "non_operational": assessment["non_operational"],
        "is_expert_adjudication": is_expert,
    }


def run_primary(reviewer_id: str, assess_fn, manifest: dict) -> dict:
    kit_dir = WORK_ROOT / reviewer_id
    kit = build_primary_kit(QUEUE, manifest, reviewer_id, kit_dir)
    blinded_rows = read_jsonl(kit_dir / "review_queue.jsonl")
    db_path = WORK_ROOT / f"{reviewer_id}.sqlite3"
    db_path.unlink(missing_ok=True)
    initialize_database(db_path, kit_dir / "review_queue.jsonl")
    reviews = []
    for row in blinded_rows:
        item_id = row.get("candidate_id") or row["item_id"]
        assessment = assess_fn(row)
        reviews.append(_review_record(item_id, reviewer_id, assessment, is_expert=False))
    import_reviews(db_path, reviews)
    submission = export_submission(db_path, kit)
    out_path = SUBMISSIONS / f"{reviewer_id}.json"
    write_json(out_path, submission)
    return submission


def run_expert(manifest: dict, first: dict, second: dict) -> dict:
    kit_dir = WORK_ROOT / EXPERT
    kit = build_expert_kit(QUEUE, manifest, first, second, EXPERT, kit_dir)
    blinded_rows = read_jsonl(kit_dir / "expert_queue.jsonl")
    # Expert also sees both primary (still-blinded) reviews for context, matching
    # the real reviewer.app expert flow -- but our adjudication policy only needs
    # the two primary decisions, already available from `first`/`second` in memory.
    first_by_id = {r["item_id"]: r for r in first["reviews"]}
    second_by_id = {r["item_id"]: r for r in second["reviews"]}
    db_path = WORK_ROOT / f"{EXPERT}.sqlite3"
    db_path.unlink(missing_ok=True)
    initialize_database(db_path, kit_dir / "expert_queue.jsonl")
    # The expert db must also hold both primary reviewers' verdicts for these
    # conflict items -- _save_review's expert-eligibility check reads them from
    # the SAME db, not from the in-memory submissions. build_expert_kit already
    # wrote them to primary_reviews.jsonl for exactly this purpose.
    import_reviews(db_path, read_jsonl(kit_dir / "primary_reviews.jsonl"))
    reviews = []
    for row in blinded_rows:
        item_id = row.get("candidate_id") or row["item_id"]
        assessment = expert_adjudicate(row, first_by_id[item_id], second_by_id[item_id])
        reviews.append(_review_record(item_id, EXPERT, assessment, is_expert=True))
    import_reviews(db_path, reviews)
    submission = export_submission(db_path, kit)
    out_path = SUBMISSIONS / f"{EXPERT}.json"
    write_json(out_path, submission)
    return submission


def main() -> int:
    SUBMISSIONS.mkdir(parents=True, exist_ok=True)
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    manifest = build_public_manifest(QUEUE, "targeted_v0_3_review")
    write_json(PUBLIC_MANIFEST, manifest)

    submission_a = run_primary(REVIEWER_A, reviewer_a_assess, manifest)
    submission_b = run_primary(REVIEWER_B, reviewer_b_assess, manifest)

    a_by_id = {r["item_id"]: (r["decision"], tuple(sorted(r["labels"]))) for r in submission_a["reviews"]}
    b_by_id = {r["item_id"]: (r["decision"], tuple(sorted(r["labels"]))) for r in submission_b["reviews"]}
    conflicts = sorted(i for i in a_by_id if a_by_id[i] != b_by_id[i])
    agreement_rate = 1 - len(conflicts) / len(a_by_id)

    expert_submission = None
    if conflicts:
        expert_submission = run_expert(manifest, submission_a, submission_b)

    summary = {
        "queue_items": len(a_by_id),
        "agreements": len(a_by_id) - len(conflicts),
        "conflicts": len(conflicts),
        "agreement_rate": round(agreement_rate, 4),
        "expert_adjudicated": len(expert_submission["reviews"]) if expert_submission else 0,
        "reviewer_a_malicious": sum(1 for v in a_by_id.values() if v[0] == "malicious"),
        "reviewer_b_malicious": sum(1 for v in b_by_id.values() if v[0] == "malicious"),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
