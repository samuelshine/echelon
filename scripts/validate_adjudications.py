#!/usr/bin/env python3
"""Validate dual-review adjudication decisions without printing prompt text."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

VALID_DECISIONS = {"benign", "malicious", "exclude"}
VALID_LABELS = {
    "prompt_injection", "system_prompt_leakage", "malicious_code",
    "toxicity_harm", "adversarial_obfuscation", "benign",
}


def validate_review(review: dict[str, Any], line_number: int) -> list[str]:
    errors = []
    for field in ("item_id", "reviewer_id", "decision", "labels", "rationale_code"):
        if not review.get(field):
            errors.append(f"line {line_number}: missing {field}")
    if review.get("decision") not in VALID_DECISIONS:
        errors.append(f"line {line_number}: invalid decision")
    labels = set(review.get("labels") or [])
    if labels - VALID_LABELS:
        errors.append(f"line {line_number}: invalid labels")
    if review.get("decision") == "benign" and labels != {"benign"}:
        errors.append(f"line {line_number}: benign decision requires only benign label")
    if review.get("decision") == "malicious" and (not labels or "benign" in labels):
        errors.append(f"line {line_number}: malicious decision requires non-benign labels")
    if review.get("decision") == "exclude" and labels:
        errors.append(f"line {line_number}: exclude decision must have no labels")
    return errors


def summarize(reviews: list[dict[str, Any]]) -> dict[str, Any]:
    by_item: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for review in reviews:
        by_item[review["item_id"]].append(review)
    status = Counter()
    for item_reviews in by_item.values():
        reviewers = {review["reviewer_id"] for review in item_reviews}
        verdicts = {(review["decision"], tuple(sorted(review["labels"]))) for review in item_reviews}
        if len(reviewers) < 2:
            status["pending_second_review"] += 1
        elif len(verdicts) == 1:
            status["resolved_by_agreement"] += 1
        elif any(review.get("is_expert_adjudication") for review in item_reviews):
            status["resolved_by_expert"] += 1
        else:
            status["needs_expert_adjudication"] += 1
    return {"items": len(by_item), "status": dict(sorted(status.items()))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    reviews, errors = [], []
    for number, line in enumerate(args.decisions.read_text(encoding="utf-8").split("\n"), start=1):
        if not line:
            continue
        try:
            review = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {number}: invalid JSON: {exc.msg}")
            continue
        errors.extend(validate_review(review, number))
        reviews.append(review)
    report = {"valid": not errors, "errors": errors, **summarize(reviews)}
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
