#!/usr/bin/env python3
"""Derive per-category serving thresholds, then verify them on the frozen holdout.

The gateway consumes a single `malicious_probability` and cuts it at 0.55
(escalate to the judge) and 0.90 (block). The service currently produces that by
taking a plain max over the five category scores, which forces every head to
share one operating point. v0.6 made that untenable in a measurable way: on the
holdout's benign controls `toxicity_harm` fires at 0.53 while every other head
is at or below 0.05, so the noisiest head alone sets the false-positive rate.

This derives a per-category (judge, block) pair and emits a piecewise-linear map
onto the gateway's fixed band, so each head reaches 0.90 at its own score while
the wire contract is unchanged.

**Thresholds are derived on the validation split, never on the holdout.** Tuning
on the holdout would rebuild precisely the circularity the holdout exists to
break -- the numbers would then describe a set the thresholds had already seen.
Validation is in-distribution, so transfer is not guaranteed; that is exactly
what the holdout verification pass measures and reports.

Usage:
  python -m scripts.derive_serving_thresholds \
     --model models/layer2-threat-distilbert/v06-candidate \
     --validation data/splits_v2_v06/validation.jsonl \
     --holdout data/holdout_v1/holdout_eval_clean.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_semantic_splits import load_jsonl, project_relative
from scripts.evaluate_layer2_v03 import CATEGORIES, calibrated_scores

GATEWAY_JUDGE = 0.55
GATEWAY_BLOCK = 0.90


def benign_mask(rows: list[dict]) -> np.ndarray:
    return np.array([not (set(r["labels"]) - {"benign"}) for r in rows])


# Floors applied on principle, not fitted. On in-distribution validation the
# sparse heads score benign rows so close to zero that any false-positive
# quantile lands near zero too, which would have the model *block* on scores its
# own calibration puts below 5%. A block is not defensible at that confidence
# whatever the quantile says, and a floor chosen a priori cannot be accused of
# being shopped against the holdout. Escalation is a judge call rather than a
# refusal, so its floor is looser.
MIN_BLOCK_THRESHOLD = 0.30
MIN_JUDGE_THRESHOLD = 0.10


def pick_threshold(scores: np.ndarray, negatives: np.ndarray, budget: float, floor: float) -> float:
    """Lowest threshold whose false-positive rate on benign rows is within budget.

    Lowest rather than any-qualifying: among thresholds that meet the
    false-positive budget, the smallest is the one that keeps the most recall.
    """
    negative_scores = scores[negatives]
    if not len(negative_scores):
        return max(0.5, floor)
    # The (1-budget) quantile of benign scores is the smallest cut meeting the budget.
    threshold = float(np.quantile(negative_scores, 1.0 - budget))
    return float(min(max(threshold, floor), 0.995))


def remap(score: float, judge: float, block: float) -> float:
    """Piecewise-linear map of a category score onto the gateway's fixed band."""
    if score <= 0:
        return 0.0
    if score < judge:
        return GATEWAY_JUDGE * (score / judge) if judge > 0 else 0.0
    if score < block:
        span = max(block - judge, 1e-9)
        return GATEWAY_JUDGE + (GATEWAY_BLOCK - GATEWAY_JUDGE) * ((score - judge) / span)
    span = max(1.0 - block, 1e-9)
    return min(1.0, GATEWAY_BLOCK + (1.0 - GATEWAY_BLOCK) * ((score - block) / span))


def aggregate(probs: np.ndarray, thresholds: dict[str, dict[str, float]]) -> np.ndarray:
    out = np.zeros(len(probs))
    for index, category in enumerate(CATEGORIES):
        t = thresholds[category]
        mapped = np.array([remap(float(s), t["judge"], t["block"]) for s in probs[:, index]])
        out = np.maximum(out, mapped)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=PROJECT_ROOT / "models" / "layer2-threat-distilbert" / "v06-candidate")
    parser.add_argument("--validation", type=Path, default=PROJECT_ROOT / "data" / "splits_v2_v06" / "validation.jsonl")
    parser.add_argument("--holdout", type=Path, default=PROJECT_ROOT / "data" / "holdout_v1" / "holdout_eval_clean.jsonl")
    parser.add_argument("--output", type=Path, default=None, help="thresholds.json (defaults to <model>/thresholds.json)")
    parser.add_argument("--report", type=Path, default=PROJECT_ROOT / "data" / "reports" / "serving_thresholds_v06.json")
    parser.add_argument("--block-budget", type=float, default=0.01,
                        help="per-category benign false-positive budget at the block point")
    parser.add_argument("--judge-budget", type=float, default=0.10,
                        help="per-category benign false-positive budget at the judge point; "
                             "escalation costs a judge call, not a block, so it is deliberately looser")
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()
    output = args.output or (args.model / "thresholds.json")

    validation = load_jsonl(args.validation)
    print(f"scoring {len(validation)} validation rows ...", flush=True)
    val_probs = calibrated_scores(args.model, [r["text"] for r in validation], args.batch_size)
    val_benign = benign_mask(validation)

    thresholds = {}
    for index, category in enumerate(CATEGORIES):
        scores = val_probs[:, index]
        block = pick_threshold(scores, val_benign, args.block_budget, MIN_BLOCK_THRESHOLD)
        judge = pick_threshold(scores, val_benign, args.judge_budget, MIN_JUDGE_THRESHOLD)
        judge = min(judge, block - 1e-3)
        thresholds[category] = {"judge": round(max(judge, 0.01), 4), "block": round(block, 4)}

    payload = {
        "categories": CATEGORIES,
        "thresholds": thresholds,
        "gateway_band": {"judge": GATEWAY_JUDGE, "block": GATEWAY_BLOCK},
        "method": "per_category_piecewise_linear_remap",
        "derived_on": project_relative(args.validation),
        "derived_on_note": "validation split only; the holdout is never used to fit thresholds",
        "block_budget": args.block_budget,
        "judge_budget": args.judge_budget,
        "min_block_threshold": MIN_BLOCK_THRESHOLD,
        "min_judge_threshold": MIN_JUDGE_THRESHOLD,
    }
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # Verification on the untouched holdout.
    holdout = load_jsonl(args.holdout)
    print(f"verifying on {len(holdout)} held-out rows ...", flush=True)
    hold_probs = calibrated_scores(args.model, [r["text"] for r in holdout], args.batch_size)
    hold_benign = benign_mask(holdout)

    plain = hold_probs.max(axis=1)
    tuned = aggregate(hold_probs, thresholds)

    def summarize(agg: np.ndarray) -> dict:
        summary = {
            "benign_fpr_at_judge": round(float((agg[hold_benign] >= GATEWAY_JUDGE).mean()), 4),
            "benign_fpr_at_block": round(float((agg[hold_benign] >= GATEWAY_BLOCK).mean()), 4),
        }
        for index, category in enumerate(CATEGORIES):
            positives = np.array([category in r["labels"] for r in holdout])
            if positives.sum():
                summary[f"{category}_escalated"] = round(float((agg[positives] >= GATEWAY_JUDGE).mean()), 4)
                summary[f"{category}_blocked"] = round(float((agg[positives] >= GATEWAY_BLOCK).mean()), 4)
        return summary

    report = {
        "report_version": "0.1.0",
        "model": project_relative(args.model),
        "thresholds": thresholds,
        "validation_rows": len(validation),
        "validation_benign_rows": int(val_benign.sum()),
        "holdout_rows": len(holdout),
        "holdout_benign_rows": int(hold_benign.sum()),
        "holdout_verification": {
            "plain_max_aggregate": summarize(plain),
            "per_category_thresholds": summarize(tuned),
        },
        "caveat": (
            "Thresholds are fitted on in-distribution validation data and verified once on the "
            "holdout. The holdout was not used to choose them. The benign control slice is 100 rows, "
            "so benign false-positive figures carry wide error bars."
        ),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
