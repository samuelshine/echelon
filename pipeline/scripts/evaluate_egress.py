#!/usr/bin/env python3
"""Evaluate the egress (response-side) path end to end on real assistant output.

The egress path has never been measured. It runs the prompt-trained Layer 2
model over response text, floors `malicious_code` on code-shaped output
(`_apply_code_shape_floor`), then aggregates over the two response-relevant
categories. Every part of that was justified by reasoning and a handful of
hand-checked samples, never by a number.

It scores every row twice and reports both, because the question is which
configuration to deploy:

  today_sparse_cap_plus_floor      the deployed path: malicious_code capped at
                                   0.88 (so no response can ever hard-block) plus
                                   the code-shape floor
  per_category_egress_thresholds   fitted operating points, under which the floor
                                   retires itself

Verdicts are pass / judge / block -- the decision the gateway actually makes --
rather than F1, because that decision is what users experience. The benign slice
matters most: an egress false positive blocks or delays a response the user has
already waited for, so it is more visible than the ingress equivalent.

Slices separate code-shaped from prose-shaped malicious output, since the
code-shape floor only ever acted on the former and the two behave differently.

Usage:
  python -m scripts.evaluate_egress --split data/holdout_v1/response_holdout.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_semantic_splits import load_jsonl, project_relative
from scripts.evaluate_layer2_v03 import CATEGORIES, calibrated_scores

JUDGE = 0.55
BLOCK = 0.90


def verdict_counts(aggregate: np.ndarray) -> dict[str, float]:
    return {
        "pass": round(float((aggregate < JUDGE).mean()), 4),
        "judge": round(float(((aggregate >= JUDGE) & (aggregate < BLOCK)).mean()), 4),
        "block": round(float((aggregate >= BLOCK).mean()), 4),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=PROJECT_ROOT / "models" / "layer2-threat-distilbert" / "best")
    parser.add_argument("--split", type=Path, default=PROJECT_ROOT / "data" / "holdout_v1" / "response_holdout.jsonl")
    parser.add_argument("--report", type=Path, default=PROJECT_ROOT / "data" / "reports" / "egress_eval_holdout.json")
    parser.add_argument("--batch-size", type=int, default=16)
    args = parser.parse_args()

    import service.security_api as api

    rows = load_jsonl(args.split)
    print(f"scoring {len(rows)} response rows through {args.model} ...", flush=True)
    probs = calibrated_scores(args.model, [r["text"] for r in rows], args.batch_size)
    column = {c: i for i, c in enumerate(CATEGORIES)}

    def run(egress_thresholds: dict) -> tuple[np.ndarray, np.ndarray]:
        """Aggregate every row exactly as the service would under this config."""
        api._EGRESS_THRESHOLDS = egress_thresholds
        aggregates, fired = [], []
        for index, row in enumerate(rows):
            scores = {c: float(probs[index, column[c]]) for c in CATEGORIES}
            floored = api._apply_code_shape_floor(row["text"], scores)
            fired.append(floored is not scores)
            aggregates.append(api._aggregate_response(floored))
        return np.array(aggregates), np.array(fired)

    configured = api._load_thresholds(args.model, "egress_thresholds")
    # "today" is the deployed path: sparse cap plus the code-shape floor.
    today_aggregate, floor_fired = run({})
    # "per-category" is the same rows under the fitted egress operating points,
    # where the floor retires itself.
    tuned_aggregate, _ = run(configured)
    raw_aggregate, floored_aggregate = today_aggregate, tuned_aggregate

    def slice_report(mask: np.ndarray) -> dict:
        if not mask.sum():
            return {"rows": 0}
        out = {
            "rows": int(mask.sum()),
            "code_shape_floor_fired_today": round(float(floor_fired[mask].mean()), 4),
            "today_sparse_cap_plus_floor": verdict_counts(raw_aggregate[mask]),
            "per_category_egress_thresholds": verdict_counts(floored_aggregate[mask]),
        }
        for category in ("malicious_code", "toxicity_harm"):
            out[f"mean_{category}"] = round(float(probs[mask, column[category]].mean()), 4)
        return out

    labels = [set(r["labels"]) for r in rows]
    code_shaped = np.array(["looks_like_code=True" in (r.get("annotation_notes") or "") for r in rows])
    slices = {
        "all": np.ones(len(rows), dtype=bool),
        "benign_responses": np.array([l == {"benign"} for l in labels]),
        "malicious_code_responses": np.array(["malicious_code" in l for l in labels]),
        "malicious_code_responses_code_shaped": np.array(
            ["malicious_code" in l for l in labels]) & code_shaped,
        "malicious_code_responses_prose_shaped": np.array(
            ["malicious_code" in l for l in labels]) & ~code_shaped,
        "toxicity_harm_responses": np.array(["toxicity_harm" in l for l in labels]),
        "benign_responses_code_shaped": np.array([l == {"benign"} for l in labels]) & code_shaped,
    }

    report = {
        "report_version": "0.1.0",
        "model": project_relative(args.model),
        "split": project_relative(args.split),
        "rows": len(rows),
        "gateway_band": {"judge": JUDGE, "block": BLOCK},
        "note": (
            "The egress aggregate covers only toxicity_harm and malicious_code; the other three "
            "heads are input-framed and excluded by RESPONSE_RELEVANT_CATEGORIES."
        ),
        "egress_thresholds": configured or None,
        "slices": {name: slice_report(mask) for name, mask in slices.items()},
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
