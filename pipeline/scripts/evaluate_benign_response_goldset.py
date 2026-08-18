#!/usr/bin/env python3
"""Measure egress false positives on ordinary assistant output, and the ceiling.

Companion to evaluate_benign_cyber_goldset.py, on the response side. It answers
two questions:

  1. How often does ordinary assistant output escalate to the LLM judge?
  2. Can moving the egress threshold fix that?

The second question is the important one, and the answer here is no. On the
ingress side the analogous problem *was* fixable by a threshold, because the
prompts that stopped hard-blocking still escalated to the judge -- total coverage
was unchanged. Egress has no such safety net: content below the judge threshold
is delivered without any review at all, so buying benign quiet costs real toxic
recall. This script reports the frontier so that trade is visible instead of
assumed.

Usage:
  python -m scripts.evaluate_benign_response_goldset
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
import scripts.evaluate_layer2_v03 as ev


def note(row: dict, key: str) -> str:
    return next(
        (f.partition("=")[2] for f in (row.get("annotation_notes") or "").split(";")
         if f.startswith(key + "=")), "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path,
                        default=PROJECT_ROOT / "models" / "layer2-response-distilbert" / "best")
    parser.add_argument("--goldset", type=Path,
                        default=PROJECT_ROOT / "data" / "holdout_v1" / "benign_response_goldset.jsonl")
    parser.add_argument("--response-test", type=Path,
                        default=PROJECT_ROOT / "data" / "splits_response_v1" / "test.jsonl")
    parser.add_argument("--report", type=Path,
                        default=PROJECT_ROOT / "data" / "reports" / "benign_response_goldset_eval.json")
    parser.add_argument("--sample", type=int, default=400)
    args = parser.parse_args()

    labels = json.loads((args.model / "config.json").read_text())["id2label"]
    order = [labels[str(i)] for i in range(len(labels))]
    thresholds = json.loads((args.model / "thresholds.json").read_text())["egress_thresholds"]
    live_judge = float(thresholds["toxicity_harm"]["judge"])
    live_block = float(thresholds["toxicity_harm"]["block"])

    original, ev.CATEGORIES = ev.CATEGORIES, order

    def toxicity(texts: list[str]) -> np.ndarray:
        return ev.calibrated_scores(args.model, texts, 16)[:, order.index("toxicity_harm")]

    gold = load_jsonl(args.goldset)
    gold_scores = toxicity([r["text"] for r in gold])
    dev = np.array([i for i, r in enumerate(gold) if note(r, "goldset_split") == "dev"])
    test = np.array([i for i, r in enumerate(gold) if note(r, "goldset_split") == "test"])

    response_rows = load_jsonl(args.response_test)
    corpus_benign = toxicity([r["text"] for r in response_rows if r["labels"] == ["benign"]][:args.sample])
    corpus_toxic = toxicity([r["text"] for r in response_rows if "toxicity_harm" in r["labels"]][:args.sample])
    ev.CATEGORIES = original

    def describe(name: str, arr: np.ndarray) -> dict:
        return {
            "slice": name, "rows": int(len(arr)),
            "p50": round(float(np.percentile(arr, 50)), 4),
            "p90": round(float(np.percentile(arr, 90)), 4),
            "mean": round(float(arr.mean()), 4),
            "escalates_at_live_threshold": round(float((arr >= live_judge).mean()), 4),
            "blocks_at_live_threshold": round(float((arr >= live_block).mean()), 4),
        }

    frontier = []
    for candidate in (live_judge, 0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9):
        frontier.append({
            "judge_threshold": round(float(candidate), 4),
            "goldset_dev_escalates": round(float((gold_scores[dev] >= candidate).mean()), 4),
            "goldset_test_escalates": round(float((gold_scores[test] >= candidate).mean()), 4),
            "corpus_benign_escalates": round(float((corpus_benign >= candidate).mean()), 4),
            "corpus_toxic_reviewed": round(float((corpus_toxic >= candidate).mean()), 4),
        })

    # The best operating point that keeps ordinary output quiet, and what it costs.
    affordable = [f for f in frontier if f["goldset_dev_escalates"] <= 0.10]
    ceiling = max(affordable, key=lambda f: f["corpus_toxic_reviewed"]) if affordable else None
    live = frontier[0]

    report = {
        "report_version": "0.1.0",
        "model": project_relative(args.model),
        "goldset": project_relative(args.goldset),
        "live_egress_thresholds": {"judge": live_judge, "block": live_block},
        "slices": [
            describe("goldset_ordinary_assistant_output", gold_scores),
            describe("corpus_benign_wildguard", corpus_benign),
            describe("corpus_toxic_wildguard", corpus_toxic),
        ],
        "threshold_frontier": frontier,
        "verdict": {
            "live": live,
            "best_point_keeping_ordinary_output_quiet": ceiling,
            "toxic_review_cost": (
                round(live["corpus_toxic_reviewed"] - ceiling["corpus_toxic_reviewed"], 4)
                if ceiling else None
            ),
            "conclusion": (
                "A threshold cannot fix this. Ordinary assistant output and genuinely "
                "toxic responses occupy overlapping score ranges, so any threshold that "
                "quiets the first stops reviewing a large share of the second. Unlike "
                "the ingress case there is no safety net: egress content below the judge "
                "threshold is delivered unreviewed. The fix is training data -- the "
                "benign class is entirely WildGuard refusal-shaped safety prose and "
                "contains no ordinary assistant output at all."
            ),
        },
        "results": [
            {"text": r["text"][:160], "domain": note(r, "domain"), "shape": note(r, "shape"),
             "goldset_split": note(r, "goldset_split"), "toxicity_harm": round(float(s), 4)}
            for r, s in zip(gold, gold_scores)
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for entry in report["slices"]:
        print(f"  {entry['slice']:36s} n={entry['rows']:4d} p50={entry['p50']:.3f} "
              f"p90={entry['p90']:.3f} escalates={entry['escalates_at_live_threshold']:.3f}")
    print(f"\n  {'judge':>7} | {'gold dev':>9} {'gold test':>10} {'corpus benign':>14} {'toxic reviewed':>15}")
    for f in frontier:
        print(f"  {f['judge_threshold']:7.4f} | {f['goldset_dev_escalates']:9.3f} "
              f"{f['goldset_test_escalates']:10.3f} {f['corpus_benign_escalates']:14.3f} "
              f"{f['corpus_toxic_reviewed']:15.3f}")
    if ceiling:
        print(f"\n  best point keeping ordinary output quiet: judge={ceiling['judge_threshold']}, "
              f"toxic reviewed {ceiling['corpus_toxic_reviewed']:.3f} "
              f"(costs {report['verdict']['toxic_review_cost']:.3f} vs live)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
