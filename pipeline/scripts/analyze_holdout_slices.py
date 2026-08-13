#!/usr/bin/env python3
"""Slice held-out evaluation results by source and publisher subcategory.

The aggregate held-out numbers say the model collapses out of distribution. This
separates two very different causes that the aggregate conflates:

  * genuine blindness -- the model misses real attacks that look like the ones it
    trained on (HarmBench's cybercrime prompts are the same length and register
    as the synthetic malicious_code corpus), and
  * format shift -- CyberSecEval's MITRE prompts are ~500 tokens of LLM-generated
    JSON-wrapped text, past the 256-token truncation limit and unlike anything in
    training.

Both are real failures, but only the first is fixed by better labels and the
second by longer context plus format diversity, so the report keeps them apart.
Also reports per-head firing on the benign control slice, since aggregate
false-positive rate hides which head is responsible.

Usage:
  python -m scripts.analyze_holdout_slices \
     --split data/holdout_v1/holdout_eval_clean.jsonl \
     --report data/reports/layer2_holdout_slices_v1.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.evaluate_layer2_v03 import CATEGORIES, calibrated_scores, project_relative
from scripts.build_semantic_splits import load_jsonl


def publisher_category(row: dict) -> str | None:
    notes = row.get("annotation_notes") or ""
    for field in notes.split(";"):
        key, _, value = field.partition("=")
        if key == "publisher_category":
            return value
    return None


def estimated_tokens(text: str) -> int:
    return int(len(text.split()) * 1.35) + 2


def slice_stats(probs: np.ndarray, rows: list[dict], members: list[int], column: int) -> dict:
    scores = probs[members, column]
    tokens = [estimated_tokens(rows[i]["text"]) for i in members]
    return {
        "rows": len(members),
        "recall_at_0.5": round(float((scores >= 0.5).mean()), 4),
        "recall_at_0.9": round(float((scores >= 0.9).mean()), 4),
        "mean_probability": round(float(scores.mean()), 4),
        "estimated_tokens_p50": int(np.percentile(tokens, 50)),
        "estimated_tokens_p90": int(np.percentile(tokens, 90)),
        "over_truncation_limit_fraction": round(float(np.mean([t > 256 for t in tokens])), 4),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=PROJECT_ROOT / "models" / "layer2-threat-distilbert" / "best")
    parser.add_argument("--split", type=Path, default=PROJECT_ROOT / "data" / "holdout_v1" / "holdout_eval_clean.jsonl")
    parser.add_argument("--report", type=Path, default=PROJECT_ROOT / "data" / "reports" / "layer2_holdout_slices_v1.json")
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()

    rows = load_jsonl(args.split)
    print(f"scoring {len(rows)} rows through {args.model} ...", flush=True)
    probs = calibrated_scores(args.model, [r["text"] for r in rows], args.batch_size)
    column = {c: i for i, c in enumerate(CATEGORIES)}

    per_category = {}
    for category in CATEGORIES:
        positives = [i for i, r in enumerate(rows) if category in r["labels"]]
        if not positives:
            continue
        by_source = defaultdict(list)
        by_publisher = defaultdict(list)
        for index in positives:
            by_source[rows[index]["source_id"]].append(index)
            label = publisher_category(rows[index])
            if label:
                by_publisher[f"{rows[index]['source_id']}:{label}"].append(index)
        per_category[category] = {
            "overall": slice_stats(probs, rows, positives, column[category]),
            "by_source": {
                name: slice_stats(probs, rows, members, column[category])
                for name, members in sorted(by_source.items())
            },
            "by_publisher_category": {
                name: slice_stats(probs, rows, members, column[category])
                for name, members in sorted(by_publisher.items())
            },
        }

    benign = [i for i, r in enumerate(rows) if r["labels"] == ["benign"]]
    aggregate = probs[benign].max(axis=1) if benign else np.array([])
    benign_report = {
        "rows": len(benign),
        "any_head_fires_at_0.5": round(float((aggregate >= 0.5).mean()), 4) if benign else None,
        "any_head_fires_at_0.9": round(float((aggregate >= 0.9).mean()), 4) if benign else None,
        "per_head_fires_at_0.5": {
            c: round(float((probs[benign, column[c]] >= 0.5).mean()), 4) for c in CATEGORIES
        } if benign else {},
    }

    report = {
        "report_version": "0.1.0",
        "model": project_relative(args.model),
        "split": project_relative(args.split),
        "rows": len(rows),
        "truncation_limit_tokens": 256,
        "per_category": per_category,
        "benign_controls": benign_report,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
