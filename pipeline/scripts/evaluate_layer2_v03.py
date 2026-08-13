#!/usr/bin/env python3
"""Proper calibration + threshold evaluation of a served Layer 2 model.

Runs echelon/evaluation.py (binary_metrics, expected_calibration_error,
select_threshold, slice_metrics) against a materialized test split, using the
*calibrated* probabilities the serving adapter actually emits (per-category
temperature scaling from calibration.json applied exactly as
MultiLabelTransformersAdapter.predict does). The train script only reported
Brier at threshold 0.5; this adds ECE and recall-constrained operating points,
and -- to test the "in-distribution synthetic inflation" concern directly --
breaks each category down by real-source vs synthetic-source rows.

Usage:
  python -m scripts.evaluate_layer2_v03 \
     --model models/layer2-threat-distilbert/best \
     --split data/splits_v2_v03/test.jsonl \
     --report data/reports/layer2_eval_v03_best.json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from echelon.evaluation import (
    binary_metrics, expected_calibration_error, select_threshold, slice_metrics,
)
from scripts.build_semantic_splits import load_jsonl, project_relative

CATEGORIES = [
    "prompt_injection", "system_prompt_leakage", "malicious_code",
    "toxicity_harm", "adversarial_obfuscation",
]
SYNTHETIC_PREFIXES = ("echelon_targeted_", "echelon_response_")


def calibrated_scores(model_dir: Path, texts: list[str], batch_size: int) -> np.ndarray:
    """Batched replica of MultiLabelTransformersAdapter.predict's calibrated math."""
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True)
    model.eval()
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    model.to(device)
    id2label = {int(i): str(l) for i, l in model.config.id2label.items()}
    order = [id2label[i] for i in range(len(id2label))]
    calib = json.loads((model_dir / "calibration.json").read_text())["temperatures"]
    temps = np.array([float(calib.get(c, 1.0)) for c in order], dtype=np.float64)

    out = []
    with torch.inference_mode():
        for start in range(0, len(texts), batch_size):
            chunk = texts[start:start + batch_size]
            enc = tok(chunk, return_tensors="pt", truncation=True, max_length=256, padding=True).to(device)
            logits = model(**enc).logits.float().cpu().numpy()
            scaled = np.clip(logits / temps, -60.0, 60.0)
            out.append(1.0 / (1.0 + np.exp(-scaled)))
    probs = np.concatenate(out)
    # Reorder columns to CATEGORIES order for downstream indexing. A response-side
    # model carries only the heads meaningful on assistant output, so categories it
    # does not have are returned as zeros rather than raising -- callers that care
    # about a missing head (the egress aggregate) filter to their own category set.
    zeros = np.zeros(len(probs), dtype=probs.dtype)
    return np.stack(
        [probs[:, order.index(c)] if c in order else zeros for c in CATEGORIES], axis=1,
    )


def bm_dict(m) -> dict:
    return {
        "threshold": round(m.threshold, 4), "tp": m.tp, "tn": m.tn, "fp": m.fp, "fn": m.fn,
        "precision": round(m.precision, 4), "recall": round(m.recall, 4), "f1": round(m.f1, 4),
        "benign_fpr": round(m.benign_fpr, 4), "brier": round(m.brier, 6),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, default=PROJECT_ROOT / "models" / "layer2-threat-distilbert" / "best")
    parser.add_argument("--split", type=Path, default=PROJECT_ROOT / "data" / "splits_v2_v03" / "test.jsonl")
    parser.add_argument("--report", type=Path, default=PROJECT_ROOT / "data" / "reports" / "layer2_eval_v03_best.json")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--ece-bins", type=int, default=10)
    parser.add_argument("--min-recall", type=float, default=0.90)
    parser.add_argument("--max-benign-fpr", type=float, default=0.05)
    args = parser.parse_args()

    rows = load_jsonl(args.split)
    texts = [r["text"] for r in rows]
    label_mat = np.array([[1 if c in r["labels"] else 0 for c in CATEGORIES] for r in rows])
    is_synth = [str(r.get("source_id", "")).startswith(SYNTHETIC_PREFIXES) for r in rows]
    source_slice = ["synthetic" if s else "real" for s in is_synth]

    print(f"scoring {len(rows)} rows through {args.model} ...", flush=True)
    probs = calibrated_scores(args.model, texts, args.batch_size)

    per_category = {}
    macro_f1 = []
    for ci, cat in enumerate(CATEGORIES):
        y = label_mat[:, ci].tolist()
        p = probs[:, ci].tolist()
        at_half = binary_metrics(y, p, 0.5)
        ece = expected_calibration_error(y, p, args.ece_bins)
        macro_f1.append(at_half.f1)
        entry = {
            "support": int(sum(y)),
            "at_0.5": bm_dict(at_half),
            "expected_calibration_error": round(ece, 4),
        }
        # Recall-constrained operating point (may not exist for tiny/degenerate slices).
        try:
            sel = select_threshold(y, p, minimum_recall=args.min_recall, maximum_benign_fpr=args.max_benign_fpr)
            entry["recall_constrained_operating_point"] = bm_dict(sel)
        except ValueError as exc:
            entry["recall_constrained_operating_point"] = {"error": str(exc)}
        # Real vs synthetic slice at 0.5 (the in-distribution-inflation probe).
        if sum(y) > 0:
            sl = slice_metrics(y, p, source_slice, 0.5)
            entry["by_source"] = {
                name: {**bm_dict(m), "support": m.tp + m.fn} for name, m in sl.items()
            }
        per_category[cat] = entry

    # Aggregate benign FPR (row is benign iff no category label set); max calibrated prob.
    agg = probs.max(axis=1)
    benign_mask = label_mat.sum(axis=1) == 0
    report = {
        "model": project_relative(args.model),
        "split": project_relative(args.split),
        "rows": len(rows),
        "macro_f1_at_0.5": round(float(np.mean(macro_f1)), 4),
        "benign_rows": int(benign_mask.sum()),
        "benign_fpr_at_0.5": round(float((agg[benign_mask] >= 0.5).mean()), 4),
        "benign_fpr_at_0.9": round(float((agg[benign_mask] >= 0.9).mean()), 4),
        "ece_bins": args.ece_bins,
        "recall_constraint": {"min_recall": args.min_recall, "max_benign_fpr": args.max_benign_fpr},
        "per_category": per_category,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
