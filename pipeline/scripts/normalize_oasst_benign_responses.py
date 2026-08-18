#!/usr/bin/env python3
"""Normalize oasst1 assistant messages into benign response controls.

Fixes a measured defect rather than adding volume for its own sake. The response
model's benign class is 100% WildGuardMix, whose benign rows are answers to
adversarial prompts -- refusals and safety-hedged prose. The model learned that a
benign response *sounds like a refusal*, and scores ordinary assistant output as
toxic: 0.687 on a 145-word order-status reply, 0.859 on an eight-word one, against
0.011 for a short refusal. Register, not length. Nothing in the corpus carries the
ordinary register at all, which is why the egress evaluation reports benign
responses passing 89.6% while 44% of ordinary replies escalate in practice.

Filtering is deliberately conservative, because a row admitted here is labelled
benign and a mistake teaches the model that something harmful is fine:

  * assistant role only -- prompter turns are user text, not model output
  * English only, not deleted, and `review_result: true` (passed community review)
  * contributor safety labels near zero (toxicity, hate_speech, violence,
    sexual_content, not_appropriate, pii)
  * Detoxify scores below a low ceiling, as an independent second opinion
  * quality label above a floor, so the benign class is not taught on bad answers

Usage:
  python -m scripts.normalize_oasst_benign_responses --limit 6000
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_semantic_splits import project_relative

SAFETY_LABELS = ("toxicity", "hate_speech", "violence", "sexual_content",
                 "not_appropriate", "spam", "pii")
DETOXIFY_KEYS = ("toxicity", "severe_toxicity", "obscene", "threat",
                 "insult", "identity_attack", "sexual_explicit")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path,
                        default=PROJECT_ROOT / "data" / "manifests" / "acquisition_manifest_oasst.json")
    parser.add_argument("--raw-root", type=Path, default=PROJECT_ROOT / "data" / "raw_v2")
    parser.add_argument("--output", type=Path,
                        default=PROJECT_ROOT / "data" / "normalized_v2" / "oasst_benign_responses.jsonl")
    parser.add_argument("--report", type=Path,
                        default=PROJECT_ROOT / "data" / "reports" / "oasst_benign_responses.json")
    parser.add_argument("--limit", type=int, default=6000)
    parser.add_argument("--max-safety-label", type=float, default=0.10)
    parser.add_argument("--max-detoxify", type=float, default=0.10)
    parser.add_argument("--min-quality", type=float, default=0.50)
    parser.add_argument("--min-words", type=int, default=5)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    source = next(s for s in manifest["sources"] if s["id"] == "oasst1_assistant_responses")
    path = (args.raw_root / source["id"] / source["revision"]
            / "2023-04-12_oasst_ready.messages.jsonl.gz")

    dropped: Counter = Counter()
    kept = []
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("role") != "assistant":
                dropped["not_assistant"] += 1
                continue
            if row.get("lang") != "en":
                dropped["not_english"] += 1
                continue
            if row.get("deleted") or row.get("review_result") is not True:
                dropped["deleted_or_unreviewed"] += 1
                continue
            text = (row.get("text") or "").strip()
            if len(text.split()) < args.min_words:
                dropped["too_short"] += 1
                continue
            labels = row.get("labels") or {}
            if any(float((labels.get(k) or {}).get("value", 0.0)) > args.max_safety_label
                   for k in SAFETY_LABELS):
                dropped["safety_label"] += 1
                continue
            detox = row.get("detoxify") or {}
            if any(float(detox.get(k, 0.0)) > args.max_detoxify for k in DETOXIFY_KEYS):
                dropped["detoxify"] += 1
                continue
            quality = float((labels.get("quality") or {}).get("value", 0.0))
            if quality < args.min_quality:
                dropped["low_quality"] += 1
                continue
            kept.append((row, text, quality))

    # Highest-quality first, so a --limit takes the best rather than an arbitrary slice.
    kept.sort(key=lambda item: (-item[2], item[0]["message_id"]))
    selected = kept[:args.limit]

    records = []
    for row, text, quality in selected:
        record_id = hashlib.sha256(
            f"oasst1_benign_response\x1f{row['message_id']}".encode()).hexdigest()
        records.append({
            "record_id": record_id,
            "text": text,
            "source_id": "oasst1_benign_response",
            "source_item_id": row["message_id"],
            "source_revision": source["revision"],
            "split": "train",
            "language": "en",
            "labels": ["benign"],
            "severity": "none",
            "annotation_confidence": 1.0,
            "template_family": None,
            "semantic_cluster_id": None,
            "conversation_id": row.get("message_tree_id"),
            "transformation_parent_id": None,
            "transformations": [],
            "context": "benign",
            "license_spdx": "Apache-2.0",
            "annotation_notes": (
                f"role=assistant;quality={quality:.3f};"
                f"synthetic={bool(row.get('synthetic'))};register=ordinary_assistant_output"
            ),
            "training_eligible": True,
        })

    records.sort(key=lambda r: r["record_id"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    words = sorted(len(r["text"].split()) for r in records)
    report = {
        "report_version": "0.1.0",
        "source": {"dataset": source["id"], "revision": source["revision"],
                   "license_spdx": source["license_spdx"]},
        "output": project_relative(args.output),
        "eligible_after_filters": len(kept),
        "rows": len(records),
        "limit": args.limit,
        "filters": {
            "max_safety_label": args.max_safety_label,
            "max_detoxify": args.max_detoxify,
            "min_quality": args.min_quality,
            "min_words": args.min_words,
        },
        "rows_dropped": dict(sorted(dropped.items())),
        "word_count": {
            "p50": words[len(words)//2] if words else 0,
            "p90": words[int(len(words)*0.9)] if words else 0,
        },
        "purpose": "supply the ordinary-assistant-output register the benign class lacks",
        "status": "normalized_pending_merge",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
