#!/usr/bin/env python3
"""Merge contamination-scanned real-source rows into the v0.3 training corpus.

Produces the v0.5 corpus: v0.3's 36,392 reviewed rows plus the real-source
malicious-code and harmful-request rows from `normalize_real_code_sources.py`,
after those have been scanned against the frozen holdout.

Refuses to run on unscanned input. The scan is not advisory here: the publisher
provenance filter in the registry removed the 67 rows RedTeam_2K itself
attributes to AdvBench, and the content scan *still* found 17 exact normalized
matches against holdout prompts. Metadata was not sufficient, so the merge
requires the scanned output specifically.

Usage:
  python -m scripts.build_training_corpus_v05 \
     --base data/normalized_v2/eligible_reviewed_v03.jsonl \
     --additions data/normalized_v2/real_code_sources_clean.jsonl \
     --scan-report data/reports/real_code_vs_holdout_scan.json \
     --output data/normalized_v2/eligible_reviewed_v05.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_semantic_splits import load_jsonl, project_relative

WHITESPACE = re.compile(r"\s+")


def normalized_text(text: str) -> str:
    return WHITESPACE.sub(" ", text).strip().casefold()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=PROJECT_ROOT / "data" / "normalized_v2" / "eligible_reviewed_v03.jsonl")
    parser.add_argument("--additions", type=Path, default=PROJECT_ROOT / "data" / "normalized_v2" / "real_code_sources_clean.jsonl")
    parser.add_argument("--scan-report", type=Path, default=PROJECT_ROOT / "data" / "reports" / "real_code_vs_holdout_scan.json")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "data" / "normalized_v2" / "eligible_reviewed_v05.jsonl")
    parser.add_argument("--report", type=Path, default=PROJECT_ROOT / "data" / "reports" / "training_corpus_v05.json")
    args = parser.parse_args()

    scan = json.loads(args.scan_report.read_text(encoding="utf-8"))
    if scan.get("status") != "scanned":
        raise SystemExit(f"scan report is not a completed scan: {args.scan_report}")
    if scan.get("clean_rows") is None:
        raise SystemExit("scan report has no clean_rows count")

    base = load_jsonl(args.base)
    additions = load_jsonl(args.additions)
    if len(additions) != scan["clean_rows"]:
        raise SystemExit(
            f"additions ({len(additions)}) do not match the scan's clean_rows ({scan['clean_rows']}); "
            "the merge input must be the scanned output, not the raw normalization"
        )

    base_ids = {row["record_id"] for row in base}
    base_texts = {normalized_text(row["text"]) for row in base}
    merged = list(base)
    skipped: Counter = Counter()
    for row in additions:
        if row["record_id"] in base_ids:
            skipped["duplicate_record_id"] += 1
            continue
        if normalized_text(row["text"]) in base_texts:
            skipped["duplicate_normalized_text"] += 1
            continue
        base_ids.add(row["record_id"])
        base_texts.add(normalized_text(row["text"]))
        merged.append(row)

    merged.sort(key=lambda row: row["record_id"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in merged:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()

    def labels_by_source_kind(rows):
        real = Counter(l for r in rows for l in r["labels"]
                       if not str(r.get("source_id", "")).startswith("echelon_"))
        synth = Counter(l for r in rows for l in r["labels"]
                        if str(r.get("source_id", "")).startswith("echelon_"))
        return {"real": dict(sorted(real.items())), "synthetic": dict(sorted(synth.items()))}

    report = {
        "report_version": "0.1.0",
        "base": project_relative(args.base),
        "additions": project_relative(args.additions),
        "output": project_relative(args.output),
        "base_rows": len(base),
        "addition_rows_offered": len(additions),
        "addition_rows_merged": len(merged) - len(base),
        "addition_rows_skipped": dict(sorted(skipped.items())),
        "output_rows": len(merged),
        "output_sha256": digest,
        "holdout_scan": {
            "report": project_relative(args.scan_report),
            "contaminated_rows_excluded": scan.get("contaminated_rows"),
            "contamination_reasons": scan.get("contamination_reasons"),
        },
        "label_occurrences_by_source_kind": labels_by_source_kind(merged),
        "rows_by_source": dict(sorted(Counter(r["source_id"] for r in merged).items())),
        "status": "merged_pending_split",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
