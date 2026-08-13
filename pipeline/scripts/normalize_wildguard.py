#!/usr/bin/env python3
"""Normalize WildGuardMix prompts into training-eligible records.

Acquired to fix the two things v0.5 measured as broken at once:

  * `cyberattack` supplies 1,599 real `malicious_code` prompts -- roughly ten
    times the 153 obtainable from ungated sources, and the category where the
    served model catches 18 of 1,077 real holdout positives.
  * `benign` supplies matched controls. v0.5 added 1,595 real *harmful* rows and
    zero benign ones, and benign false positives tripled at the 0.90 production
    block threshold. `TARGETED_CURATION_SPEC.md` has always required matched
    controls; this is the first source that can actually satisfy it.

Scope decisions, all deliberate and recorded rather than left implicit:

1. **Response columns are never read.** WildGuardMix ships `response`,
   `response_refusal_label`, and `response_harm_label`. This pipeline's standing
   rule is that no assistant response may become a prompt feature, so only
   `prompt` is used. The response columns are relevant to Track B and are left
   for a round that is actually about egress.
2. **Only `cyberattack` and `benign` are ingested this round.** The other
   harmful subcategories would land in `toxicity_harm`, which already has 15,520
   real rows and is not the failing category. Ingesting them would confound the
   experiment this round exists to run.
3. **`copyright_violations` is excluded**, matching the holdout normalizer's
   treatment of HarmBench's copyright slice: verbatim-reproduction requests have
   no honest home among the five categories.
4. **The `adversarial` flag is recorded, not mapped.** It marks jailbreak-style
   phrasing and would arguably justify a `prompt_injection` label, but 20,567
   such rows would swamp a category that currently has 2,866 real ones and
   silently turn this into a different experiment. The flag is preserved in
   `annotation_notes` so a later round can use it on purpose.
5. **Benign rows are subsampled deterministically**, stratified by the
   `adversarial` flag so half the controls are hard negatives. All 40,543 would
   double the corpus and swamp everything else.

Usage:
  python -m scripts.normalize_wildguard \
     --manifest data/manifests/acquisition_manifest_wildguard.json \
     --benign-sample 3200 \
     --output data/normalized_v2/wildguard_sources.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_semantic_splits import project_relative

DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "manifests" / "acquisition_manifest_wildguard.json"
DEFAULT_RAW_ROOT = PROJECT_ROOT / "data" / "raw_v2"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "normalized_v2" / "wildguard_sources.jsonl"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "reports" / "wildguard_normalization.json"

SOURCE_ID = "wildguardmix"
INGESTED_SUBCATEGORIES = {"cyberattack": ["malicious_code"], "benign": ["benign"]}
# Never read as prompt features, per the standing no-assistant-response rule.
FORBIDDEN_COLUMNS = {"response", "response_refusal_label", "response_harm_label"}


class NormalizationError(RuntimeError):
    pass


def record_id(item_id: str, text: str) -> str:
    return hashlib.sha256("\x1f".join((SOURCE_ID, item_id, text)).encode("utf-8")).hexdigest()


def make_record(
    *, revision: str, item_id: str, text: str, labels: list[str], license_spdx: str,
    notes: str, template_family: str,
) -> dict[str, Any]:
    text = text.strip()
    if not text:
        raise NormalizationError(f"{SOURCE_ID}:{item_id} has empty text")
    benign = labels == ["benign"]
    return {
        "record_id": record_id(item_id, text),
        "text": text,
        "source_id": SOURCE_ID,
        "source_item_id": item_id,
        "source_revision": revision,
        "split": "train",
        "language": "en",
        "labels": sorted(set(labels)),
        "severity": "none" if benign else "high",
        "annotation_confidence": 1.0,
        "template_family": template_family,
        "semantic_cluster_id": None,
        "conversation_id": None,
        "transformation_parent_id": None,
        "transformations": [],
        "context": "benign" if benign else "malicious",
        "license_spdx": license_spdx,
        "annotation_notes": notes,
        "training_eligible": True,
    }


def deterministic_sample(candidates: list[int], quota: int, key) -> list[int]:
    """Stable content-hash ordering, so reruns pick the same rows without a seed."""
    return sorted(candidates, key=key)[:quota]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--benign-sample", type=int, default=3200,
                        help="benign controls to keep, split evenly across the adversarial flag")
    args = parser.parse_args()

    import pyarrow.parquet as pq

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    source = next((s for s in manifest["sources"] if s["id"] == SOURCE_ID), None)
    if source is None:
        raise NormalizationError(f"{SOURCE_ID} not present in {args.manifest}")
    revision, license_spdx = source["revision"], source["license_spdx"]

    path = args.raw_root / SOURCE_ID / revision / "train" / "wildguard_train.parquet"
    columns = ["prompt", "adversarial", "prompt_harm_label", "subcategory"]
    if FORBIDDEN_COLUMNS & set(columns):
        raise NormalizationError("refusing to read assistant-response columns as prompt features")
    table = pq.read_table(path, columns=columns).to_pydict()

    counters: Counter = Counter()
    kept: dict[str, list[int]] = defaultdict(list)
    # WildGuardMix pairs each prompt with several responses, so its 86,759 train
    # rows carry only ~47,852 distinct prompts. Deduplicating on prompt text
    # before sampling is what makes the quotas mean unique prompts; keying on row
    # identity instead silently fills a benign quota with the same prompt over
    # and over, which would weight those prompts in training and overstate how
    # many controls were actually added.
    seen_text: set[str] = set()
    for index, subcategory in enumerate(table["subcategory"]):
        labels = INGESTED_SUBCATEGORIES.get(subcategory)
        if labels is None:
            counters[f"skipped_subcategory:{subcategory}"] += 1
            continue
        harm = table["prompt_harm_label"][index]
        expected = "unharmful" if labels == ["benign"] else "harmful"
        if harm != expected:
            # Publisher labels disagreeing with each other is a data-quality
            # signal, not something to resolve by preferring whichever one suits.
            counters[f"skipped_label_conflict:{subcategory}:{harm}"] += 1
            continue
        normalized = " ".join(table["prompt"][index].split()).casefold()
        if normalized in seen_text:
            counters[f"skipped_duplicate_prompt:{subcategory}"] += 1
            continue
        seen_text.add(normalized)
        kept[subcategory].append(index)

    def content_key(index: int) -> str:
        return hashlib.sha256(table["prompt"][index].encode("utf-8")).hexdigest()

    selected: list[int] = list(kept.get("cyberattack", []))
    benign = kept.get("benign", [])
    half = args.benign_sample // 2
    for adversarial in (True, False):
        pool = [i for i in benign if bool(table["adversarial"][i]) is adversarial]
        chosen = deterministic_sample(pool, half, content_key)
        counters[f"benign_sampled_adversarial_{adversarial}"] = len(chosen)
        counters[f"benign_available_adversarial_{adversarial}"] = len(pool)
        selected.extend(chosen)

    records, seen = [], set()
    duplicates = 0
    for index in selected:
        subcategory = table["subcategory"][index]
        labels = INGESTED_SUBCATEGORIES[subcategory]
        adversarial = bool(table["adversarial"][index])
        record = make_record(
            revision=revision, item_id=f"train-{index}", text=table["prompt"][index],
            labels=labels, license_spdx=license_spdx,
            notes=(
                f"publisher_subcategory={subcategory};"
                f"publisher_prompt_harm_label={table['prompt_harm_label'][index]};"
                f"adversarial={adversarial};response_columns_unused=true"
            ),
            template_family=f"wildguard_{subcategory}_{'adversarial' if adversarial else 'plain'}",
        )
        if record["record_id"] in seen:
            duplicates += 1
            continue
        seen.add(record["record_id"])
        records.append(record)
    records.sort(key=lambda row: row["record_id"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    report = {
        "report_version": "0.1.0",
        "acquisition_manifest": project_relative(args.manifest),
        "output": project_relative(args.output),
        "source_rows_available": len(table["prompt"]),
        "rows": len(records),
        "exact_duplicate_rows_collapsed": duplicates,
        "label_occurrences": dict(sorted(Counter(l for r in records for l in r["labels"]).items())),
        "counters": dict(sorted(counters.items())),
        "ingested_subcategories": {k: v for k, v in sorted(INGESTED_SUBCATEGORIES.items())},
        "labelling_policy": "publisher-declared subcategory and prompt_harm_label only; no text-derived labels",
        "assistant_response_columns_used": False,
        "adversarial_flag_mapped_to_label": False,
        "status": "normalized_pending_contamination_scan",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
