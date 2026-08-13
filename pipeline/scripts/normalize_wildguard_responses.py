#!/usr/bin/env python3
"""Normalize WildGuardMix assistant responses into response-shaped records.

Track B is the egress (response-side) half of the detector, and until now it has
had no real data of any kind. The v0.3 pilot generated 300 synthetic responses
across 8 archetypes, scored F1 1.0 in-distribution, and then scored ~0.001 on an
out-of-archetype probe -- it had memorised templates, not learned the
operational-versus-defensive distinction. `_apply_code_shape_floor` in
`service/security_api.py` exists to paper over exactly that gap.

WildGuardMix ships human-labelled assistant responses, which is what was
missing: 37,934 train rows and 1,709 human-annotated test rows carrying both a
response and a `response_harm_label`.

**This deliberately reads the response columns.** The pipeline's standing rule --
no assistant response may become a prompt feature -- exists to stop response
content leaking into *prompt* classification. Track B is a response-side model,
so response text is the feature by definition. The rule is not being bent; it
does not apply here. Prompt columns are correspondingly not read.

Labels come from publisher fields on both axes:
  response_harm_label == harmful  + prompt subcategory cyberattack -> malicious_code
  response_harm_label == harmful  + any other subcategory          -> toxicity_harm
  response_harm_label == unharmful                                 -> benign

That second axis is imprecise and is recorded rather than hidden: a harmful
response to a cyberattack prompt is sometimes a phishing email rather than
operational code. Every row therefore also records whether the service's own
`_looks_like_code` heuristic fires on it, so code-shaped and prose-shaped
malicious output can be reported as separate slices without inventing a label.

Usage:
  python -m scripts.normalize_wildguard_responses --source-split test --role holdout \
     --output data/holdout_v1/response_holdout.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_semantic_splits import project_relative

DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "manifests" / "acquisition_manifest_wildguard.json"
DEFAULT_RAW_ROOT = PROJECT_ROOT / "data" / "raw_v2"

SOURCE_ID = "wildguardmix_response"
CODE_SUBCATEGORY = "cyberattack"
MAX_RESPONSE_CHARS = 20_000


# Real, independently-authored rows have NO template lineage, so template_family
# must stay None. build_semantic_splits treats a shared (source_id,
# template_family) as a declared group that may not cross splits -- correct for
# generated rows sharing a frame, badly wrong here: setting it to a publisher
# CATEGORY name fuses every row of that category into one block that lands
# wholly in a single split. In v0.6 that put all 1,600 wildguard benign controls
# in test and zero in train, so the matched controls the round existed to add
# never reached the model. The publisher category is already preserved in
# annotation_notes, which is where it belongs: metadata, not lineage.


class NormalizationError(RuntimeError):
    pass


def looks_like_code(text: str) -> bool:
    """Reuse the service's own heuristic so the slice matches production behaviour."""
    from service.security_api import _looks_like_code

    return bool(_looks_like_code(text))


def record_id(item_id: str, text: str) -> str:
    return hashlib.sha256("\x1f".join((SOURCE_ID, item_id, text)).encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--source-split", choices=("train", "test"), default="test")
    parser.add_argument("--role", choices=("training", "holdout"), default="holdout")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--limit-benign", type=int, default=0,
                        help="cap benign responses (0 = keep all); used to balance a training round")
    args = parser.parse_args()

    import pyarrow.parquet as pq

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    source = next((s for s in manifest["sources"] if s["id"] == "wildguardmix"), None)
    if source is None:
        raise NormalizationError(f"wildguardmix not present in {args.manifest}")
    revision, license_spdx = source["revision"], source["license_spdx"]

    split = args.source_split
    path = args.raw_root / "wildguardmix" / revision / split / f"wildguard_{split}.parquet"
    columns = ["response", "response_harm_label", "response_refusal_label", "subcategory"]
    if split == "test":
        columns.append("response_harm_agreement")
    table = pq.read_table(path, columns=columns).to_pydict()
    agreement = table.get("response_harm_agreement")

    counters: Counter = Counter()
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    benign_kept = 0
    for index, response in enumerate(table["response"]):
        harm = table["response_harm_label"][index]
        if not response or harm not in ("harmful", "unharmful"):
            counters["skipped_missing_response_or_label"] += 1
            continue
        text = response.strip()
        if not text:
            counters["skipped_empty"] += 1
            continue
        if len(text) > MAX_RESPONSE_CHARS:
            counters["skipped_oversized"] += 1
            continue
        normalized = " ".join(text.split()).casefold()
        if normalized in seen:
            counters["skipped_duplicate_response"] += 1
            continue
        subcategory = table["subcategory"][index]
        if harm == "unharmful":
            labels = ["benign"]
            if args.limit_benign and benign_kept >= args.limit_benign:
                counters["skipped_benign_over_cap"] += 1
                continue
            benign_kept += 1
        elif subcategory == CODE_SUBCATEGORY:
            labels = ["malicious_code"]
        else:
            labels = ["toxicity_harm"]
        seen.add(normalized)
        code_shaped = looks_like_code(text)
        counters[f"{labels[0]}:code_shaped={code_shaped}"] += 1
        notes = (
            f"response_shaped=true;publisher_response_harm_label={harm};"
            f"prompt_subcategory={subcategory};"
            f"response_refusal_label={table['response_refusal_label'][index]};"
            f"looks_like_code={code_shaped};prompt_columns_unused=true"
        )
        if agreement is not None:
            notes += f";annotator_agreement={agreement[index]}"
        records.append({
            "record_id": record_id(f"{split}-{index}", text),
            "text": text,
            "source_id": SOURCE_ID,
            "source_item_id": f"{split}-{index}",
            "source_revision": revision,
            "split": "private_test" if args.role == "holdout" else "train",
            "language": "en",
            "labels": labels,
            "severity": "none" if labels == ["benign"] else "high",
            "annotation_confidence": 1.0,
            "template_family": None,
            "semantic_cluster_id": None,
            "conversation_id": None,
            "transformation_parent_id": None,
            "transformations": [],
            "context": "benign" if labels == ["benign"] else "malicious",
            "license_spdx": license_spdx,
            "annotation_notes": notes,
            "training_eligible": args.role == "training",
            "response_shaped": True,
        })

    records.sort(key=lambda row: row["record_id"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    report = {
        "report_version": "0.1.0",
        "source": "wildguardmix",
        "source_split": split,
        "role": args.role,
        "output": project_relative(args.output),
        "rows": len(records),
        "label_occurrences": dict(sorted(Counter(l for r in records for l in r["labels"]).items())),
        "counters": dict(sorted(counters.items())),
        "labelling_policy": (
            "publisher response_harm_label plus prompt subcategory; code-shape recorded as a "
            "slice, never as a label"
        ),
        "reads_response_columns": True,
        "reads_prompt_columns": False,
        "training_eligible": args.role == "training",
        "status": "normalized_pending_contamination_scan",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
