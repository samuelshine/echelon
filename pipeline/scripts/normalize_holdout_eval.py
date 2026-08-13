#!/usr/bin/env python3
"""Normalize the frozen evaluation-only benchmarks into a held-out eval split.

Every prior Layer 2 number this project has reported was measured on a test split
carved out of the same corpus the model trained on, reviewed by the same
AI-assisted reviewers that accepted the training rows. This script builds the
first evaluation set that shares neither the sources nor the review process:
JailbreakBench, HarmBench, StrongREJECT, and CyberSecEval, acquired at pinned
revisions under `role: evaluation_only, holdout: true`.

Two rules make the resulting numbers mean something, and both are load-bearing:

1. **Publisher labels only.** Category assignment comes from a declared field on
   the source row -- JailbreakBench's `Category`, HarmBench's `SemanticCategory`,
   CyberSecEval's `mitre_category` and `injection_variant`. Nothing is inferred
   from prompt text. Deriving labels from the text with our own keyword rules
   would rebuild exactly the circularity this set exists to break.
2. **Never eligible for training.** Rows are emitted with `split: private_test`
   and `training_eligible: false`. `build_training_corpus_*` reads
   `data/normalized_v2/eligible_reviewed*.jsonl`; this writes elsewhere.

Unmappable rows are dropped, loudly and counted, rather than forced into the
taxonomy: HarmBench's `copyright` slice has no honest home among the five
categories, so labelling it `toxicity_harm` would manufacture agreement.

Usage:
  python -m scripts.normalize_holdout_eval \
     --manifest data/manifests/acquisition_manifest_holdout.json \
     --output data/holdout_v1/holdout_eval.jsonl
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_semantic_splits import project_relative

DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "manifests" / "acquisition_manifest_holdout.json"
DEFAULT_RAW_ROOT = PROJECT_ROOT / "data" / "raw_v2"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "holdout_v1" / "holdout_eval.jsonl"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "reports" / "holdout_eval_normalization.json"

# JailbreakBench `Category` -> our taxonomy. Only Malware/Hacking maps to
# malicious_code; the rest are harmful-request behaviours, which is what
# toxicity_harm covers in this corpus (see CURRENT_PROGRESS's label definitions).
JBB_CATEGORY_LABELS = {
    "Malware/Hacking": ["malicious_code"],
    "Harassment/Discrimination": ["toxicity_harm"],
    "Physical harm": ["toxicity_harm"],
    "Economic harm": ["toxicity_harm"],
    "Fraud/Deception": ["toxicity_harm"],
    "Disinformation": ["toxicity_harm"],
    "Sexual/Adult content": ["toxicity_harm"],
    "Privacy": ["toxicity_harm"],
    "Expert advice": ["toxicity_harm"],
    "Government decision-making": ["toxicity_harm"],
}

# HarmBench `SemanticCategory` -> our taxonomy. `copyright` is deliberately
# absent: verbatim-reproduction requests are not any of our five categories.
HARMBENCH_CATEGORY_LABELS = {
    "cybercrime_intrusion": ["malicious_code"],
    "chemical_biological": ["toxicity_harm"],
    "illegal": ["toxicity_harm"],
    "misinformation_disinformation": ["toxicity_harm"],
    "harassment_bullying": ["toxicity_harm"],
    "harmful": ["toxicity_harm"],
}

# CyberSecEval injection variants that are obfuscation *by the publisher's own
# definition of the variant*, not by inspection of the prompt text.
OBFUSCATION_VARIANTS = {"token_smuggling", "payload_splitting", "repeated_token_attack"}

SEVERITY_BY_LABEL = {
    "malicious_code": "high",
    "prompt_injection": "high",
    "system_prompt_leakage": "high",
    "toxicity_harm": "high",
    "adversarial_obfuscation": "medium",
    "benign": "none",
}


class NormalizationError(RuntimeError):
    pass


def record_id(source_id: str, item_id: str, text: str) -> str:
    material = "\x1f".join((source_id, item_id, text))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def make_record(
    *, source_id: str, revision: str, item_id: str, text: str, labels: list[str],
    license_spdx: str, notes: str, template_family: str | None = None,
) -> dict[str, Any]:
    text = text.strip()
    if not text:
        raise NormalizationError(f"{source_id}:{item_id} has empty text")
    labels = sorted(set(labels))
    severity = "none" if labels == ["benign"] else max(
        (SEVERITY_BY_LABEL[label] for label in labels),
        key=lambda level: ["none", "low", "medium", "high", "critical"].index(level),
    )
    return {
        "record_id": record_id(source_id, item_id, text),
        "text": text,
        "source_id": source_id,
        "source_item_id": item_id,
        "source_revision": revision,
        "split": "private_test",
        "language": "en",
        "labels": labels,
        "severity": severity,
        "annotation_confidence": 1.0,
        "template_family": template_family,
        "semantic_cluster_id": None,
        "conversation_id": None,
        "transformation_parent_id": None,
        "transformations": [],
        "context": "benign" if labels == ["benign"] else "malicious",
        "license_spdx": license_spdx,
        "annotation_notes": notes,
        "training_eligible": False,
        "holdout": True,
    }


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def normalize_jailbreakbench(root: Path, revision: str, license_spdx: str, dropped: Counter) -> Iterator[dict]:
    for filename, benign in (("harmful-behaviors.csv", False), ("benign-behaviors.csv", True)):
        for row in read_csv(root / "data" / filename):
            category = row["Category"]
            if benign:
                labels = ["benign"]
            else:
                labels = JBB_CATEGORY_LABELS.get(category)
                if not labels:
                    dropped[f"jailbreakbench:unmapped_category:{category}"] += 1
                    continue
            slice_name = "benign" if benign else "harmful"
            yield make_record(
                source_id="jailbreakbench", revision=revision,
                item_id=f"{slice_name}-{row['Index']}", text=row["Goal"], labels=labels,
                license_spdx=license_spdx,
                notes=f"slice={slice_name};publisher_category={category};behavior={row['Behavior']};publisher_source={row['Source']}",
                template_family=f"jbb_{slice_name}_{category}",
            )


def normalize_harmbench(root: Path, revision: str, license_spdx: str, dropped: Counter) -> Iterator[dict]:
    path = root / "data" / "behavior_datasets" / "harmbench_behaviors_text_all.csv"
    for row in read_csv(path):
        labels = HARMBENCH_CATEGORY_LABELS.get(row["SemanticCategory"])
        if not labels:
            dropped[f"harmbench:unmapped_category:{row['SemanticCategory']}"] += 1
            continue
        # `contextual` behaviours ship a separate ContextString the attack refers
        # to. The prompt-side classifier scores one text, so only the behaviour
        # itself is scored and the omission is recorded rather than concatenated.
        yield make_record(
            source_id="harmbench", revision=revision,
            item_id=row["BehaviorID"], text=row["Behavior"], labels=labels,
            license_spdx=license_spdx,
            notes=(
                f"publisher_category={row['SemanticCategory']};"
                f"functional_category={row['FunctionalCategory']};"
                f"context_string_omitted={bool(row['ContextString'])}"
            ),
            template_family=f"harmbench_{row['SemanticCategory']}",
        )


def normalize_strongreject(root: Path, revision: str, license_spdx: str, dropped: Counter) -> Iterator[dict]:
    path = root / "strongreject_dataset" / "strongreject_dataset.csv"
    for index, row in enumerate(read_csv(path)):
        # All six StrongREJECT categories are harmful-request categories. The set
        # has no declared cyber sub-slice, so none is invented here.
        yield make_record(
            source_id="strongreject", revision=revision,
            item_id=f"row-{index}", text=row["forbidden_prompt"], labels=["toxicity_harm"],
            license_spdx=license_spdx,
            notes=f"publisher_category={row['category']};publisher_source={row['source']}",
            template_family=f"strongreject_{row['category']}",
        )


def normalize_cyberseceval(root: Path, revision: str, license_spdx: str, dropped: Counter) -> Iterator[dict]:
    base = root / "CybersecurityBenchmarks" / "datasets"
    mitre = json.loads((base / "mitre" / "mitre_benchmark_100_per_category_with_augmentation.json").read_text(encoding="utf-8"))
    for index, row in enumerate(mitre):
        ttp = row.get("ttp_id_name_mapping") or {}
        yield make_record(
            source_id="cyberseceval_mitre", revision=revision,
            item_id=f"mitre-{index}", text=row["mutated_prompt"], labels=["malicious_code"],
            license_spdx=license_spdx,
            notes=(
                f"publisher_category={row['mitre_category']};"
                f"ttp_id={ttp.get('TTP_ID')};ttp_name={ttp.get('TTP_Name')}"
            ),
            template_family=f"cyberseceval_mitre_{row['mitre_category']}",
        )

    injection = json.loads((base / "prompt_injection" / "prompt_injection.json").read_text(encoding="utf-8"))
    for row in injection:
        if row.get("speaking_language") != "English":
            dropped["cyberseceval_injection:non_english"] += 1
            continue
        labels = ["prompt_injection"]
        if row["injection_variant"] in OBFUSCATION_VARIANTS:
            labels.append("adversarial_obfuscation")
        yield make_record(
            source_id="cyberseceval_injection", revision=revision,
            item_id=f"injection-{row['prompt_id']}", text=row["user_input"], labels=labels,
            license_spdx=license_spdx,
            notes=(
                f"injection_variant={row['injection_variant']};"
                f"injection_type={row['injection_type']};"
                f"risk_category={row['risk_category']};"
                "system_prompt_omitted=true"
            ),
            template_family=f"cyberseceval_injection_{row['injection_variant']}",
        )


NORMALIZERS = {
    "jailbreakbench": normalize_jailbreakbench,
    "harmbench": normalize_harmbench,
    "strongreject": normalize_strongreject,
    "cyberseceval": normalize_cyberseceval,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    dropped: Counter = Counter()
    records: list[dict[str, Any]] = []
    for source in manifest["sources"]:
        normalizer = NORMALIZERS.get(source["id"])
        if normalizer is None:
            raise NormalizationError(f"no normalizer for acquired source: {source['id']}")
        root = args.raw_root / source["id"] / source["revision"]
        records.extend(normalizer(root, source["revision"], source["license_spdx"], dropped))

    seen: dict[str, dict] = {}
    duplicates = 0
    for record in records:
        if record["record_id"] in seen:
            duplicates += 1
            continue
        seen[record["record_id"]] = record
    records = sorted(seen.values(), key=lambda row: row["record_id"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    report = {
        "report_version": "0.1.0",
        "acquisition_manifest": project_relative(args.manifest),
        "output": project_relative(args.output),
        "rows": len(records),
        "exact_duplicate_rows_collapsed": duplicates,
        "rows_by_source": dict(sorted(Counter(row["source_id"] for row in records).items())),
        "label_occurrences": dict(sorted(Counter(l for row in records for l in row["labels"]).items())),
        "rows_dropped": dict(sorted(dropped.items())),
        "labelling_policy": "publisher-declared category fields only; no text-derived labels",
        "training_eligible": False,
        "status": "normalized_pending_contamination_scan",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
