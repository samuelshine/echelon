#!/usr/bin/env python3
"""Train + calibrate the v0.3 Layer 2 multi-label classifier candidate.

Forked from scripts/train_layer2_multilabel.py: points at the v0.3 manifest/
splits and writes to a *candidate* output directory (models/layer2-threat-
distilbert/v03-candidate), never overwriting the currently-served `best/`
model in place -- promotion is a separate, explicit step after the candidate's
metrics are reviewed.
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from echelon.training_data import validate_split_rows
from echelon.training_gate import validate_training_manifest
from scripts.build_semantic_splits import load_jsonl

# The five prompt-side heads by default. A response-side round overrides this
# with the two categories that are meaningful on assistant output; training the
# full five on response data would recreate the zero-support defect that made
# malicious_code's temperature meaningless in v0.3 (a head with no positives
# contributes a constant 0 to model selection and is calibrated on negatives).
CATEGORIES = [c for c in os.environ.get(
    "CATEGORIES",
    "prompt_injection,system_prompt_leakage,malicious_code,toxicity_harm,adversarial_obfuscation",
).split(",") if c]
CAT_INDEX = {c: i for i, c in enumerate(CATEGORIES)}


def _path_env(name: str, default: Path) -> Path:
    """Env override for a path constant; defaults reproduce the promoted run exactly.

    Relative overrides resolve against PROJECT_ROOT, not the caller's cwd.
    """
    override = os.environ.get(name)
    if not override:
        return default
    path = Path(override)
    return path if path.is_absolute() else (PROJECT_ROOT / path)


MANIFEST = _path_env("MANIFEST", PROJECT_ROOT / "data" / "manifests" / "layer2_training_manifest_v03.json")
SPLIT_ROOT = _path_env("SPLIT_ROOT", PROJECT_ROOT / "data" / "splits_v2_v03")
OUTPUT_DIR = _path_env("OUTPUT_DIR", PROJECT_ROOT / "models" / "layer2-threat-distilbert" / "v03-candidate")
METRICS_PATH = _path_env("METRICS_PATH", PROJECT_ROOT / "models" / "layer2-threat-distilbert" / "metrics_v03.json")
BASE_MODEL = "distilbert-base-uncased"
MAX_LEN = 256
BATCH = 16
EPOCHS = 3
LR = 3e-5
SEED = 42
DEFENSIVE_SOURCE_IDS = {"echelon_targeted_v0_2", "echelon_targeted_v0_3"}


def multi_hot(labels: list[str]) -> np.ndarray:
    vec = np.zeros(len(CATEGORIES), dtype=np.float32)
    for label in labels:
        if label in CAT_INDEX:
            vec[CAT_INDEX[label]] = 1.0
    return vec


class PromptDataset(Dataset):
    def __init__(self, rows, tokenizer):
        self.texts = [r["text"] for r in rows]
        self.labels = np.stack([multi_hot(r["labels"]) for r in rows])
        self.tok = tokenizer

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, i):
        enc = self.tok(self.texts[i], truncation=True, max_length=MAX_LEN,
                       padding="max_length", return_tensors="pt")
        return {
            "input_ids": enc["input_ids"][0],
            "attention_mask": enc["attention_mask"][0],
            "labels": torch.from_numpy(self.labels[i]),
        }


@torch.inference_mode()
def collect_logits(model, loader, device):
    model.eval()
    logits, labels = [], []
    for batch in loader:
        out = model(input_ids=batch["input_ids"].to(device),
                    attention_mask=batch["attention_mask"].to(device))
        logits.append(out.logits.float().cpu().numpy())
        labels.append(batch["labels"].numpy())
    return np.concatenate(logits), np.concatenate(labels)


def fit_temperatures(logits, labels):
    temps = np.ones(len(CATEGORIES), dtype=np.float32)
    grid = np.arange(0.25, 5.01, 0.05)
    for c in range(len(CATEGORIES)):
        z, y = logits[:, c], labels[:, c]
        best_t, best_loss = 1.0, float("inf")
        for t in grid:
            p = 1.0 / (1.0 + np.exp(-z / t))
            p = np.clip(p, 1e-7, 1 - 1e-7)
            loss = -np.mean(y * np.log(p) + (1 - y) * np.log(1 - p))
            if loss < best_loss:
                best_loss, best_t = loss, float(t)
        temps[c] = best_t
    return temps


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def metrics_at(probs, labels, source_ids, families):
    out = {"per_category": {}}
    macro_f1 = []
    for c, cat in enumerate(CATEGORIES):
        p, y = probs[:, c], labels[:, c]
        pred = (p >= 0.5).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        brier = float(np.mean((p - y) ** 2))
        macro_f1.append(f1)
        out["per_category"][cat] = {
            "support": int(y.sum()), "precision": round(prec, 4),
            "recall": round(rec, 4), "f1": round(f1, 4), "brier": round(brier, 4),
        }
    out["macro_f1"] = round(float(np.mean(macro_f1)), 4)
    agg = probs.max(axis=1)
    benign_true = labels.sum(axis=1) == 0
    out["benign_rows"] = int(benign_true.sum())
    out["benign_fpr_at_0.5"] = round(float((agg[benign_true] >= 0.5).mean()), 4) if benign_true.any() else None
    out["benign_fpr_at_0.9"] = round(float((agg[benign_true] >= 0.9).mean()), 4) if benign_true.any() else None
    defensive = np.array([
        s in DEFENSIVE_SOURCE_IDS and str(f).startswith("defensive_cyber")
        for s, f in zip(source_ids, families)
    ])
    dslice = defensive & benign_true
    out["defensive_cyber_slice_rows"] = int(dslice.sum())
    out["defensive_cyber_fpr_at_0.5"] = round(float((agg[dslice] >= 0.5).mean()), 4) if dslice.any() else None
    # v0.3-specific matched control: code-targeted defensive twin (distinct from
    # the general defensive_cyber slice above).
    matched = np.array([
        s == "echelon_targeted_v0_3" and str(f).startswith("malicious_code_defensive_control")
        for s, f in zip(source_ids, families)
    ])
    mslice = matched & benign_true
    out["malicious_code_matched_control_rows"] = int(mslice.sum())
    out["malicious_code_matched_control_fpr_at_0.5"] = round(float((agg[mslice] >= 0.5).mean()), 4) if mslice.any() else None
    return out


def main() -> int:
    validate_training_manifest(MANIFEST)
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    print(f"device={device}")

    train_rows = load_jsonl(SPLIT_ROOT / "train.jsonl")
    val_rows = load_jsonl(SPLIT_ROOT / "validation.jsonl")
    test_rows = load_jsonl(SPLIT_ROOT / "test.jsonl")
    validate_split_rows(train_rows + val_rows + test_rows)

    smoke = int(os.environ.get("SMOKE", "0"))
    if smoke:
        global EPOCHS
        EPOCHS = 1
        train_rows, val_rows, test_rows = train_rows[:smoke], val_rows[:smoke], test_rows[:smoke]
        print(f"SMOKE mode: {smoke} rows/split, 1 epoch")

    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL, num_labels=len(CATEGORIES), problem_type="multi_label_classification",
        id2label={i: c for i, c in enumerate(CATEGORIES)},
        label2id=CAT_INDEX,
    ).to(device)

    train_ds = PromptDataset(train_rows, tokenizer)
    val_ds = PromptDataset(val_rows, tokenizer)
    test_ds = PromptDataset(test_rows, tokenizer)
    train_loader = DataLoader(train_ds, batch_size=BATCH, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH)
    test_loader = DataLoader(test_ds, batch_size=BATCH)

    pos = train_ds.labels.sum(axis=0)
    neg = len(train_ds) - pos
    pos_weight = torch.tensor(np.clip(neg / np.clip(pos, 1, None), 1.0, 30.0), dtype=torch.float32).to(device)
    print("supports:", {c: int(pos[i]) for i, c in enumerate(CATEGORIES)})
    loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optim = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)

    best_macro, best_state, best_temps = -1.0, None, None
    for epoch in range(1, EPOCHS + 1):
        model.train(); t0 = time.time(); running = 0.0
        for step, batch in enumerate(train_loader, 1):
            optim.zero_grad()
            out = model(input_ids=batch["input_ids"].to(device),
                        attention_mask=batch["attention_mask"].to(device))
            loss = loss_fn(out.logits, batch["labels"].to(device))
            loss.backward(); optim.step()
            running += loss.item()
            if step % 200 == 0:
                print(f"  epoch {epoch} step {step}/{len(train_loader)} loss {running/step:.4f}", flush=True)
        vlog, vlab = collect_logits(model, val_loader, device)
        temps = fit_temperatures(vlog, vlab)
        vprob = sigmoid(vlog / temps)
        vmeta = [(r["source_id"], r.get("template_family")) for r in val_rows]
        vm = metrics_at(vprob, vlab, [m[0] for m in vmeta], [m[1] for m in vmeta])
        print(f"epoch {epoch} done in {time.time()-t0:.0f}s | val macro_f1={vm['macro_f1']} temps={np.round(temps,2).tolist()}", flush=True)
        if vm["macro_f1"] > best_macro:
            best_macro = vm["macro_f1"]
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            best_temps = temps

    model.load_state_dict(best_state)
    tlog, tlab = collect_logits(model, test_loader, device)
    tprob = sigmoid(tlog / best_temps)
    tmeta = [(r["source_id"], r.get("template_family")) for r in test_rows]
    test_metrics = metrics_at(tprob, tlab, [m[0] for m in tmeta], [m[1] for m in tmeta])

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    (OUTPUT_DIR / "calibration.json").write_text(json.dumps({
        "categories": CATEGORIES,
        "temperatures": {c: float(best_temps[i]) for i, c in enumerate(CATEGORIES)},
        "method": "per_category_temperature_scaling",
    }, indent=2) + "\n")
    report = {
        "base_model": BASE_MODEL, "categories": CATEGORIES, "device": device,
        "max_length": MAX_LEN, "batch_size": BATCH, "epochs": EPOCHS, "lr": LR, "seed": SEED,
        "dataset_sha256": validate_training_manifest(MANIFEST)["dataset_sha256"],
        "rows": {"train": len(train_ds), "validation": len(val_ds), "test": len(test_ds)},
        "best_val_macro_f1": round(best_macro, 4),
        "calibration_temperatures": {c: round(float(best_temps[i]), 3) for i, c in enumerate(CATEGORIES)},
        "test": test_metrics,
        "provenance_note": (
            "labels include AI-assisted provisional review: v0.2's 152-conflict expert "
            "adjudication, and v0.3's full-coverage AI dual review (scripts/ai_reviewers_v03.py)"
        ),
    }
    METRICS_PATH.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
