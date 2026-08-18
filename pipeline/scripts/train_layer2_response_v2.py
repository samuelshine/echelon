#!/usr/bin/env python3
"""Retrain the egress response model with ordinary assistant output in the benign class.

The served response model treats ordinary assistant output as toxic: 0.687 on a
145-word order-status reply, 0.859 on an eight-word one, against 0.011 for a short
refusal. Register, not length. The cause is visible in the corpus -- its benign
class was 100% WildGuardMix, whose benign rows are answers to *adversarial*
prompts, so the model learned that a benign response sounds like a refusal.

`evaluate_benign_response_goldset.py` established that no threshold fixes it: to
keep ordinary output quiet you must raise the egress judge threshold to ~0.70,
which stops reviewing a fifth of genuinely toxic responses. Egress has no safety
net -- content below the threshold is delivered unreviewed -- so that is a real
regression, not a trade. Hence data.

This trains the same architecture and hyperparameters as the served model on the
v2 corpus, which adds 5,987 oasst1 assistant replies (Apache-2.0, safety-filtered)
as benign controls. Two labels only: toxicity_harm and malicious_code. The other
three categories are input-framed and meaningless about model output.

Usage:
  SPLIT_ROOT=data/splits_response_v2 \
  OUTPUT_DIR=models/layer2-response-distilbert/v2-candidate \
  python -m scripts.train_layer2_response_v2
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

from scripts.build_semantic_splits import load_jsonl

CATEGORIES = ["toxicity_harm", "malicious_code"]
CAT_INDEX = {c: i for i, c in enumerate(CATEGORIES)}


def _path_env(name: str, default: Path) -> Path:
    override = os.environ.get(name)
    if not override:
        return default
    path = Path(override)
    return path if path.is_absolute() else (PROJECT_ROOT / path)


SPLIT_ROOT = _path_env("SPLIT_ROOT", PROJECT_ROOT / "data" / "splits_response_v2")
OUTPUT_DIR = _path_env("OUTPUT_DIR", PROJECT_ROOT / "models" / "layer2-response-distilbert" / "v2-candidate")
METRICS_PATH = _path_env("METRICS_PATH", PROJECT_ROOT / "models" / "layer2-response-distilbert" / "metrics_v2.json")
BASE_MODEL = "distilbert-base-uncased"
MAX_LEN, BATCH, EPOCHS, LR, SEED = 256, 16, 3, 3e-5, 42
ORDINARY_REGISTER_SOURCE = "oasst1_benign_response"


def multi_hot(labels: list[str]) -> np.ndarray:
    vec = np.zeros(len(CATEGORIES), dtype=np.float32)
    for label in labels:
        if label in CAT_INDEX:
            vec[CAT_INDEX[label]] = 1.0
    return vec


class ResponseDataset(Dataset):
    def __init__(self, rows, tokenizer):
        self.texts = [r["text"] for r in rows]
        self.labels = np.stack([multi_hot(r["labels"]) for r in rows])
        self.tok = tokenizer

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, i):
        enc = self.tok(self.texts[i], truncation=True, max_length=MAX_LEN,
                       padding="max_length", return_tensors="pt")
        return {"input_ids": enc["input_ids"][0],
                "attention_mask": enc["attention_mask"][0],
                "labels": torch.from_numpy(self.labels[i])}


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
    for c in range(len(CATEGORIES)):
        z, y = logits[:, c], labels[:, c]
        best_t, best_loss = 1.0, float("inf")
        for t in np.arange(0.25, 5.01, 0.05):
            p = np.clip(1.0 / (1.0 + np.exp(-z / t)), 1e-7, 1 - 1e-7)
            loss = -np.mean(y * np.log(p) + (1 - y) * np.log(1 - p))
            if loss < best_loss:
                best_loss, best_t = loss, float(t)
        temps[c] = best_t
    return temps


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def metrics_at(probs, labels, sources):
    out = {"per_category": {}}
    macro = []
    for c, cat in enumerate(CATEGORIES):
        p, y = probs[:, c], labels[:, c]
        pred = (p >= 0.5).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        macro.append(f1)
        out["per_category"][cat] = {
            "support": int(y.sum()), "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "brier": round(float(np.mean((p - y) ** 2)), 4)}
    out["macro_f1"] = round(float(np.mean(macro)), 4)

    benign = labels.sum(axis=1) == 0
    agg = probs.max(axis=1)
    out["benign_rows"] = int(benign.sum())
    out["benign_toxicity_mean"] = round(float(probs[benign, CAT_INDEX["toxicity_harm"]].mean()), 4) if benign.any() else None
    # The slice this retrain exists for: ordinary assistant output, which the
    # previous corpus contained none of.
    ordinary = np.array([s == ORDINARY_REGISTER_SOURCE for s in sources]) & benign
    out["ordinary_register_rows"] = int(ordinary.sum())
    out["ordinary_register_toxicity_mean"] = round(float(probs[ordinary, CAT_INDEX["toxicity_harm"]].mean()), 4) if ordinary.any() else None
    out["ordinary_register_fpr_at_0.5"] = round(float((agg[ordinary] >= 0.5).mean()), 4) if ordinary.any() else None
    refusal = np.array([s != ORDINARY_REGISTER_SOURCE for s in sources]) & benign
    out["refusal_register_toxicity_mean"] = round(float(probs[refusal, CAT_INDEX["toxicity_harm"]].mean()), 4) if refusal.any() else None
    return out


def main() -> int:
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    print(f"device={device}")

    train_rows = load_jsonl(SPLIT_ROOT / "train.jsonl")
    val_rows = load_jsonl(SPLIT_ROOT / "validation.jsonl")
    test_rows = load_jsonl(SPLIT_ROOT / "test.jsonl")

    smoke = int(os.environ.get("SMOKE", "0"))
    if smoke:
        global EPOCHS
        EPOCHS = 1
        train_rows, val_rows, test_rows = train_rows[:smoke], val_rows[:smoke], test_rows[:smoke]
        print(f"SMOKE mode: {smoke} rows/split, 1 epoch")

    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL, num_labels=len(CATEGORIES),
        problem_type="multi_label_classification",
        id2label={i: c for i, c in enumerate(CATEGORIES)}, label2id=CAT_INDEX,
    ).to(device)

    train_ds, val_ds, test_ds = (ResponseDataset(r, tokenizer) for r in (train_rows, val_rows, test_rows))
    train_loader = DataLoader(train_ds, batch_size=BATCH, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH)
    test_loader = DataLoader(test_ds, batch_size=BATCH)

    pos = train_ds.labels.sum(axis=0)
    neg = len(train_ds) - pos
    pos_weight = torch.tensor(np.clip(neg / np.clip(pos, 1, None), 1.0, 30.0), dtype=torch.float32).to(device)
    print("supports:", {c: int(pos[i]) for i, c in enumerate(CATEGORIES)})
    loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optim = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)

    val_sources = [r.get("source_id", "") for r in val_rows]
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
            if step % 300 == 0:
                print(f"  epoch {epoch} step {step}/{len(train_loader)} loss {running/step:.4f}", flush=True)
        vlog, vlab = collect_logits(model, val_loader, device)
        temps = fit_temperatures(vlog, vlab)
        vm = metrics_at(sigmoid(vlog / temps), vlab, val_sources)
        print(f"epoch {epoch} done in {time.time()-t0:.0f}s | val macro_f1={vm['macro_f1']} "
              f"ordinary_tox={vm['ordinary_register_toxicity_mean']} "
              f"refusal_tox={vm['refusal_register_toxicity_mean']}", flush=True)
        if vm["macro_f1"] > best_macro:
            best_macro, best_temps = vm["macro_f1"], temps
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    model.load_state_dict(best_state)
    tlog, tlab = collect_logits(model, test_loader, device)
    test_metrics = metrics_at(sigmoid(tlog / best_temps), tlab,
                              [r.get("source_id", "") for r in test_rows])

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    (OUTPUT_DIR / "calibration.json").write_text(json.dumps({
        "categories": CATEGORIES,
        "temperatures": {c: float(best_temps[i]) for i, c in enumerate(CATEGORIES)},
        "method": "per_category_temperature_scaling"}, indent=2) + "\n")

    report = {
        "base_model": BASE_MODEL, "categories": CATEGORIES, "device": device,
        "max_length": MAX_LEN, "batch_size": BATCH, "epochs": EPOCHS, "lr": LR, "seed": SEED,
        "split_root": str(SPLIT_ROOT.relative_to(PROJECT_ROOT)),
        "rows": {"train": len(train_ds), "validation": len(val_ds), "test": len(test_ds)},
        "best_val_macro_f1": round(best_macro, 4),
        "calibration_temperatures": {c: round(float(best_temps[i]), 3) for i, c in enumerate(CATEGORIES)},
        "test": test_metrics,
        "purpose": (
            "adds oasst1 ordinary assistant output to a benign class that was 100% "
            "WildGuard refusal-shaped safety prose; see "
            "scripts/normalize_oasst_benign_responses.py"),
    }
    METRICS_PATH.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
