#!/usr/bin/env python3
"""
train.py — Fine-tune DistilBERT for prompt injection detection.

Uses HuggingFace Trainer with:
  • Class-weighted loss for imbalanced data
  • MPS (Apple Silicon) or CUDA acceleration
  • Early stopping on validation F1
  • Comprehensive evaluation: accuracy, F1, precision, recall,
    confusion matrix, ROC-AUC curve
"""

import os
import sys
import json
import logging
import argparse
from typing import Any

import numpy as np
import pandas as pd
import torch
import yaml
import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from echelon.training_gate import TrainingGateError, validate_training_manifest
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
)
from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback,
    TrainerCallback,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ===================================================================
# Config
# ===================================================================
def load_config(config_path: str | None = None) -> dict:
    """Load training configuration from YAML."""
    if config_path is None:
        config_path = os.path.join(PROJECT_ROOT, "configs", "training_config.yaml")

    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f)

    log.info(f"Loaded config from {config_path}")
    return cfg


# ===================================================================
# Device
# ===================================================================
def get_device() -> torch.device:
    """Determine the best available device (MPS > CUDA > CPU)."""
    if torch.backends.mps.is_available():
        device = torch.device("mps")
        log.info("🍎 Using Apple MPS (Metal Performance Shaders)")
    elif torch.cuda.is_available():
        device = torch.device("cuda")
        log.info(f"🔥 Using CUDA: {torch.cuda.get_device_name(0)}")
    else:
        device = torch.device("cpu")
        log.info("💻 Using CPU")
    return device


# ===================================================================
# Data Loading
# ===================================================================
def load_split(path: str) -> pd.DataFrame:
    """Load a CSV split."""
    df = pd.read_csv(path)
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)
    return df


def tokenize_data(df: pd.DataFrame, tokenizer, max_length: int) -> Dataset:
    """Tokenize a DataFrame and return a HuggingFace Dataset."""
    dataset = Dataset.from_pandas(df[["text", "label"]], preserve_index=False)

    def tokenize_fn(examples):
        return tokenizer(
            examples["text"],
            padding="max_length",
            truncation=True,
            max_length=max_length,
        )

    dataset = dataset.map(tokenize_fn, batched=True, batch_size=1000,
                          desc="Tokenizing")
    dataset.set_format(type="torch",
                       columns=["input_ids", "attention_mask", "label"])
    return dataset


# ===================================================================
# Class-Weighted Trainer
# ===================================================================
class WeightedTrainer(Trainer):
    """Custom Trainer that applies class weights to the loss function."""

    def __init__(self, class_weights: torch.Tensor | None = None, **kwargs):
        super().__init__(**kwargs)
        self.class_weights = class_weights

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        logits = outputs.logits

        if self.class_weights is not None:
            weight = self.class_weights.to(device=model.device, dtype=logits.dtype)
            loss_fn = torch.nn.CrossEntropyLoss(weight=weight)
        else:
            loss_fn = torch.nn.CrossEntropyLoss()

        loss = loss_fn(logits, labels)
        return (loss, outputs) if return_outputs else loss


# ===================================================================
# Metrics
# ===================================================================
def compute_metrics(eval_pred) -> dict:
    """Compute accuracy, F1, precision, recall from predictions."""
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)

    return {
        "accuracy": accuracy_score(labels, preds),
        "f1": f1_score(labels, preds, average="weighted"),
        "f1_macro": f1_score(labels, preds, average="macro"),
        "precision": precision_score(labels, preds, average="weighted",
                                     zero_division=0),
        "recall": recall_score(labels, preds, average="weighted",
                               zero_division=0),
    }


# ===================================================================
# Evaluation & Visualisation
# ===================================================================
def full_evaluation(trainer: Trainer, test_dataset: Dataset,
                    cfg: dict) -> dict:
    """Run comprehensive evaluation on the test set."""
    log.info("\n" + "=" * 60)
    log.info("Running full evaluation on test set …")
    log.info("=" * 60)

    # Predict
    predictions = trainer.predict(test_dataset)
    logits = predictions.predictions
    labels = predictions.label_ids
    preds = np.argmax(logits, axis=-1)
    probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()

    # Classification report
    report_str = classification_report(
        labels, preds,
        target_names=["benign", "injection"],
        digits=4,
    )
    log.info(f"\nClassification Report:\n{report_str}")

    # Metrics dict
    metrics = {
        "accuracy": float(accuracy_score(labels, preds)),
        "f1_weighted": float(f1_score(labels, preds, average="weighted")),
        "f1_macro": float(f1_score(labels, preds, average="macro")),
        "precision_weighted": float(precision_score(labels, preds,
                                                     average="weighted",
                                                     zero_division=0)),
        "recall_weighted": float(recall_score(labels, preds,
                                               average="weighted",
                                               zero_division=0)),
        "classification_report": report_str,
    }

    # ROC-AUC
    try:
        auc = roc_auc_score(labels, probs[:, 1])
        metrics["roc_auc"] = float(auc)
        log.info(f"ROC-AUC: {auc:.4f}")
    except Exception as e:
        log.warning(f"Could not compute ROC-AUC: {e}")
        metrics["roc_auc"] = None

    # --- Confusion Matrix Plot ---
    cm_path = os.path.join(PROJECT_ROOT, cfg["output"]["confusion_matrix_path"])
    os.makedirs(os.path.dirname(cm_path), exist_ok=True)
    plot_confusion_matrix(labels, preds, cm_path)

    # --- ROC Curve Plot ---
    roc_path = os.path.join(PROJECT_ROOT, cfg["output"]["roc_curve_path"])
    plot_roc_curve(labels, probs[:, 1], roc_path)

    # Save metrics JSON
    results_path = os.path.join(PROJECT_ROOT, cfg["output"]["results_file"])
    with open(results_path, "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    log.info(f"\n✓ Results saved to {results_path}")

    return metrics


def plot_confusion_matrix(labels, preds, save_path: str) -> None:
    """Generate and save a confusion matrix heatmap."""
    cm = confusion_matrix(labels, preds)
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Benign", "Injection"],
        yticklabels=["Benign", "Injection"],
        ax=ax,
        annot_kws={"size": 14},
    )
    ax.set_xlabel("Predicted", fontsize=13)
    ax.set_ylabel("Actual", fontsize=13)
    ax.set_title("Confusion Matrix — Prompt Injection Detection", fontsize=14)
    fig.tight_layout()
    fig.savefig(save_path, dpi=150)
    plt.close(fig)
    log.info(f"  Confusion matrix saved → {save_path}")


def plot_roc_curve(labels, probs_positive, save_path: str) -> None:
    """Generate and save an ROC curve plot."""
    try:
        fpr, tpr, _ = roc_curve(labels, probs_positive)
        auc = roc_auc_score(labels, probs_positive)

        fig, ax = plt.subplots(figsize=(8, 6))
        ax.plot(fpr, tpr, color="#2563eb", lw=2,
                label=f"ROC Curve (AUC = {auc:.4f})")
        ax.plot([0, 1], [0, 1], color="#94a3b8", lw=1, linestyle="--",
                label="Random Classifier")
        ax.fill_between(fpr, tpr, alpha=0.1, color="#2563eb")
        ax.set_xlabel("False Positive Rate", fontsize=13)
        ax.set_ylabel("True Positive Rate", fontsize=13)
        ax.set_title("ROC Curve — Prompt Injection Detection", fontsize=14)
        ax.legend(loc="lower right", fontsize=12)
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(save_path, dpi=150)
        plt.close(fig)
        log.info(f"  ROC curve saved → {save_path}")
    except Exception as e:
        log.warning(f"  Could not plot ROC curve: {e}")


# ===================================================================
# Main Training Pipeline
# ===================================================================
def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune a model for prompt injection detection.")
    parser.add_argument("--config", type=str, default="configs/training_config.yaml",
                        help="Path to the training configuration file.")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("Model Fine-Tuning — Prompt Injection Detection")
    log.info("=" * 60)

    # ── Config ──
    cfg = load_config(args.config)
    manifest_path = cfg.get("data", {}).get("training_manifest")
    if not manifest_path:
        raise SystemExit("Refusing to train: config must declare data.training_manifest")
    try:
        manifest = validate_training_manifest(PROJECT_ROOT / manifest_path)
    except TrainingGateError as exc:
        raise SystemExit(f"Refusing to train: {exc}") from exc
    log.info("Training gate passed for %s reviewed rows", manifest["rows"])
    device = get_device()

    # ── Load Data ──
    log.info("\n[1/5] Loading processed data …")
    train_df = load_split(os.path.join(PROJECT_ROOT, cfg["data"]["train_path"]))
    val_df = load_split(os.path.join(PROJECT_ROOT, cfg["data"]["val_path"]))
    test_df = load_split(os.path.join(PROJECT_ROOT, cfg["data"]["test_path"]))

    log.info(f"  Train: {len(train_df):,}  Val: {len(val_df):,}  "
             f"Test: {len(test_df):,}")

    # ── Compute class weights ──
    label_counts = train_df["label"].value_counts().sort_index()
    total = len(train_df)
    n_classes = len(label_counts)
    class_weights = torch.tensor(
        [total / (n_classes * count) for count in label_counts.values],
        dtype=torch.float32,
    )
    log.info(f"  Class weights: benign={class_weights[0]:.3f}, "
             f"injection={class_weights[1]:.3f}")

    # ── Tokenizer ──
    log.info("\n[2/5] Loading tokenizer …")
    model_name = cfg["model"]["name"]
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    max_length = cfg["tokenizer"]["max_length"]

    # ── Tokenize ──
    log.info("\n[3/5] Tokenizing datasets …")
    train_dataset = tokenize_data(train_df, tokenizer, max_length)
    val_dataset = tokenize_data(val_df, tokenizer, max_length)
    test_dataset = tokenize_data(test_df, tokenizer, max_length)

    # ── Model ──
    log.info("\n[4/5] Loading model …")
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        num_labels=cfg["model"]["num_labels"],
    )

    # Label name mapping
    model.config.id2label = {0: "benign", 1: "injection"}
    model.config.label2id = {"benign": 0, "injection": 1}

    # ── Training Arguments ──
    output_dir = os.path.join(PROJECT_ROOT,
                              cfg["output"]["checkpoint_dir"])
    best_model_dir = os.path.join(PROJECT_ROOT, cfg["output"]["model_dir"])

    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=cfg["training"]["epochs"],
        per_device_train_batch_size=cfg["training"]["batch_size"],
        per_device_eval_batch_size=cfg["training"]["batch_size"] * 2,
        learning_rate=cfg["training"]["learning_rate"],
        weight_decay=cfg["training"]["weight_decay"],
        warmup_ratio=cfg["training"]["warmup_ratio"],
        gradient_accumulation_steps=cfg["training"]["gradient_accumulation_steps"],
        fp16=False,  # MPS doesn't support fp16 via Trainer flag
        seed=cfg["training"]["seed"],
        logging_steps=cfg["training"]["logging_steps"],
        eval_strategy=cfg["evaluation"]["strategy"],
        save_strategy=cfg["evaluation"]["strategy"],
        load_best_model_at_end=True,
        metric_for_best_model=cfg["evaluation"]["metric_for_best_model"],
        greater_is_better=cfg["evaluation"]["greater_is_better"],
        save_total_limit=3,
        report_to="none",          # no WandB / MLflow
        dataloader_num_workers=0,  # MPS-safe
        remove_unused_columns=False,
    )

    # ── Callbacks ──
    class MPSClearCacheCallback(TrainerCallback):
        def on_step_end(self, args, state, control, **kwargs):
            if state.global_step % 20 == 0:
                if torch.backends.mps.is_available():
                    torch.mps.empty_cache()
    
    callbacks = [MPSClearCacheCallback()]
    if cfg["early_stopping"]["enabled"]:
        callbacks.append(
            EarlyStoppingCallback(
                early_stopping_patience=cfg["early_stopping"]["patience"]
            )
        )

    # ── Trainer ──
    log.info("\n[5/5] Starting training …\n")
    trainer = WeightedTrainer(
        class_weights=class_weights,
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=callbacks,
    )

    # Train
    train_result = trainer.train()

    # Log training results
    log.info(f"\nTraining complete!")
    log.info(f"  Total steps: {train_result.global_step}")
    log.info(f"  Training loss: {train_result.training_loss:.4f}")

    # ── Save best model ──
    log.info(f"\nSaving best model to {best_model_dir} …")
    trainer.save_model(best_model_dir)
    tokenizer.save_pretrained(best_model_dir)
    log.info("✓ Model and tokenizer saved.")

    # ── Full Evaluation ──
    metrics = full_evaluation(trainer, test_dataset, cfg)

    # ── Summary ──
    log.info("\n" + "=" * 60)
    log.info("TRAINING SUMMARY")
    log.info("=" * 60)
    log.info(f"  Accuracy:         {metrics['accuracy']:.4f}")
    log.info(f"  F1 (weighted):    {metrics['f1_weighted']:.4f}")
    log.info(f"  F1 (macro):       {metrics['f1_macro']:.4f}")
    log.info(f"  Precision:        {metrics['precision_weighted']:.4f}")
    log.info(f"  Recall:           {metrics['recall_weighted']:.4f}")
    if metrics.get("roc_auc"):
        log.info(f"  ROC-AUC:          {metrics['roc_auc']:.4f}")
    log.info(f"\n  Best model:       {best_model_dir}")
    log.info(f"  Results JSON:     {cfg['output']['results_file']}")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
