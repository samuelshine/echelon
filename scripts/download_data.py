#!/usr/bin/env python3
"""
download_data.py — Download prompt injection datasets from multiple sources.

Datasets:
  1. deepset/prompt-injections          (HuggingFace)
  2. neuralchemy/Prompt-injection-dataset (HuggingFace, "full" config)
  3. rossja/prompt-injection-datasets   (GitHub repo)

Each dataset is normalised to { text, label } and saved as CSV in data/raw/<source>/.
Label convention: 1 = injection/malicious, 0 = benign.
"""

import os
import sys
import subprocess
import glob
import logging

import pandas as pd

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
RAW_DIR = os.path.join(PROJECT_ROOT, "data", "raw")


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ===================================================================
# 1. deepset/prompt-injections
# ===================================================================
def download_deepset() -> None:
    """Download the deepset/prompt-injections dataset from HuggingFace."""
    log.info("=" * 60)
    log.info("Downloading deepset/prompt-injections …")
    log.info("=" * 60)

    from datasets import load_dataset

    dest = os.path.join(RAW_DIR, "deepset")
    ensure_dir(dest)

    ds = load_dataset("deepset/prompt-injections")

    for split_name in ds:
        df = ds[split_name].to_pandas()
        # Schema: text, label (0=benign, 1=injection) — matches our convention
        df = df[["text", "label"]].copy()
        df["label"] = df["label"].astype(int)
        out_path = os.path.join(dest, f"{split_name}.csv")
        df.to_csv(out_path, index=False)
        log.info(f"  [{split_name}] {len(df):,} rows → {out_path}")

    log.info("✓ deepset download complete.\n")


# ===================================================================
# 2. neuralchemy/Prompt-injection-dataset
# ===================================================================
def download_neuralchemy() -> None:
    """Download the neuralchemy/Prompt-injection-dataset (full config)."""
    log.info("=" * 60)
    log.info("Downloading neuralchemy/Prompt-injection-dataset …")
    log.info("=" * 60)

    from datasets import load_dataset

    dest = os.path.join(RAW_DIR, "neuralchemy")
    ensure_dir(dest)

    ds = load_dataset("neuralchemy/Prompt-injection-dataset", "full")

    for split_name in ds:
        df = ds[split_name].to_pandas()
        # Schema: text, label (0=benign, 1=injection), + extras
        df = df[["text", "label"]].copy()
        df["label"] = df["label"].astype(int)
        out_path = os.path.join(dest, f"{split_name}.csv")
        df.to_csv(out_path, index=False)
        log.info(f"  [{split_name}] {len(df):,} rows → {out_path}")

    log.info("✓ neuralchemy download complete.\n")


# ===================================================================
# 3. Additional HuggingFace datasets (referenced by rossja index)
# ===================================================================
def download_additional_hf() -> None:
    """
    Download additional prompt injection / jailbreak datasets from HuggingFace.
    These are sourced from the rossja/prompt-injection-datasets index.
    """
    log.info("=" * 60)
    log.info("Downloading additional HuggingFace datasets …")
    log.info("=" * 60)

    from datasets import load_dataset

    dest = os.path.join(RAW_DIR, "github")
    ensure_dir(dest)

    # ── JasperLS/prompt-injections ──
    try:
        log.info("\n  [a] JasperLS/prompt-injections")
        ds = load_dataset("JasperLS/prompt-injections")
        for split_name in ds:
            df = ds[split_name].to_pandas()
            text_col = None
            for c in ["text", "prompt", "content"]:
                if c in df.columns:
                    text_col = c
                    break
            if text_col and "label" in df.columns:
                df = df[[text_col, "label"]].copy()
                df.columns = ["text", "label"]
                df["label"] = df["label"].astype(int)
                out = os.path.join(dest, f"jasperls_{split_name}.csv")
                df.to_csv(out, index=False)
                log.info(f"      [{split_name}] {len(df):,} rows → {out}")
            else:
                log.warning(f"      [{split_name}] no usable text/label columns: "
                            f"{list(df.columns)}")
    except Exception as e:
        log.warning(f"  ✗ JasperLS/prompt-injections failed: {e}")

    # ── imoxto/prompt_injection_cleaned_dataset-v2 ──
    try:
        log.info("\n  [b] imoxto/prompt_injection_cleaned_dataset-v2")
        ds = load_dataset("imoxto/prompt_injection_cleaned_dataset-v2")
        for split_name in ds:
            df = ds[split_name].to_pandas()
            text_col = None
            for c in ["text", "prompt", "content"]:
                if c in df.columns:
                    text_col = c
                    break
            label_col = None
            for c in ["label", "labels", "is_injection", "class"]:
                if c in df.columns:
                    label_col = c
                    break
            if text_col and label_col:
                df = df[[text_col, label_col]].copy()
                df.columns = ["text", "label"]
                df = _normalise_labels(df)
                if df is not None and len(df) > 0:
                    out = os.path.join(dest, f"imoxto_v2_{split_name}.csv")
                    df.to_csv(out, index=False)
                    log.info(f"      [{split_name}] {len(df):,} rows → {out}")
            else:
                log.warning(f"      [{split_name}] no usable columns: "
                            f"{list(df.columns)}")
    except Exception as e:
        log.warning(f"  ✗ imoxto/prompt_injection_cleaned_dataset-v2 failed: {e}")

    # ── jackhhao/jailbreak-classification ──
    try:
        log.info("\n  [c] jackhhao/jailbreak-classification")
        ds = load_dataset("jackhhao/jailbreak-classification")
        for split_name in ds:
            df = ds[split_name].to_pandas()
            text_col = None
            for c in ["prompt", "text", "content"]:
                if c in df.columns:
                    text_col = c
                    break
            label_col = None
            for c in ["type", "label", "is_jailbreak", "class"]:
                if c in df.columns:
                    label_col = c
                    break
            if text_col and label_col:
                df = df[[text_col, label_col]].copy()
                df.columns = ["text", "label"]
                df = _normalise_labels(df)
                if df is not None and len(df) > 0:
                    out = os.path.join(dest, f"jackhhao_{split_name}.csv")
                    df.to_csv(out, index=False)
                    log.info(f"      [{split_name}] {len(df):,} rows → {out}")
            else:
                log.warning(f"      [{split_name}] no usable columns: "
                            f"{list(df.columns)}")
    except Exception as e:
        log.warning(f"  ✗ jackhhao/jailbreak-classification failed: {e}")

    log.info("\n✓ Additional HF downloads complete.\n")


def _normalise_labels(df: pd.DataFrame) -> pd.DataFrame | None:
    """
    Convert label column to int 0/1.
    Handles: int 0/1, string "injection"/"benign", bool, etc.
    """
    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str).str.strip()
    df = df[df["text"].str.len() > 0]

    # If already numeric
    try:
        df["label"] = pd.to_numeric(df["label"], errors="raise")
        unique = set(df["label"].unique())
        if unique.issubset({0, 1, 0.0, 1.0}):
            df["label"] = df["label"].astype(int)
            return df
    except (ValueError, TypeError):
        pass

    # String-based label mapping
    label_str = df["label"].astype(str).str.strip().str.lower()
    injection_keywords = {"1", "injection", "malicious", "jailbreak", "attack",
                          "true", "yes", "prompt_injection", "positive"}
    benign_keywords = {"0", "benign", "safe", "clean", "normal", "false",
                       "no", "legitimate", "negative"}

    def map_label(val: str) -> int | None:
        if val in injection_keywords:
            return 1
        if val in benign_keywords:
            return 0
        return None

    df["label"] = label_str.apply(map_label)
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    return df if len(df) > 0 else None


# ===================================================================
# Main
# ===================================================================
def main() -> None:
    log.info("Starting dataset downloads …\n")
    ensure_dir(RAW_DIR)

    download_deepset()
    download_neuralchemy()
    download_additional_hf()

    log.info("=" * 60)
    log.info("All downloads complete.")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
