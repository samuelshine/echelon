#!/usr/bin/env python3
"""
prepare_data.py — Merge, deduplicate, and split raw datasets for training.

Reads all CSVs from data/raw/<source>/, merges them, removes duplicates,
and creates stratified train/val/test splits in data/processed/.
"""

import os
import glob
import logging

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

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
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")


def load_all_raw_csvs() -> pd.DataFrame:
    """Recursively load all CSVs from data/raw/ and combine them."""
    csv_files = glob.glob(os.path.join(RAW_DIR, "**", "*.csv"), recursive=True)
    # Exclude anything inside a git clone (nested repo artefacts)
    csv_files = [f for f in csv_files
                 if "prompt-injection-datasets" not in f.split(os.sep)
                 or f.endswith("combined.csv")]

    log.info(f"Found {len(csv_files)} CSV file(s) in {RAW_DIR}")

    frames = []
    for csv_path in csv_files:
        try:
            df = pd.read_csv(csv_path)
            if "text" in df.columns and "label" in df.columns:
                df = df[["text", "label"]].copy()
                frames.append(df)
                source_name = os.path.relpath(csv_path, RAW_DIR)
                log.info(f"  ✓ {source_name}: {len(df):,} rows")
            else:
                log.warning(f"  ✗ {csv_path}: missing text/label columns "
                            f"(has {list(df.columns)})")
        except Exception as e:
            log.warning(f"  ✗ {csv_path}: {e}")

    if not frames:
        raise RuntimeError("No valid CSV files found in data/raw/. "
                           "Run download_data.py first.")

    combined = pd.concat(frames, ignore_index=True)
    log.info(f"\nCombined total: {len(combined):,} rows")
    return combined


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and deduplicate the combined dataset."""
    initial_count = len(df)

    # Drop nulls
    df = df.dropna(subset=["text", "label"]).copy()
    log.info(f"  After dropping nulls: {len(df):,} "
             f"(removed {initial_count - len(df):,})")

    # Convert types
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)

    # Remove empty texts
    pre = len(df)
    df = df[df["text"].str.len() > 0]
    log.info(f"  After removing empty texts: {len(df):,} "
             f"(removed {pre - len(df):,})")

    # Remove very short texts (< 5 chars — likely noise)
    pre = len(df)
    df = df[df["text"].str.len() >= 5]
    log.info(f"  After removing short texts (<5 chars): {len(df):,} "
             f"(removed {pre - len(df):,})")

    # Deduplicate on normalised text
    pre = len(df)
    df["_text_normalised"] = df["text"].str.lower().str.strip()
    df = df.drop_duplicates(subset=["_text_normalised"], keep="first")
    df = df.drop(columns=["_text_normalised"])
    log.info(f"  After deduplication: {len(df):,} "
             f"(removed {pre - len(df):,} dupes)")

    # Validate labels are 0 or 1
    valid_mask = df["label"].isin([0, 1])
    invalid_count = (~valid_mask).sum()
    if invalid_count > 0:
        log.warning(f"  Removing {invalid_count} rows with invalid labels")
        df = df[valid_mask]

    return df.reset_index(drop=True)


def split_data(df: pd.DataFrame,
               train_ratio: float = 0.80,
               val_ratio: float = 0.10,
               test_ratio: float = 0.10,
               seed: int = 42) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Stratified split into train / val / test.
    Default: 80% / 10% / 10%.
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6

    # First split: train vs. (val + test)
    train_df, temp_df = train_test_split(
        df,
        test_size=(val_ratio + test_ratio),
        stratify=df["label"],
        random_state=seed,
    )

    # Second split: val vs. test (50/50 of the temp set)
    relative_test_ratio = test_ratio / (val_ratio + test_ratio)
    val_df, test_df = train_test_split(
        temp_df,
        test_size=relative_test_ratio,
        stratify=temp_df["label"],
        random_state=seed,
    )

    return (
        train_df.reset_index(drop=True),
        val_df.reset_index(drop=True),
        test_df.reset_index(drop=True),
    )


def log_statistics(name: str, df: pd.DataFrame) -> None:
    """Print per-class statistics for a split."""
    total = len(df)
    benign = (df["label"] == 0).sum()
    injection = (df["label"] == 1).sum()
    balance = injection / total * 100 if total > 0 else 0

    log.info(f"  {name:>8s}: {total:>6,} total  |  "
             f"benign={benign:>6,}  injection={injection:>6,}  |  "
             f"injection%={balance:.1f}%")


def main() -> None:
    log.info("=" * 60)
    log.info("Data Preparation Pipeline")
    log.info("=" * 60)

    # 1. Load
    log.info("\n[1/3] Loading raw CSVs …")
    combined = load_all_raw_csvs()

    # 2. Clean
    log.info("\n[2/3] Cleaning data …")
    cleaned = clean_data(combined)

    # 3. Split
    log.info("\n[3/3] Stratified splitting (80/10/10) …")
    train_df, val_df, test_df = split_data(cleaned)

    # Statistics
    log.info("\n" + "─" * 50)
    log.info("Final Dataset Statistics:")
    log.info("─" * 50)
    log_statistics("train", train_df)
    log_statistics("val", val_df)
    log_statistics("test", test_df)
    log_statistics("TOTAL", cleaned)

    # Save
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    train_path = os.path.join(PROCESSED_DIR, "train.csv")
    val_path = os.path.join(PROCESSED_DIR, "val.csv")
    test_path = os.path.join(PROCESSED_DIR, "test.csv")

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    log.info(f"\n✓ Saved to {PROCESSED_DIR}/")
    log.info(f"  train.csv  → {train_path}")
    log.info(f"  val.csv    → {val_path}")
    log.info(f"  test.csv   → {test_path}")
    log.info("\n" + "=" * 60)
    log.info("Data preparation complete.")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
