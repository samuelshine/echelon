#!/usr/bin/env python3
"""Quarantine held-out evaluation rows that overlap the training corpus.

A held-out set only breaks the in-distribution circularity if it is genuinely
disjoint from what the model saw. The benchmarks are independently sourced, but
disjoint provenance is not disjoint content: JailbreakBench's own card credits
TDC/HarmBench for part of its behaviour set, and several public jailbreak
corpora reprint the same prompts.

This scans every held-out row against the full v0.3 corpus using the same
embedding model, pinned revision, and cosine threshold the project already uses
for near-duplicate grouping (BGE-small at 0.94, per build_semantic_splits), plus
an exact normalized-text check. Contaminated rows are written to a separate
quarantine file and excluded from the clean split -- never silently dropped.

Usage:
  python -m scripts.scan_holdout_contamination \
     --holdout data/holdout_v1/holdout_eval.jsonl \
     --corpus data/normalized_v2/eligible_reviewed_v03.jsonl \
     --corpus-embeddings data/normalized_v2/eligible_reviewed_v03_embeddings.npz
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_semantic_splits import embedding_view, load_jsonl, project_relative

DEFAULT_HOLDOUT = PROJECT_ROOT / "data" / "holdout_v1" / "holdout_eval.jsonl"
DEFAULT_CORPUS = PROJECT_ROOT / "data" / "normalized_v2" / "eligible_reviewed_v03.jsonl"
DEFAULT_CORPUS_EMBEDDINGS = PROJECT_ROOT / "data" / "normalized_v2" / "eligible_reviewed_v03_embeddings.npz"
DEFAULT_CLEAN = PROJECT_ROOT / "data" / "holdout_v1" / "holdout_eval_clean.jsonl"
DEFAULT_QUARANTINE = PROJECT_ROOT / "data" / "holdout_v1" / "holdout_eval_contaminated.jsonl"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "reports" / "holdout_contamination_scan.json"
MODEL_ID = "BAAI/bge-small-en-v1.5"
MODEL_REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"

WHITESPACE = re.compile(r"\s+")


def normalized_text(text: str) -> str:
    return WHITESPACE.sub(" ", text).strip().casefold()


def embed(texts: list[str], model_id: str, revision: str, batch_size: int) -> np.ndarray:
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(model_id, revision=revision)
    return model.encode(
        texts, batch_size=batch_size, show_progress_bar=True,
        normalize_embeddings=True, convert_to_numpy=True,
    ).astype(np.float32, copy=False)


def max_similarity(holdout: np.ndarray, corpus: np.ndarray, chunk: int = 512) -> tuple[np.ndarray, np.ndarray]:
    """Max cosine similarity of each held-out row against the whole corpus.

    Both matrices are L2-normalized, so the dot product is the cosine. Chunked to
    keep the 2k x 36k product off the peak-memory path.
    """
    best = np.full(len(holdout), -1.0, dtype=np.float32)
    best_index = np.zeros(len(holdout), dtype=np.int64)
    for start in range(0, len(holdout), chunk):
        block = holdout[start:start + chunk] @ corpus.T
        block_best = block.argmax(axis=1)
        best[start:start + chunk] = block[np.arange(len(block_best)), block_best]
        best_index[start:start + chunk] = block_best
    return best, best_index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--holdout", type=Path, default=DEFAULT_HOLDOUT)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--corpus-embeddings", type=Path, default=DEFAULT_CORPUS_EMBEDDINGS)
    parser.add_argument("--clean", type=Path, default=DEFAULT_CLEAN)
    parser.add_argument("--quarantine", type=Path, default=DEFAULT_QUARANTINE)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--threshold", type=float, default=0.94)
    parser.add_argument("--model", default=MODEL_ID)
    parser.add_argument("--model-revision", default=MODEL_REVISION)
    parser.add_argument("--batch-size", type=int, default=64)
    args = parser.parse_args()

    holdout_rows = load_jsonl(args.holdout)
    corpus_rows = load_jsonl(args.corpus)
    corpus_embeddings = None
    if args.corpus_embeddings.is_file():
        cached = np.load(args.corpus_embeddings, allow_pickle=False)
        if str(cached["model_revision"]) != args.model_revision:
            raise SystemExit(
                f"corpus embeddings were built with revision {cached['model_revision']}, "
                f"not {args.model_revision}"
            )
        corpus_embeddings = cached["embeddings"].astype(np.float32, copy=False)
        if len(corpus_embeddings) != len(corpus_rows):
            raise SystemExit(
                f"cached embeddings ({len(corpus_embeddings)}) do not align with corpus rows ({len(corpus_rows)})"
            )
    else:
        # The scan runs in both directions -- new evaluation rows against the
        # training corpus, and new training rows against the frozen holdout --
        # and only the former has a prebuilt cache.
        print(f"no cache at {args.corpus_embeddings}; embedding {len(corpus_rows)} corpus rows ...", flush=True)
        corpus_embeddings = embed(
            [embedding_view(row["text"])[0] for row in corpus_rows],
            args.model, args.model_revision, args.batch_size,
        )
        args.corpus_embeddings.parent.mkdir(parents=True, exist_ok=True)
        np.savez(
            args.corpus_embeddings, embeddings=corpus_embeddings,
            input_sha256="", model_revision=args.model_revision,
        )

    corpus_exact = {}
    for index, row in enumerate(corpus_rows):
        corpus_exact.setdefault(normalized_text(row["text"]), index)

    print(f"embedding {len(holdout_rows)} held-out rows ...", flush=True)
    holdout_embeddings = embed(
        [embedding_view(row["text"])[0] for row in holdout_rows],
        args.model, args.model_revision, args.batch_size,
    )
    similarity, neighbor = max_similarity(holdout_embeddings, corpus_embeddings)

    clean, contaminated = [], []
    reasons: Counter = Counter()
    for position, row in enumerate(holdout_rows):
        exact_index = corpus_exact.get(normalized_text(row["text"]))
        near = float(similarity[position]) >= args.threshold
        if exact_index is None and not near:
            clean.append(row)
            continue
        neighbor_index = exact_index if exact_index is not None else int(neighbor[position])
        reason = "exact_normalized_match" if exact_index is not None else "semantic_near_duplicate"
        reasons[f"{row['source_id']}:{reason}"] += 1
        contaminated.append({
            **row,
            "contamination": {
                "reason": reason,
                "max_cosine_similarity": round(float(similarity[position]), 4),
                "corpus_record_id": corpus_rows[neighbor_index]["record_id"],
                "corpus_source_id": corpus_rows[neighbor_index]["source_id"],
            },
        })

    for path, rows in ((args.clean, clean), (args.quarantine, contaminated)):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    def label_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
        return dict(sorted(Counter(l for row in rows for l in row["labels"]).items()))

    report = {
        "report_version": "0.1.0",
        "holdout": project_relative(args.holdout),
        "corpus": project_relative(args.corpus),
        "corpus_rows": len(corpus_rows),
        "embedding_model": args.model,
        "embedding_model_revision": args.model_revision,
        "cosine_threshold": args.threshold,
        "holdout_rows": len(holdout_rows),
        "clean_rows": len(clean),
        "contaminated_rows": len(contaminated),
        "contamination_reasons": dict(sorted(reasons.items())),
        "similarity_percentiles": {
            str(p): round(float(np.percentile(similarity, p)), 4)
            for p in (50, 90, 99, 100)
        },
        "clean_rows_by_source": dict(sorted(Counter(row["source_id"] for row in clean).items())),
        "clean_label_occurrences": label_counts(clean),
        "contaminated_label_occurrences": label_counts(contaminated),
        "status": "scanned",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
