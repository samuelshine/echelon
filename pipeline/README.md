# Echelon — Detection Pipeline (Three-Fold Prompt Security)

Echelon's detection pipeline is a staged prompt/response-security cascade:
deterministic Layer 1 heuristics, a trained multi-label Layer 2 DistilBERT
classifier, and a Layer 3 LLM-judge (local Ollama) for gray-area cases. This
directory is also the data-governance and evaluation workspace that produced
the reviewed training corpus.

**Current state (see `CURRENT_PROGRESS.md` for the full log, `../DEMO.md` for
the live end-to-end contracts):** the training gate has passed, Layer 2 is
trained and calibrated on the reviewed corpus (macro-F1 0.696;
`models/layer2-threat-distilbert/best`, weights git-ignored), and
`service/security_api.py` serves it over HTTP (`/classify`, `/judge`,
`/classify_response`, `/judge_response`) to the Go gateway. Known limitation:
the rare categories (`system_prompt_leakage`, `malicious_code`) have low
precision/tiny support and are mitigated by forced judge escalation rather
than fixed at the classifier level — see `DEMO.md` → "Honest limitations."
Expert adjudication of the 152 review conflicts was AI-assisted
(`ai_claude`), recorded as provisional and human-overridable, not native
human review.

The sections below (datasets, legacy training commands, project structure)
describe the original R&D/data-governance workspace and the superseded
binary-classifier training path; they are retained for historical/data-lineage
reference. The production path is: `service/security_api.py` serves the
trained multilabel model already in `models/layer2-threat-distilbert/best` —
no retraining is required to run the system.

## 📁 Project Structure

```
echelon/
├── configs/
│   ├── layer1_rules.json        # Deterministic rules and risk thresholds
│   ├── pipeline.yaml            # Cascade shadow/enforcement policy
│   ├── training_config.yaml      # Guarded legacy training configuration
│   └── deberta_config.yaml       # Guarded DeBERTa configuration
├── data/
│   ├── raw/                     # Downloaded source data
│   │   ├── deepset/
│   │   ├── neuralchemy/
│   │   └── github/
│   └── processed/               # Merged & split CSVs
│       ├── train.csv
│       ├── val.csv
│       └── test.csv
├── models/
│   ├── prompt-injection-distilbert/
│   │   ├── best/                # Best model checkpoint
│   │   ├── checkpoints/         # All training checkpoints
│   │   ├── results.json         # Evaluation metrics
│   │   ├── confusion_matrix.png
│   │   └── roc_curve.png
│   └── prompt-injection-deberta/
│       └── ...                  # Same structure for DeBERTa
├── scripts/
│   ├── run_pipeline.py          # Three-fold local smoke/inference CLI
│   ├── benchmark_pipeline.py    # Fixture-only end-to-end benchmark
│   ├── check_training_gate.py   # Fail-closed manifest check
│   └── train.py                 # Refuses data without reviewed manifest
├── notebooks/                   # EDA & experimentation
├── requirements.txt
└── README.md
```

## Quick Start: pipeline smoke run

This uses a fixture-only semantic score and does not train or download a model:

```bash
printf '%s' 'Summarize this meeting agenda.' | python -m scripts.run_pipeline --fixture-risk 0.10 --judge mock
```

For a real local model artifact, select it explicitly; model loading is local-only:

```bash
python -m scripts.run_pipeline \
  --model-dir models/prompt-injection-distilbert/best \
  --mode shadow < prompt.txt
```

See [`docs/PIPELINE_DESIGN.md`](docs/PIPELINE_DESIGN.md) for routing, calibration, judge, privacy, and failure-policy details.

## Legacy data/training commands

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Download Datasets

Downloads from 3 sources: deepset (HuggingFace), neuralchemy (HuggingFace), and rossja (GitHub).

```bash
python scripts/download_data.py
```

### 3. Prepare Data

Merges all sources, deduplicates, and creates stratified 80/10/10 splits.

```bash
python scripts/prepare_data.py
```

### 4. Train Model

The old random-split workflow is retained only for historical comparison. `scripts/train.py` now refuses to run unless the configuration points to a manifest marked human-reviewed, privacy-reviewed, and semantically split. Do not use `scripts/prepare_data.py` for production training.

You can fine-tune either DistilBERT (default) or DeBERTa by passing the respective configuration file:

**Train DistilBERT (Default):**
```bash
python scripts/train.py --config configs/training_config.yaml
```

**Train DeBERTa:**
```bash
python scripts/train.py --config configs/deberta_config.yaml
```

## 📊 Datasets

| Source | Size | Description |
|--------|------|-------------|
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | ~750 | Classic prompt injection benchmark |
| [neuralchemy/Prompt-injection-dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset) | ~29K+ | Large-scale, leakage-free dataset |
| [rossja/prompt-injection-datasets](https://github.com/rossja/prompt-injection-datasets) | ~3K+ | Community-aggregated collection |

## ⚙️ Configuration

All hyperparameters are in [`configs/training_config.yaml`](configs/training_config.yaml):

- **Model**: `distilbert-base-uncased`
- **Max sequence length**: 512
- **Epochs**: 5 (with early stopping, patience=2)
- **Batch size**: 32 (effective 64 with gradient accumulation)
- **Learning rate**: 2e-5 with warmup
- **Optimisation**: class-weighted loss, MPS acceleration

## 🧪 Training Features

- **Class-weighted cross-entropy** to handle dataset imbalance
- **Early stopping** on validation F1 (patience=2)
- **MPS GPU acceleration** (Apple Silicon)
- **Gradient accumulation** for effective batch size 64
- **Comprehensive evaluation**: accuracy, F1, precision, recall, ROC-AUC
- **Visualisations**: confusion matrix & ROC curve PNGs

## 📈 Output

After training, check:
- `models/prompt-injection-distilbert/results.json` — all metrics
- `models/prompt-injection-distilbert/confusion_matrix.png` — visual
- `models/prompt-injection-distilbert/roc_curve.png` — visual
- `models/prompt-injection-distilbert/best/` — saved model & tokenizer
