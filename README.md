# Echelon — Prompt Injection Detection (R&D)

Fine-tuning **DistilBERT** for binary classification of prompt injection attacks and malicious prompts. This R&D branch serves as a sandbox for experimenting with different training approaches, datasets, and model configurations.

## 📁 Project Structure

```
echelon/
├── configs/
│   ├── training_config.yaml     # DistilBERT configuration
│   └── deberta_config.yaml      # DeBERTa configuration
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
│   ├── download_data.py         # Download all datasets
│   ├── prepare_data.py          # Merge, deduplicate, split
│   └── train.py                 # Fine-tune DistilBERT
├── notebooks/                   # EDA & experimentation
├── requirements.txt
└── README.md
```

## 🚀 Quick Start

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