# Echelon Three-Fold Prompt Evaluation Ingress Pipeline

## Mission and operating constraints

Build and evaluate an ultra-low-latency, defense-in-depth prompt firewall on the `rnd` branch. The ingress pipeline must detect prompt injection, system-prompt extraction, malicious code intent, toxicity/harm, and novel or obfuscated attacks while returning calibrated risk scores, category evidence, and an explicit route—not only a Boolean label.

This document is a research plan, not an assertion that every listed dataset is approved for redistribution or production training. Every source must pass license, provenance, privacy, quality, and contamination review before ingestion. Raw harmful data remains access-controlled and is never logged verbatim in production.

## Success criteria

- Optimize safety recall under a measured false-positive budget; report per-category precision, recall, F1, PR-AUC, ROC-AUC, expected calibration error (ECE), Brier score, and latency percentiles.
- Establish a frozen, source-disjoint test suite with multilingual, encoded, typoglycemic, role-play, long-context, and benign hard-negative slices.
- Produce calibrated scores in `[0, 1]`, deterministic routes, stable reason codes, and auditable model/data versions.
- Define latency budgets after profiling on target hardware; record p50/p95/p99 for each layer and cascade-level LLM call rate.
- Prevent benchmark contamination with exact, normalized, fuzzy, and embedding-based near-duplicate checks grouped by source and attack template.

## Threat taxonomy and labeling

Use multi-label targets so a prompt can simultaneously request instruction override, secret extraction, and harmful code. Initial labels:

1. `prompt_injection`: instruction override, authority impersonation, delimiter attacks, indirect injection, tool/output manipulation.
2. `system_prompt_leakage`: requests to reveal, transform, quote, encode, summarize, or infer hidden instructions/context/secrets.
3. `malicious_code`: exploit development, credential theft, malware, persistence, evasion, destructive automation; distinguish legitimate defensive/educational context.
4. `toxicity_harm`: hate, harassment, violence, self-harm, sexual abuse, illegal or dangerous intent.
5. `adversarial_obfuscation`: encoding, translation, homoglyphs, zero-width characters, token splitting, typoglycemia, nested role-play, multi-turn setup.
6. `benign`: ordinary requests plus hard negatives that mention security concepts without malicious intent.

Labels include `severity`, `attack_family`, `language`, `encoding`, `source`, `source_item_id`, `template_family`, annotation confidence, and adjudication notes. Ambiguous examples are retained with soft/uncertain labels for analysis but excluded from the gold test set until adjudicated.

## Phase 1 — Dataset research, governance, and curation

### Candidate training sources

| Source | Primary use | Planned treatment |
|---|---|---|
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Direct injection seed set | Curated seed; small size means no standalone claims. Verify conflicting license metadata before use. |
| Existing `neuralchemy/Prompt-injection-dataset` and `rossja/prompt-injection-datasets` inputs | Injection breadth | Audit original provenance, licenses, duplicates, label construction, and possible synthetic leakage before retention. |
| [Tensor Trust](https://tensortrust.ai/paper/) and [HackAPrompt](https://paper.hackaprompt.com/) | Human adversarial injection attempts | Research candidates; group by challenge/template and strictly separate near-duplicates. |
| [WildGuardMix](https://huggingface.co/datasets/allenai/wildguardmix) | Prompt harmfulness and jailbreak/refusal supervision | Map taxonomy carefully; sample-balance and audit generated labels. |
| [Aegis AI Content Safety Dataset 2.0](https://huggingface.co/datasets/nvidia/Aegis-AI-Content-Safety-Dataset-2.0) | Broad safety categories | Candidate for harmful-intent coverage; verify license and taxonomy compatibility. |
| [ToxicChat](https://huggingface.co/datasets/lmsys/toxic-chat) | Real user–AI toxicity | Preserve official splits where appropriate; use as toxicity-focused data/evaluation with source-aware deduplication. |
| [BeaverTails](https://huggingface.co/datasets/PKU-Alignment/BeaverTails) and [Do-Not-Answer](https://huggingface.co/datasets/LibrAI/do-not-answer) | Diverse harmful requests | Downsample, taxonomy-map, and prevent response text from leaking into prompt-only features. |
| [CyberSecEval](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks) | Cybersecurity and malicious-code evaluation | Prefer as held-out evaluation; separate dual-use benign tasks from genuinely harmful requests. |
| Curated benign corpora and domain traffic samples | False-positive control | Privacy-scrub, stratify by domain/language, and include security-themed benign hard negatives. |

### Held-out adversarial evaluation

- [JailbreakBench](https://github.com/JailbreakBench/jailbreakbench): frozen jailbreak behavior/artifact evaluation; do not train on its evaluation behaviors or close paraphrases.
- [HarmBench](https://www.harmbench.org/): broad automated red-team evaluation; reserve behaviors and adversarial variants.
- [StrongREJECT](https://github.com/dsbowen/strong_reject), XSTest, and CyberSecEval slices: evaluate harmfulness, exaggerated refusal, and dual-use cyber intent.
- Add a private, versioned Echelon challenge set of novel compositions unavailable to training jobs.

### Edge-case generation

Generate transformations only after train/validation/test grouping so siblings cannot cross splits. Cover Base64, hex, URL encoding, Unicode escapes, homoglyphs, zero-width characters, reversed/chunked text, whitespace/punctuation noise, leetspeak, typoglycemia, nested quotes, fake system messages, role-play, gradual multi-turn escalation, and mixed-language code switching. Include matched benign encoded payloads and benign role-play to prevent shortcut learning.

For multilingual coverage, prioritize human-validated examples in high-traffic languages, then controlled translation/back-translation. Track language and translator/model provenance. Native-speaker review is required for the gold set; transliterations and mixed-script attacks form separate slices.

### Curation pipeline

1. Snapshot immutable source revisions and dataset cards; produce a manifest with hashes and license decisions.
2. Normalize without destroying an original-text column; detect encoding/Unicode anomalies as features.
3. Map labels to the Echelon multi-label taxonomy with documented rules.
4. Remove exact and normalized duplicates; cluster fuzzy and semantic near-duplicates.
5. Group splits by source, conversation, attack template, semantic cluster, and transformation parent.
6. Run stratified quality sampling and dual annotation; adjudicate disagreements and measure inter-annotator agreement.
7. Publish dataset cards, composition tables, imbalance statistics, and excluded-source reasons.

## Phase 2 — Model and feature research

Benchmark compact encoders rather than committing prematurely:

- DistilBERT as the latency and implementation baseline.
- DeBERTa-v3-small/base for accuracy-sensitive comparison.
- MiniLM or compact multilingual encoders for CPU/edge latency.
- XLM-R-base or a distilled multilingual alternative for multilingual recall.

Train a multi-label classifier with category logits plus an aggregate threat head. Compare weighted BCE/focal loss, balanced sampling, hard-negative mining, adversarial augmentation, and knowledge distillation. Select from Pareto-optimal validation results across recall, calibration, model size, and target-hardware p99 latency. Quantization/ONNX export follows accuracy validation.

## Phase 3 — Layer 1: heuristic analysis

- Unicode-aware normalization with both raw and canonical views.
- Aho–Corasick phrase families for known override, leakage, and malicious-intent indicators.
- Regex for fake role headers, delimiters, extraction requests, encoded payload signatures, and suspicious shell/code constructs.
- Entropy and printable-character ratios for likely encoded spans; guarded Base64/hex decoding with strict size/depth/time limits.
- Length, repetition, invisible-character, mixed-script, and instruction-density signals.
- Negative rules/context dampeners for quotations, analysis, defensive education, and clearly benign transformations.

Layer 1 returns `heuristic_score`, matched reason codes, normalized variants, and category modifiers. Rules are versioned, tested against adversarial positives and benign hard negatives, and bounded against ReDoS/resource exhaustion.

## Phase 4 — Scoring, calibration, and routing

All stage probabilities are calibrated on source-disjoint validation data (compare temperature scaling, Platt scaling, and isotonic regression). The initial research formula is:

```text
h = calibrated Layer-1 risk in [0, 1]
m = calibrated Layer-2 aggregate risk in [0, 1]
c_k = calibrated Layer-2 probability for category k
pre_judge_risk = 1 - (1 - m) * (1 - alpha * h)
```

`alpha` is learned/tuned under the false-positive budget rather than assumed. Critical deterministic indicators may impose a configurable score floor, but no single weak keyword may auto-block. Layer 3 returns `judge_risk`, category probabilities, and a schema-valid verdict. Candidate fusion for adjudicated cases:

```text
final_risk = calibrated_logistic(beta_0 + beta_1*logit(pre_judge_risk)
                                 + beta_2*logit(judge_risk)
                                 + beta_3*disagreement)
```

Initial shadow-mode routing hypothesis for validation—not production defaults:

- `risk >= 0.90`: auto-block only after calibration and category-policy checks.
- `0.35 <= risk < 0.90`: escalate to Layer 3.
- `risk < 0.35`: pass, unless a separately approved critical policy rule applies.

These wider initial escalation bounds favor recall while requiring stronger evidence for automatic blocking. They are scaffolding for shadow evaluation, not a claim of optimality. Final boundaries will be selected on source-disjoint validation data to minimize expected cost subject to per-category recall and benign false-positive constraints. Use inclusive/exclusive boundaries explicitly. Tune separate category thresholds where costs differ, and choose operating points from precision–recall curves plus a cost matrix. Return the maximum calibrated category risk and all category scores; never treat raw softmax confidence as calibrated risk.

Legitimate cybersecurity is determined by intent and context, not a keyword allowlist. Defensive education, authorized testing, CTFs, code review, incident response, and vulnerability remediation form a dedicated benign/dual-use hard-negative slice. Requests for credential theft, persistence, evasion, destructive payloads, unauthorized exploitation, or operational malware remain malicious even when framed as “research.” The system measures cyber false positives separately and may use category-aware adjudication, but no user-supplied claim of authorization automatically suppresses risk.

## Phase 5 — Layer 2 training and evaluation pipeline

- Reproducible configuration, seed control, revision-pinned data/model dependencies, and artifact hashes.
- Tokenization analysis for encoded, multilingual, and long prompts; quantify truncation failures and evaluate sliding-window/chunk aggregation.
- Baseline, ablation, and model-selection experiments with bootstrap confidence intervals.
- Threshold optimization on validation only; one-time frozen-test reporting.
- Report macro/micro/weighted F1, per-category recall/precision, PR-AUC, FPR on benign hard negatives, calibration, slice metrics, and latency/memory.
- Model card with intended use, exclusions, safety limitations, data lineage, and rollback criteria.

## Phase 6 — Layer 3 judge

Define a provider-neutral `Judge` interface with local and API adapters. The judge receives only necessary prompt context plus structured Layer 1/2 evidence, uses an injection-resistant fixed system instruction, and must emit a validated JSON schema containing risk, categories, rationale codes, uncertainty, and recommended route. Do not expose secrets or hidden system prompts to the judge input.

Mitigations include strict timeouts, retries with caps, circuit breakers, concurrency limits, response-schema validation, prompt/data delimiters, model/version pinning, privacy redaction, and fail-policy configuration. Cache only privacy-safe keyed results. Evaluate judge consistency, injection susceptibility, provider drift, cost, and added latency. Human review remains available for high-impact ambiguity.

## Phase 7 — Cascade orchestration and production readiness

Implement typed stage contracts, threshold configuration, batch and async execution, observability, safe logging, and deterministic routing. A likely latency-efficient cascade runs Layer 1 first, immediately blocks only approved critical/high-confidence cases, runs Layer 2 for all remaining prompts, and invokes Layer 3 only in the uncertainty band. Shadow-mode deployment precedes enforcement.

Production gates:

- Frozen regression suite and property/fuzz tests.
- Load, timeout, malformed-Unicode, long-input, and adversarial resource tests.
- Privacy/security review, data retention controls, and no raw-prompt logs by default.
- Signed/versioned rule, model, calibration, threshold, and judge-prompt artifacts.
- Drift monitoring by category/language/route plus rollback and kill-switch procedures.

## Planned deliverables and checkpoints

1. **Research checkpoint:** approved dataset registry, taxonomy, governance rules, benchmark isolation, and provisional threshold policy.
2. **Curation checkpoint:** data manifest, audit report, split statistics, and frozen evaluation suite.
3. **Layer 1 checkpoint:** tested rule engine, risk features, and latency/false-positive report.
4. **Layer 2 checkpoint:** trained candidates, calibrated metrics, slice analysis, and selected deployment artifact.
5. **Layer 3 checkpoint:** judge contract, hardened prompts, provider/local adapters, and adjudication evaluation.
6. **Orchestration checkpoint:** end-to-end cascade, configuration, tests, benchmarks, and shadow-mode plan.

No Python implementation begins until the research checkpoint is approved.

## Baseline corpus audit (2026-07-11)

The pre-existing binary `data/processed` corpus is retained only as a legacy baseline. A read-only audit found 33,188 rows, 1,876 normalized duplicates within splits, 980 normalized fingerprint groups crossing train/validation/test boundaries, two prompts larger than 128 KiB, and no source/revision/language/taxonomy lineage. Consequently, existing results cannot be used as clean generalization evidence. The replacement data pipeline must ingest revision-pinned sources into `schemas/dataset_record.schema.json` and group splits before any transformations or balancing.

## Approved acquisition set (2026-07-11)

The first production-compatible raw snapshot contains four immutable Hugging Face revisions: NVIDIA Aegis/Nemotron Content Safety 2.0 (`CC-BY-4.0`), neuralchemy Prompt Injection Dataset (`Apache-2.0`, subject to downstream lineage/quality audit), jackhhao Jailbreak Classification (`Apache-2.0`), and LibrAI Do-Not-Answer (`Apache-2.0`). Thirteen artifacts totaling 32,789,495 bytes are recorded in `data/manifests/acquisition_manifest.json`; raw content is git-ignored. Hash, byte-size, JSON/CSV structure, and Parquet magic validation passed.

ToxicChat and BeaverTails are excluded from the production training pool because their `CC-BY-NC-4.0` terms are noncommercial. WildGuardMix remains pending because its ODC-BY repository is gated by separate AI2 Responsible Use Guidelines that require manual acceptance. The deepset injection repository is rejected for automated acquisition until its conflicting Apache-2.0 versus CC-BY-4.0 metadata is resolved. Unlicensed mirrors are not used. Benchmark holdouts remain unacquired until their exact evaluation licenses, versions, and contamination strategy are recorded.
