# Echelon Current Progress

## Status

**Phase:** 1 — Primary-source verification and pinned acquisition complete

**Branch:** `rnd`

**Checkpoint:** Awaiting approval before normalization, provenance mapping, and grouped deduplication

## Completed in this step

- Verified the repository is on `rnd` and had no pre-existing planning documents to overwrite.
- Reviewed the existing R&D README and dependency baseline.
- Defined the five threat families plus benign/hard-negative labeling.
- Drafted a candidate source registry spanning injection, jailbreaks, toxicity, broad harmful intent, malicious code, multilingual attacks, and obfuscation.
- Separated candidate training sources from frozen adversarial benchmarks.
- Defined provenance, license, privacy, deduplication, annotation, and source/template-disjoint split gates.
- Proposed compact model candidates and a latency/quality/calibration selection process.
- Proposed Layer 1 signals, calibrated Layer 2 scoring, Layer 3 fusion, and explicit routing boundaries.
- Added evaluation, judge-hardening, orchestration, observability, and production-readiness phases.
- Initialized the Medium article draft.
- Recorded collaborator decisions: English native-speaker gold set, performance-led benchmark isolation, and low false positives for legitimate defensive cybersecurity.
- Created a 15-source dataset registry with explicit training/evaluation/benign-control roles and approval gates.
- Created a normalized multi-label record schema covering provenance, revision, language, severity, context, template family, semantic cluster, and transformation lineage.
- Implemented a read-only, prompt-redacting registry/CSV audit CLI with machine-readable output and SHA-256 file manifests.
- Added four passing unit tests for normalization, cross-split leakage, governance requirements, and oversized prompts.
- Audited the existing 33,188-row processed corpus: 980 normalized groups cross splits; within-split duplicates total 1,876 (train 1,812, validation 33, test 31); two prompts exceed 128 KiB; all splits use the lineage-free legacy schema.
- Marked the current processed corpus as legacy-only for future research claims.
- Verified immutable Hugging Face revisions and license metadata from primary repository APIs.
- Approved and acquired four production-compatible sources: Aegis 2.0, neuralchemy Prompt Injection, jackhhao Jailbreak Classification, and Do-Not-Answer.
- Downloaded 13 artifacts totaling 32,789,495 bytes into git-ignored `data/raw_v2`; wrote a tracked SHA-256/size manifest.
- Structurally verified 25,007/1,245/1,964 Aegis train/validation/test records, 1,044/262 jackhhao rows, 939 Do-Not-Answer rows, and valid `PAR1` boundaries on all three neuralchemy Parquet files.
- Added atomic downloads, immutable-revision checks, API-license checks, gated-source rejection, process-unique temporary files, resumability, force replacement, and offline manifest verification.
- Recovered from and detected a concurrent-transfer corruption event; forced a clean reacquisition and verified all final hashes and structures.
- Expanded the test suite to nine passing tests.

## Current policy decisions

- English is Tier 1 and receives native-speaker gold-set coverage.
- Start shadow evaluation with `pass < 0.35`, `judge 0.35–<0.90`, and `block >= 0.90`; replace these with empirically optimized, calibrated per-category thresholds before enforcement.
- Optimize for high malicious-intent recall while measuring a separate false-positive constraint on legitimate defensive/educational cybersecurity prompts.
- Treat authorization claims as evidence for adjudication, never as an automatic allowlist.
- Keep JailbreakBench, HarmBench, StrongREJECT, and CyberSecEval evaluation slices frozen unless future contamination analysis justifies a different source-level partition.
- Compare local and API judges behind one provider-neutral interface later; selection remains a measured latency/privacy/quality decision.
- Exclude CC-BY-NC sources from the production training pool; do not bypass gated dataset terms.

## Known risks and open research questions

- The deepset dataset page exposes inconsistent license metadata (`cc-by-4.0` in dataset info and `apache-2.0` at repository level); it requires resolution before ingestion.
- Existing repository dataset claims have not yet been independently audited for source lineage, leakage, or license compatibility.
- Public jailbreak collections can contaminate benchmarks through paraphrases; semantic/template grouping is required.
- Dataset size is not a proxy for label quality. Large synthetic corpora may create generator/style shortcuts.
- Binary labels are insufficient for overlapping threat categories and do not encode severity or uncertainty.
- Raw classifier confidence will be miscalibrated under domain shift; calibration and drift monitoring are mandatory.
- A judge can itself be prompt-injected, may drift by provider version, and creates privacy/latency/cost dependencies.
- Base64/hex decoding can cause resource exhaustion or false positives unless strictly bounded and paired with benign encoded controls.
- Long inputs may hide attacks beyond the classifier truncation boundary; chunking policy requires evaluation.
- The legacy corpus has confirmed exact-normalized leakage across splits and cannot support trustworthy final metrics.
- Neuralchemy is newly published and claims group-aware leakage control, but remains untrusted until independent lineage, label, and near-duplicate analysis completes.
- Aegis prompt labels are human-authored, but its response labels and refusal augmentations must not leak into prompt-only features; only the main prompt-safety JSON files were acquired.
- Do-Not-Answer contains model response columns that must be dropped during prompt normalization.

## Next action after approval

Build source-specific normalization adapters that preserve original splits and provenance, map labels into the Echelon multi-label schema, and generate a content-free quality report. Then perform exact/normalized cross-source deduplication and propose semantic/template grouping before creating any new train/validation/test split. No training begins in that step.

## Bugs

No known defect remains in the new audit/acquisition tools. The audit tool's non-zero exit on the legacy corpus is intentional because cross-split duplication is a blocking data-quality error. The existing `prepare_data.py` remains unsuitable: it discards provenance and randomly splits individual rows. Raw Parquet content has not yet been semantically validated because normalization dependencies are intentionally deferred to the next phase.
