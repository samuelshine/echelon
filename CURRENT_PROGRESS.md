# Echelon Current Progress

## Status

**Phase:** 1 — Semantic grouping and candidate split materialization complete

**Branch:** `rnd`

**Checkpoint:** Awaiting approval before human sampling/adjudication and targeted coverage generation

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
- Added source-specific normalization adapters and the normalized record schema dependency (`pyarrow`).
- Preserved 16,116 regular/benign prompts—49.64% of the eligible corpus—with per-source reporting.
- Guaranteed that no assistant response columns enter normalized prompt records.
- Quarantined 503 evaluation-contaminated, 780 gated-upstream, 5,312 unverified-upstream-license, and 992 redacted/empty rows.
- Collapsed 4,193 consistent normalized duplicate groups, removing 5,535 redundant rows.
- Quarantined 391 benign-versus-malicious conflict groups containing 793 rows.
- Produced 32,465 unique eligible records with all required fields, unique record IDs, and zero response fields.
- Added `data/reports/normalization_report.json` with content-free source, label, benign, quarantine, duplicate, and split-design metrics.
- Expanded the test suite to 16 passing tests.
- Selected the MIT-licensed 33.4M-parameter BGE-small English encoder and pinned revision `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a`.
- Added semantic near-duplicate clustering at cosine `0.94`, combined with declared template and transformation-parent grouping.
- Generated 10,583 semantic and 2,628 declared grouping edges across 32,465 records.
- Produced 27,904 semantic components; 2,686 contain multiple records and the largest contains 166.
- Quarantined 156 mixed benign/malicious semantic clusters containing 652 rows.
- Materialized leakage-safe candidate splits: 25,453 train, 3,198 validation, and 3,162 test.
- Verified that zero semantic cluster IDs cross split boundaries.
- Preserved near-balanced benign/malicious composition in every split.
- Generated private exact and semantic adjudication queues under git-ignored `data/review_v2`.
- Added an English native-speaker defensive-cyber gold-set specification covering 12 legitimate security-work categories and hard negatives.
- Expanded the test suite to 22 passing tests, including Unicode JSONL framing and 80/10/10 allocation regression coverage.

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
- The eligible corpus is close to class-balanced, but malicious-code-specific and system-leakage supervision are underrepresented.
- Exact normalization cannot detect paraphrase/template leakage; semantic clustering remains required before final splits.
- The 391 safety-label conflict groups require policy-aware adjudication and must remain excluded until resolved.
- The `0.94` semantic threshold is conservative but not yet calibrated against a human-labeled prompt-pair sample.
- 734 long prompts use head-plus-tail semantic views; chunk-level similarity should be evaluated for hidden middle-section attacks.
- The candidate test split is not yet the native-speaker English gold set; the separate gold set still needs collection and annotation.
- Malicious-code and system-prompt-leakage labels remain underrepresented even after semantic grouping.

## Next action after approval

Human-review a stratified sample of semantic neighbor pairs around thresholds `0.90–0.97`, adjudicate the exact and semantic mixed-safety queues, and lock the semantic operating point. Then create targeted, native-speaker-reviewed English examples for defensive cyber, malicious code, system leakage, and encoded attacks, re-run grouping, and freeze dataset version `v1`. No model training begins until those gates pass.

## Bugs

No known defect remains in the new audit, acquisition, or normalization tools. The audit tool's non-zero exit on the legacy corpus is intentional because cross-split duplication is a blocking data-quality error. The existing `prepare_data.py` remains unsuitable: it discards provenance and randomly splits individual rows. Semantic near-duplicate detection and conflict adjudication are intentionally deferred to the next checkpoint.
