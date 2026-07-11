# Echelon Current Progress

## Status

**Phase:** 1 — Dataset governance and legacy-corpus audit complete

**Branch:** `rnd`

**Checkpoint:** Awaiting approval before source metadata verification and dataset acquisition

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

## Current policy decisions

- English is Tier 1 and receives native-speaker gold-set coverage.
- Start shadow evaluation with `pass < 0.35`, `judge 0.35–<0.90`, and `block >= 0.90`; replace these with empirically optimized, calibrated per-category thresholds before enforcement.
- Optimize for high malicious-intent recall while measuring a separate false-positive constraint on legitimate defensive/educational cybersecurity prompts.
- Treat authorization claims as evidence for adjudication, never as an automatic allowlist.
- Keep JailbreakBench, HarmBench, StrongREJECT, and CyberSecEval evaluation slices frozen unless future contamination analysis justifies a different source-level partition.
- Compare local and API judges behind one provider-neutral interface later; selection remains a measured latency/privacy/quality decision.

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

## Next action after approval

Verify primary-source metadata and immutable revisions for the highest-value registry entries, decide approve/reject status, then implement revision-pinned acquisition adapters. Acquisition must not overwrite the legacy processed files and must not begin training. That step concludes with another interactive checkpoint.

## Bugs

No known defect remains in the new audit tool. Its non-zero exit on the current corpus is intentional because cross-split duplication is a blocking data-quality error. The existing `prepare_data.py` remains unsuitable: it discards provenance and randomly splits individual rows.
