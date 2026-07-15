# Echelon Current Progress

## Status

**Phase:** 1 — Distributed dual-review kits ready; human judgments pending

**Branch:** `rnd`

**Checkpoint:** Two private primary kits verified; awaiting secure distribution and human completion

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
- Created a deterministic 450-pair semantic calibration queue spanning five similarity bands and all three safety-pair relationships.
- Recorded candidate availability for every calibration stratum; even the smallest stratum contains 96 candidate pairs.
- Added a reusable 48 MB embedding cache keyed by normalized-corpus SHA-256 and pinned model revision.
- Added an adjudication-review JSON Schema and CLI enforcing two-reviewer agreement or expert resolution.
- Added targeted English curation minimums for system leakage, malicious code, obfuscation, social engineering, and defensive cyber.
- Required matched benign controls, multi-generator diversity, native-speaker gold review, parent-group isolation, and privacy screening.
- Expanded the test suite to 27 passing tests.
- Added a versioned targeted-candidate schema and deterministic controlled-composition generator.
- Generated 6,000 unique English candidates: 3,000 benign controls and 3,000 malicious-intent prompts.
- Added 1,500 defensive-cyber benign prompts and 500 benign system-prompt/documentation controls.
- Added 1,000 benign encoded controls matched to 1,000 obfuscated attacks across five equally represented transformations.
- Added 1,000 system-leakage and 1,000 malicious-code-intent base candidates using inert placeholders and no payload responses.
- Verified 6,000 unique IDs/fingerprints and zero exact-normalized overlap with the existing eligible corpus.
- Marked all 6,000 rows pending review and explicitly ineligible for training.
- Produced a content-free composition report and SHA-256 artifact manifest.
- Expanded the test suite to 31 passing tests.
- Embedded and audited all 6,000 candidates against the existing corpus and internally using the pinned BGE model.
- Confirmed strong external novelty: 5,987 candidates below `0.90`, 13 in `0.90–0.94`, and zero at or above `0.94` against existing records.
- Confirmed zero cross-label existing neighbors at the `0.94` threshold.
- Detected severe internal template collapse: mean nearest-neighbor similarity `0.9763` and a 4,635-row mixed-safety component.
- Failed v0.1 admission because the largest component is 77.25% of the batch and crosses benign/malicious labels.
- Produced family-level lexical diversity metrics showing low distinct-bigram ratios despite string uniqueness.
- Generated a private 600-row review queue with exactly 100 prompts per family.
- Balanced transformed review samples at 40 per method overall: 20 malicious and 20 benign for each encoding/transformation.
- Kept every v0.1 candidate ineligible for training.
- Expanded the test suite to 35 passing tests.
- Generated a smaller v0.2 pilot with 1,200 unique rows, balanced 600 benign/600 malicious.
- Added 280 explicit template lineages with a strict maximum of 10 rows per lineage.
- Broadened human-authored frame pools and recorded five generation strategies.
- Replaced the universal encoding wrapper with separate, varied benign and malicious wrapper pools.
- Passed the semantic admission gate: largest component 34 rows (2.83%) and zero mixed-safety components.
- Reduced mean internal nearest similarity from `0.9763` to `0.9150`.
- Confirmed external novelty: 1,199 rows below `0.90`, one boundary row, and none at or above `0.94` against the existing corpus.
- Improved unencoded-family distinct-bigram ratios to `0.1289–0.1683`, approximately an order-of-magnitude gain over v0.1.
- Produced a v0.2 private review queue with 100 rows per family and balanced transformation sampling.
- Kept all 1,200 candidates pending human review and ineligible for training.
- Expanded the test suite to 39 passing tests.

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
- Human calibration and adjudication are designed but have not occurred; no unresolved item has been automatically promoted into the corpus.
- Synthetic composition can create template/style shortcuts even when every string is unique; generator-family and semantic-cluster analysis is required.
- `operational_content=false` is a generator invariant, not a human safety certification.
- Unique strings did not prevent semantic/template collapse; v0.1 must not be salvaged by random row splitting.
- Automated semantic admission does not certify label correctness, naturalness, or non-operationality; v0.2 still needs human review.

## Local reviewer workflow completed (2026-07-14)

- Added a local-only Flask interface backed by SQLite for the 600-row v0.2 review queue.
- Bound the review database to queue SHA-256 `11f0ca2e3de5564276533d0a88ec53e66aeaa611478e628839379f1175566e91`.
- Blinded primary reviewers to proposed labels, nearest-neighbor prompt text, embedded review scaffolding, and prior decisions.
- Required two distinct primary reviewers; matching decision plus exact label set is necessary but not sufficient for admission.
- Added mandatory naturalness, intent correctness, label correctness, and non-operational-content quality gates.
- Restricted expert adjudication to genuine disagreements after two primary reviews and required a third distinct reviewer.
- Added token-protected APIs, loopback-only serving, disabled debug mode, no-store responses, CSP, anti-framing, and content-type hardening.
- Added an offline JSONL decision importer and a gated accepted-candidate exporter.
- Added a content-free human-review report. The dry run has 600 unreviewed items, zero review records, and zero training-eligible items.
- Added the operator guide `docs/REVIEWER_WORKFLOW.md`.
- Expanded the suite to 49 tests: 48 pass and the Flask HTTP integration test is skipped because Flask is declared but not installed in the current interpreter. All store, policy, transactional importer, and admission tests pass with resource warnings promoted to errors.

## Next action after approval

Securely send `data/review_v2/distributed_kits_v02/reviewer_a` and `reviewer_b` to two independent English native-speaker reviewers. They complete all 600 items locally, validate prompt-free exports, and wait until both report completion before pushing separate branches. Validate the pair, generate the conflict-only expert kit, collect a third distinct expert submission, and run the final cohort gate. No accepted record proceeds to training until normalization and semantic regrouping pass.

## Bugs

No known defect remains in the new audit, acquisition, normalization, semantic grouping, or review-policy tools. Flask is absent from the current interpreter, so its HTTP integration test is skipped; `Flask>=3.0.0` is already declared in `requirements.txt` and is required to launch the interface. The audit tool's non-zero exit on the legacy corpus is intentional because cross-split duplication is a blocking data-quality error. The existing `prepare_data.py` remains unsuitable: it discards provenance and randomly splits individual rows.

## Distributed review workflow completed (2026-07-15)

- Added primary-kit generation with exactly two distinct locked reviewer identities.
- Removed indirect label leakage from both kits and live primary assignments: family, context, proposed labels, generator metadata, nearest neighbors, and review scaffolding are hidden.
- Generated two private 600-item kits under ignored `data/review_v2/distributed_kits_v02`.
- Added a prompt-free tracked manifest with 600 allowed IDs and canonical queue SHA-256 `11f0ca2e3de5564276533d0a88ec53e66aeaa611478e628839379f1175566e91`.
- Added complete-only, privacy-screened submission export; prompt text, notes, timestamps, and local database details cannot enter the output schema.
- Added individual, paired-primary, expert, and final-cohort validation commands.
- Added conflict-only expert-kit generation and exact expert coverage checks.
- Added identity locking in the local app and enforced a third expert distinct from both primary reviewers.
- Added a CI workflow for every JSON submission under `review_submissions/v0.2`.
- Added `docs/DISTRIBUTED_REVIEW.md` with coordinator, primary, expert, push, validation, and import commands plus a copy/paste reviewer briefing.
- Bound primary submissions to deterministic blinded-queue SHA-256 `fafc411907234ed8b21122a0e2084e2f2eccf5b9871ce3c4259519348b69ea1` in addition to the canonical queue hash.
- Expanded the suite to 60 tests: 59 pass; one Flask HTTP integration test is skipped because Flask is not installed in the current interpreter.
- Kept all candidates ineligible. No human decisions or training admissions were fabricated.
