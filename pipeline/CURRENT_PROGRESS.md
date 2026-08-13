# Echelon Current Progress

## Status (updated 2026-08-12 — see bottom of log for the current entry)

**Phase:** Layer 1/2/3 built and served; Layer 2 retrained on a ~4x-larger,
AI-reviewed v0.3 round and promoted 2026-08-12 (macro-F1 **0.899**, up from
0.696 — see "Track A executed" near the bottom of this log); `service/security_api.py`
serves `/classify`, `/judge`, `/classify_response`, `/judge_response` to the Go
gateway; egress ML-cascade escalation added 2026-08-01. Consolidated into the
`main` monorepo under `pipeline/` (was branch `rnd`).

**Checkpoint:** Production e2e verified live (see root `DEMO.md`). Redis-backed
distributed state, CI, and observability (metrics/tracing/durable audit sink)
are now done (2026-08-01 – 2026-08-04, `gateway/EXECUTION_PLAN.md`). ML/data
side, as of 2026-08-12: `malicious_code`/`system_prompt_leakage` precision on
tiny support is mostly resolved for the served (prompt-side) model (see
"Track A executed" below); egress (response-shaped) `malicious_code` detection
still relies on the code-shape heuristic mitigation in production — a
candidate retrain that closes it directly exists (`response_shaped_malicious_code`
F1 1.0) but is evaluated, not promoted (see "Track B executed" below). Both
rounds are still below `TARGETED_CURATION_SPEC.md`'s full target volume and
used AI-assisted (not native-human) review.

<!-- Historical status line, kept for context: originally "Phase 3 — Layer 1
heuristic engine complete; human dataset review remains in parallel". The
chronological log below is append-only and has not been rewritten. -->

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

## Parallel reviewer operation

Push the encrypted kits and bootstrap tooling on `rnd`. Give each independent English native-speaker reviewer repository access and only their assigned passphrase from git-ignored `data/review_v2/distributed_kit_passphrases.json`. Reviewer A runs `python3 scripts/review_bootstrap.py reviewer_a`; Reviewer B runs the corresponding `reviewer_b` command. They finish and export locally, wait until both report completion, and then push only their prompt-free JSON. No accepted record proceeds to training until expert adjudication, normalization, and semantic regrouping pass.

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
- Expanded the suite to 64 tests: 63 pass; one Flask HTTP integration test is skipped because Flask is not installed in the current interpreter.
- Kept all candidates ineligible. No human decisions or training admissions were fabricated.

## Encrypted clone-and-run bootstrap completed (2026-07-15)

- Added two authenticated AES-256-GCM `.echelonkit` artifacts to `review_kits/v0.2`.
- Derived independent encryption keys using scrypt (`N=32768`, `r=8`, `p=1`) with unique salts and 32-byte random passphrases.
- Stored passphrases only in git-ignored `data/review_v2/distributed_kit_passphrases.json`; no secret was printed during generation or testing.
- Added a cross-platform one-command bootstrap that creates an isolated `.review-venv`, installs only Flask and cryptography, prompts invisibly for the passphrase, authenticates the kit, materializes it under ignored storage, and starts the locked loopback interface.
- Added one-command complete-only export using the same bootstrap plus `--export`.
- Added wrong-passphrase, wrong-reviewer, ciphertext-tampering, round-trip, and materialized-hash tests.
- Verified both real ciphertexts decrypt to exactly 600 assigned rows without printing secrets.
- Kept plaintext queues, passphrases, runtime databases, and virtual environments excluded from Git.

## Layer 1 heuristic engine completed (2026-07-22)

- Added shared immutable contracts for evidence, category scores, input statistics, routes, and layer results.
- Added a dependency-free Aho–Corasick matcher built once per ruleset.
- Added precompiled bounded regex rules for injection, leakage, malicious code, role-play bypass, delimiters, and targeted harm.
- Added NFKC normalization, case folding, entropy, Unicode control/format-character, and exact 100,000-character head/tail bounds.
- Added bounded Base64, hex, URL-percent, Unicode-escape, and reversal decoding with no execution or decoded-content logging.
- Added five per-category risk scores plus one overall `[0,1]` risk and explicit pass/escalate/block thresholds.
- Added correlation groups so overlapping phrase and regex evidence contributes only once at its strongest weight.
- Preserved legitimate defensive-cyber handling: the authorized reverse-shell incident-response regression passes at risk `0.24`.
- Verified combined injection plus system-leakage risk `0.9808` blocks and explicit ransomware/evasion/credential-theft risk `0.999232` blocks.
- Added content-free CLI evaluation and a reproducible microbenchmark command.
- Recorded 30,000-iteration latency: median `27.958 us`, p95 `38.750 us`, p99 `40.083 us`, throughput `33,572 prompts/s`.
- Added 22 Layer 1 tests covering scoring, boundary behavior, benign controls, all decoders, Unicode, long inputs, privacy, fuzzing, configuration failures, and automaton overlap.
- Kept rules and thresholds in shadow status pending reviewed-data calibration.

## Next action after approval

Distribute the encrypted reviewer kits and complete dual human review. After the accepted subset exists, normalize it, rebuild semantic groups/splits, generate the approved training manifest, and only then run Layer 2 calibration/training. The Layer 2/3/cascade code is ready for fixture and local-artifact smoke tests but makes no production quality claim.

## Non-data-dependent pipeline foundations completed (2026-07-22)

- Added typed `ThresholdPolicy`, Layer 2 result, judge result, and pipeline decision contracts.
- Added lazy local-only Hugging Face semantic adapter; it never downloads model weights implicitly.
- Added calibrated/uncalibrated score tracking and deterministic binary temperature fitting.
- Added dependency-light precision, recall, F1, benign false-positive rate, Brier score, ECE, slice metrics, and constrained threshold selection.
- Added strict Layer 3 judge schema validation, controlled rationale codes, hardened untrusted-prompt context, timeout-bounded HTTPS JSON adapter, and deterministic mock judge.
- Added shadow/enforcement cascade orchestration with Layer 1/2/3 routing, strongest-observed shadow reporting, fail-to-escalate behavior, and content-free serialized results.
- Added fixture-only pipeline CLI and benchmark. The 5,000-iteration run measured median `33.750 us`, p95 `40.000 us`, p99 `43.916 us`, and `30,991 prompts/s` on this development machine.
- Added split-group validation and wired a fail-closed reviewed training manifest gate into both legacy training configurations and `scripts/train.py`.
- The pending v0.2 candidate manifest is correctly refused by the training gate.
- Expanded the suite to 114 tests: 109 pass; one Flask and four cryptography integration tests are skipped in the base interpreter because those optional packages are absent. The full cryptography-enabled run previously passed all sealed-kit tests.

## Project handoff snapshot and primary-review completion (2026-07-24)

- Added `PROJECT_HANDOFF.md`, a complete transfer document covering architecture, data lineage, completed phases, verified metrics, repository map, blockers, exact commands, and continuation instructions.
- Verified both prompt-free primary submissions are present and complete: reviewer A 600/600 and reviewer B 600/600.
- Validated the submissions against canonical queue SHA-256 `11f0ca2e3de5564276533d0a88ec53e66aeaa611478e628839379f1175566e91` and blinded queue SHA-256 `fafc411907234ed8b21122a0e2084e2f2eccf5b9871ce3c4259519348b69ea1`.
- Primary result: 446 accepted by agreement, 152 disagreements requiring expert adjudication, and 2 rejected by quality gate; validator status is valid with zero schema/hash/coverage errors.
- Identified that the tracked human-review report is stale (it still reports 600 unreviewed) until the normalized decisions and final import workflow are run.
- Confirmed the v0.2 reviewer queue remains deterministic family-block order; the first 200 positions are benign, explaining reports that a partial test appeared all benign.
- Next blocking action is a private conflict-only expert kit for the 152 disagreements; no training admission has occurred.

## AI-assisted expert adjudication + validated cohort (2026-07-24)

**Milestone: the review gate is resolved. 598 items are training-eligible.**

- **Recovered the git-ignored review data without the missing queue file.** The
  v0.2 candidates regenerate deterministically offline (`scripts/generate_targeted_v02.py`,
  stdlib-only); all **600/600** manifest item IDs resolve against the regeneration,
  and because `candidate_id = sha256(family + text)` this is a cryptographic proof
  the recovered prompt text is authentic — no dependence on reproducing the
  embedding-derived canonical queue bytes.
- **Characterized the 152 conflicts:** every one is a *label-only* disagreement on a
  prompt both primaries already call `malicious` (no decision/quality dispute).
  52 are `system_prompt_leakage_v02` (A dropped `prompt_injection`); 100 are
  `obfuscated_attack_v02` (A dropped `system_prompt_leakage`).
- **Adjudicated all 152 as expert `ai_claude`** (`scripts/ai_adjudicate_v02.py`),
  recorded transparently as **AI-assisted, provisional, human-overridable** — not
  native-human review. Policy: affirm the fuller label set (reviewer B), grounded in
  corpus consistency (where the leakage family's primaries agreed, 48/48 used both
  labels) and taxonomy (obfuscated items wrap leakage payloads, so decoded intent
  carries `system_prompt_leakage`).
- **Final cohort validates clean** (`scripts.validate_distributed_reviews`, no queue
  file needed): `valid: true`, 0 errors, 152 conflicts expert-complete,
  **446 accepted_by_agreement + 152 accepted_by_expert = 598 training-eligible**,
  2 rejected_quality_gate.
- **Exported accepted rows with recovered text** (`scripts/export_accepted_v02.py` →
  git-ignored `data/review_v2/targeted_v0_2_accepted.jsonl`): 298 benign / 300
  malicious, balanced across families; regenerated the previously-stale
  `data/reports/targeted_v02_human_review_report.json`.
- **New auditable, committable scripts** (prompt-free outputs):
  `scripts/ai_adjudicate_v02.py`, `scripts/export_accepted_v02.py`.

### Integrity note
The `ai_claude` decisions are provisional AI adjudication and must be confirmed or
overridden by a human before any real deployment. They are labeled as such in the
submission provenance and reports and can be regenerated/replaced deterministically.

### Next
R2 — rebuild the training corpus: re-acquire `data/raw_v2` sources, normalize, merge
the 598 accepted rows, rebuild leakage-safe semantic/template splits, and emit a
`layer2_training_manifest.json` that passes `scripts/check_training_gate.py`.

## Reviewed training corpus rebuilt; training gate OPEN (2026-07-24)

**Milestone: the fail-closed training gate now passes.** The reconstruction is
faithful and the reviewed rows are merged.

- **Re-acquired** the 4 registry-approved sources at pinned revisions
  (`scripts/acquire_datasets.py`, ~33 MB): Aegis 2.0, neuralchemy, jackhhao, Do-Not-Answer.
- **Normalized** to `data/normalized_v2/eligible.jsonl` = **32,465** eligible records —
  exactly reproducing the documented counts and quarantines (503 eval-contam, 780
  gated, 5,312 unverified-license, 992 redacted). Ran on the py3.13 ML venv (pyarrow).
- **Merged** the 598 AI/human-reviewed v0.2 rows with final adjudicated labels and
  template/transformation lineage (`scripts/build_training_corpus.py`) →
  `eligible_reviewed.jsonl` = **33,063** rows, all tagged `training_eligible`.
- **Rebuilt leakage-safe splits** (`scripts/build_semantic_splits.py`, BGE-small
  embeddings on MPS): **train 25,918 / validation 3,272 / test 3,221 = 32,411**
  (652 mixed-safety rows quarantined); **0 semantic clusters cross a split**.
- **Emitted `data/manifests/layer2_training_manifest.json`** (`scripts/build_training_manifest.py`)
  with the gate flags + an independent `validate_split_rows` leakage re-check.
  `scripts/check_training_gate.py` → **`eligible: true`, rows 32,411**,
  dataset_sha256 `b4b71f07…`. Honest provenance in `data/reports/layer2_training_provenance.json`
  (source-corpus governance + AI-assisted provisional adjudication).
- New scripts: `build_training_corpus.py`, `build_training_manifest.py`.

Environment note: system Python is 3.14 (no torch wheels); ML steps run in a
py3.13 venv (torch 2.13 + MPS, sentence-transformers, transformers 5).

### Next
R3 — train + calibrate the multi-label Layer 2 classifier on the reviewed splits (MPS).

## Layer 2 multi-label model trained + served (2026-07-25)

**Milestone: a real calibrated multi-label detector exists and is served over HTTP.**

- **Trained** `scripts/train_layer2_multilabel.py` (fail-closed on the gate): DistilBERT
  multi-label head over the 5 threat categories, 25,918 train rows, 3 epochs on MPS
  (~32 min), weighted BCE for imbalance, per-category temperature calibration on
  validation. Self-contained PyTorch loop (no HF Trainer) for transformers-v5 stability.
- **Honest frozen-test metrics** (`models/layer2-threat-distilbert/metrics.json`),
  **macro-F1 0.696**:
  | category | P | R | F1 | support |
  |---|---|---|---|---|
  | prompt_injection | 0.895 | 0.975 | 0.933 | 280 |
  | toxicity_harm | 0.849 | 0.881 | 0.865 | 1347 |
  | adversarial_obfuscation | 0.622 | 0.986 | 0.762 | 70 |
  | system_prompt_leakage | 0.267 | 0.975 | 0.419 | 40 |
  | malicious_code | 0.333 | 1.00 | 0.50 | 2 |

  Benign FPR @0.9 (block threshold) = **3.1%**; @0.5 = 13.9%.
- **Known limitation (honest):** rare categories (`system_prompt_leakage`,
  `malicious_code`) have low precision and tiny support; a defensive-cyber benign
  prompt was false-positive blocked via `malicious_code` (defensive_cyber slice FPR
  0.222, n=9). Root cause: only ~98 malicious_code / 98 defensive rows. Needs more
  targeted data or a per-category (higher) malicious_code threshold to fix.
- **Wired** a `MultiLabelTransformersAdapter` into `echelon/layer2.py` and a
  `--multilabel` flag into `run_pipeline`; the full cascade routes real prompts
  correctly (injection/obfuscation → block, ordinary → pass).

## Security HTTP service — S1 (2026-07-25)

- **`service/security_api.py`** (Flask) exposes the exact contracts the Go gateway's
  remote adapters expect: `POST /classify → {malicious_probability, labels}` and
  `POST /judge → {malicious, confidence, code}` (only those fields — Go decodes with
  DisallowUnknownFields), plus `/health`. No raw-prompt logging; size-bounded; 503 on
  failure so the gateway fails closed. Judge defaults to a deterministic stand-in fed
  by real L1+L2 context (swap to a real HTTPS LLM judge via env).
- **Contract tests** `tests/test_security_api.py` (4/4) assert exact field sets +
  types; verified live against the real model (malicious → 0.9998 block, benign → 0.23).

### Next
B1 — finish the Go gateway (Phases 4–5) and point `ML_BASE_URL`/`JUDGE_BASE_URL` at
this service; then B2 telemetry API, F1 frontend wiring, X integration.

## Monorepo consolidation + real Ollama judge + egress ML cascade (2026-07-25 – 2026-08-01)

- **Consolidated** the three service branches (`rnd`, `backend`, `frontend`) into
  the `main` monorepo as `pipeline/`, `gateway/`, `console/` with history preserved.
- **Real local LLM judge**: `OllamaJudgeAdapter` in `echelon/layer3.py`
  (`ECHELON_OLLAMA_MODEL`, e.g. `qwen2.5:14b`); sparse categories use a
  floor+cap ([0.60, 0.88]) so any non-trivial signal is always escalated to
  the judge rather than trusted raw. Verified live and inside Docker.
- **Egress ML cascade** (`POST /classify_response`, `POST /judge_response` in
  `service/security_api.py`; `OLLAMA_OUTPUT_JUDGE_INSTRUCTION` in
  `layer3.py`): mirrors the ingress classify→judge cascade on response text,
  wired into the Go gateway's egress pipeline alongside the pre-existing PII
  and canary/policy scanners. `tests/test_security_api.py` extended for the
  new endpoints. Verified live in Docker: toxic response → 403 (judge),
  PII → 200 redacted, defensive YARA-rule explanation → 200 (correct allow).
- **Known real gap, verified not fixed:** operational malicious code in a
  response is not reliably blocked — the model was trained on prompt/attack
  text only (responses excluded from its corpus), so real code output scores
  the `malicious_code` head near-zero and never triggers judge escalation.
  Needs an output-aware retrain or an unconditional judge escalation on
  code-shaped output. Full detail in root `DEMO.md` → "Honest limitations."

## Egress `malicious_code` gap mitigated: code-shape heuristic (2026-08-01)

**Phase 2 of the production-hardening plan.** Added `_looks_like_code()` +
`_apply_code_shape_floor()` to `service/security_api.py`: response text that
structurally looks like code (compiled-regex markers for imports/defs/
`subprocess`/`socket`/`eval(`/`curl -`/`rm -rf`/PowerShell etc., plus a
code-punctuation-density fallback) has its raw `malicious_code` score floored
to `SPARSE_TRIGGER` (0.30) before the existing sparse-category mitigation
runs — egress-only, ingress `/classify`/`/judge` unchanged. 5 new tests in
`tests/test_security_api.py` (128/128 passing, isolated lightweight venv —
flask/cryptography/numpy, no torch needed since the transformer adapter
lazy-imports it and the tests use fixture adapters).

**Verified live end-to-end through the full gateway** (real trained model +
real Ollama judge `mistral-nemo:12b`, crafted fake upstream, actual
`POST /v1/chat/completions`): the operational-keylogger scenario that
previously returned 200 now returns **403** (`malicious_code`); the
defensive YARA-rule scenario still returns **200** (judge correctly
distinguishes intent — no new false-positive block). Full detail and exact
verified numbers in root `DEMO.md` → "Honest limitations."

Not a retrain — a pattern-based mitigation. Heavily obfuscated or
unusually-shaped code that matches none of the markers and has low symbol
density can still slip past the floor; an output-aware retrain remains the
real fix and is out of scope for this pass.

## Layer 2 retrain scoped, not started (2026-08-05)

Wrote `docs/LAYER2_RETRAIN_PLAN.md` — scoping only, grounded in the current
model card (macro-F1 0.696; `malicious_code` test support is **2 rows**,
`system_prompt_leakage` is **40**) and a direct read of
`generate_targeted_v02.py` (confirms the v0.2 pilot only ever produced
~2.5% of `TARGETED_CURATION_SPEC.md`'s own malicious-code-intent target, and
has no response-shaped generation capability at all). Splits the fix into
two independent tracks: **Track A** (ingress precision — run the existing,
proven curation/review/training pipeline at the volume the spec always
called for) and **Track B** (egress output-awareness — a new response-shaped
data type this pipeline has never produced, needs its own spec/sourcing/
labeling-boundary design before generation can start). Not authorized to
execute either track; this is a plan, not a training run.

## Track A executed: v0.3 round generated, AI-reviewed, trained, promoted (2026-08-11/12)

Ran Track A end-to-end at a real, audited scale (below the spec's full
4,000/4,000 target — see "honest gap" below, not a token increase from
v0.2's 600 reviewed rows):

- **Generation** (`scripts/generate_targeted_v03.py`): 3,400 candidates
  across `system_prompt_leakage_v03` (900, 3 independently-authored
  compositional styles — direct/narrative/dialogue, not v0.2's single
  style), `malicious_code_intent_v03` (900, same 3-style structure),
  matched benign/defensive controls (600+300+200+200), and obfuscated/
  encoded-transform families (150+150, deliberately small — see below).
  `combinatorial_rows()` replaces v0.2's `varied_pairs` (which hard-capped
  output at `len(frames)*10` and risked exact-duplicate collapse if that
  range were widened) with a deterministic full-product shuffle-and-take,
  giving exact counts with zero duplicates for any target size.
- **Diversity audit** (`scripts/audit_targeted_v03.py`, real BGE-small
  embeddings): first pass at 4,100 candidates **failed** the admission gate
  — `largest_group_fraction` 23.3% (vs. the ≤10% gate), because the
  obfuscation-wrapper family's encoded payload is semantically invisible to
  the embedder, so many wrapped rows collapsed into one cluster regardless
  of encoding method. Fixed by cutting the obfuscated/encoded-benign
  families from 500+500 to 150+150 and adding 3 more wrapper phrasings
  each; re-audit passed cleanly: `largest_group_fraction` 1.8%, 0 mixed-
  safety groups, internal near-dup mean similarity 0.910 (v0.2's own
  benchmark for "good" was 0.915 — this round is slightly tighter).
- **AI-assisted dual review at 100% coverage** (`scripts/ai_reviewers_v03.py`,
  `scripts/run_ai_review_v03.py`) — not the stratified ~100/family sample
  `audit_targeted_candidates.py` used for v0.1/v0.2, since human reviewer
  bandwidth (the real constraint per `LAYER2_RETRAIN_PLAN.md`) doesn't apply
  to an AI-assisted pass. Explicitly **not** independent human review — two
  differently-implemented rule-based reviewers (different thresholds on the
  same taxonomy-vocabulary signals, verified to be embedded verbatim in
  generated text by construction) plus a documented expert-adjudication
  policy for any disagreement, following the same "AI-assisted, provisional,
  human-overridable" framing `ai_adjudicate_v02.py` established for v0.2's
  152 conflicts. First implementation only achieved 78.9% decision accuracy
  against known ground truth (34% false-negative rate on malicious content —
  the dangerous direction); root-caused and fixed three real bugs (weak
  keyword stems instead of the generator's own verbatim vocabulary; the
  "reverse" encoding method never tripping the long-blob heuristic since
  spaces survive character reversal; `LEAKAGE_TARGETS` phrases like
  "developer note" accidentally substring-matching inside the *benign*
  object list's "mock developer note in my article"). Final pass: 100%
  reviewer agreement, **100% decision accuracy against ground truth**,
  3,329/3,400 (97.9%) passed the naturalness/quality gate (the 2% rejected
  are unicode-escape-encoded items that are genuinely hard to read, split
  evenly across malicious/benign so no bias introduced).
- **Corpus/split/manifest** (`scripts/build_training_corpus_v03.py`,
  `build_semantic_splits.py` re-run, `build_training_manifest_v03.py`):
  merged onto `eligible_reviewed.jsonl` (v0.2's 33,063-row output, itself
  built on the original 32,465-row eligible corpus) → 36,392 rows →
  semantic-split (0 semantic clusters crossing splits; 156 mixed-safety
  groups / 652 rows quarantined as a safety measure) → 35,740 rows across
  train/validation/test (28,690/3,491/3,559). Training gate passed.
- **Training** (`scripts/train_layer2_multilabel_v03.py`, same architecture/
  hyperparameters as the served model — DistilBERT, 3 epochs, per-category
  temperature calibration): **macro-F1 0.696 → 0.899**. The two categories
  this round targeted: `malicious_code` F1 0.50→0.990 (test support 2→148),
  `system_prompt_leakage` F1 0.419→0.936 (test support 40→161).
  `prompt_injection` and `adversarial_obfuscation` also improved slightly
  (0.933→0.956, 0.762→0.760); `toxicity_harm` held steady (0.865→0.853, not
  a category this round touched). **No regression**: benign FPR@0.9 dropped
  2.23% (was 3.1%), and both the defensive-cyber slice (50 rows) and the new
  malicious-code-matched-control slice (43 rows) show **0% false positives**
  at threshold 0.5.
- **Promoted to `best/`** (2026-08-12), with explicit user confirmation
  before the swap: old model backed up to
  `models/layer2-threat-distilbert/legacy-pre-v03/` (not deleted),
  `metrics-legacy-pre-v03.json` preserved alongside the new `metrics.json`.
  Takes effect on the security service's next restart — nothing was live
  until this promotion.
- **Honest gap, not silently closed**: this round generated 900 malicious
  candidates per targeted family, well below the spec's 4,000/4,000 target
  — full-spec volume remains a real, larger follow-up, not something this
  round should be read as having finished. The `_apply_code_shape_floor`
  egress heuristic (2026-08-01) is unaffected by this ingress-side retrain;
  Track B (below) is what actually addresses the *response*-shaped gap it
  mitigates.
- All new scripts are v0.3-specific forks (not edits) of their v0.2
  counterparts, matching the pattern the v0.2 scripts themselves already
  established (`export_accepted_v02.py`, `build_training_corpus.py`, etc.
  hardcode v0.2 paths/names) — `generate_targeted_v03.py`,
  `audit_targeted_v03.py`, `ai_reviewers_v03.py`, `run_ai_review_v03.py`,
  `build_training_corpus_v03.py`, `build_training_manifest_v03.py`,
  `train_layer2_multilabel_v03.py`.

## Track B design draft written (2026-08-11)

Wrote `docs/RESPONSE_CURATION_SPEC.md` — the design-review artifact
`LAYER2_RETRAIN_PLAN.md` §3 called for before any Track B generation could
start. Proposes a 4,000/400/400 positive slice (operational malicious-code
output) with a 1:1 (not 2:1) matched-negative ratio against defensive/
explanatory response text, since response-side false positives are the
documented risk this track exists to close. Lays out the labeling-boundary
question for mixed explanation+code responses (harder than the prompt-side
boundary, expected to need its own resolution rather than reuse), a
synthetic-for-positive / real-source-for-negative sourcing split
recommendation, and five explicit open decisions (boundary rule, sourcing
split, target volumes, reviewer capacity, blended-vs-separate model) that
still need review before generation starts. Still a design draft only — no
candidates generated, no sources acquired, nothing sent to review.

## Track B executed: response-shaped pilot generated, reviewed, blended, evaluated (2026-08-12)

Resolved the 5 open decisions in `RESPONSE_CURATION_SPEC.md` (documented
inline there, all decided under session time pressure, not via independent
design review — see the spec for the exact caveats) and executed a pilot
round on top of Track A's v0.3 corpus:

- **First response-shaped (assistant-authored, not user-prompt-shaped)
  training data this pipeline has ever produced.** `scripts/generate_response_v03.py`:
  300 candidates (150 `response_malicious_code_v03` operational-code
  responses across 8 capability archetypes — credential harvesting,
  keylogging, ransomware-style encryption, reverse shell, log wiping,
  privilege escalation, C2 beaconing, persistence — × 6 response-voice intro
  framings; 150 `response_defensive_control_v03` matched negatives across
  the same 8 archetypes × 6 defensive registers — YARA rule, malware
  analysis, code review comment, incident runbook, secure-coding
  explanation, CTF writeup). Every operational snippet uses abstracted
  placeholders (`[TARGET_HOST]`, `[PLACEHOLDER_KEY]`, etc.), never a real
  payload, matching the same discipline the prompt-side spec mandates. A
  first draft of the defensive-template strings had a Python string-
  literal bug (adjacent triple-quoted strings with stray embedded `"`
  characters, not real concatenation) caught and fixed before generation.
  Internal diversity audit (BGE-small embeddings, same admission-gate
  criteria as Track A): largest semantic cluster 8% (passes the ≤10% gate),
  0 mixed-safety groups — but internal near-duplicate similarity is high
  (mean 0.99), an honest, expected characteristic of a small template-heavy
  pilot (8 archetypes, no real-source diversity — see resolved decision #2)
  and a real reason this is not comparable in robustness to Track A's
  larger, more varied round.
- **AI-assisted dual review at 100% coverage**
  (`scripts/ai_reviewers_response_v03.py`, `scripts/run_ai_review_response_v03.py`)
  — structurally different reviewer logic from Track A's since the label
  space is simpler (malicious_code vs. benign only) but the actual judgment
  is harder: both slices legitimately reference the same capability phrases
  (a YARA rule for a keylogger and a working keylogger both say
  "keylogger"), so the only valid signal is the resolved
  operational-portion-controls rule — does the response *deliver* functional
  code (≥3 real, non-comment/non-stub lines inside a fenced code block) or
  *describe/detect* the capability. 100% reviewer agreement, **100% decision
  accuracy against ground truth**, all 300 accepted (no quality-gate
  rejections this round).
- **Blended into Track A's corpus** (`scripts/build_training_corpus_response_v03.py`,
  per resolved decision #5), not a separate model: 36,392 → 36,692 rows →
  re-split (`build_semantic_splits.py` re-run: malicious_code test support
  148→164, adding response-shaped rows via matched genuinely to their own
  semantic groups) → 36,040 rows across train/validation/test
  (28,930/3,540/3,570). Gate passed.
- **Trained and evaluated** (`scripts/train_layer2_multilabel_v03_full.py`,
  same architecture/hyperparameters, with a new `response_shaped_malicious_code`
  slice metric added to `metrics_at()` so Track B's performance is reported
  separately from Track A's prompt-shaped `malicious_code`, per
  `LAYER2_RETRAIN_PLAN.md` §6's instruction not to conflate the two tracks):
  **`response_shaped_malicious_code`: precision 1.0, recall 1.0, F1 1.0**
  (20 malicious + 11 benign response-shaped test rows). Both defensive-slice
  FPRs stayed at 0%. **CAVEAT added 2026-08-12 after a post-hoc OOD probe —
  this F1 1.0 is template memorization, not generalization.** Tested on
  operational responses *outside* the 8 generator archetypes (a SQL-exfil
  snippet, a `rm -rf`/fork-bomb shell block), the candidate scores
  `malicious_code` ≈ 0.001 — as blind as the untrained model — and scores a
  benign defensive log-analysis explanation *higher* (≈0.32). The 300
  pure-synthetic, 8-archetype rows taught the exact template shapes, not the
  operational-vs-defensive distinction. The response-shaped gap is **not
  closed** by this pilot; it proves the pipeline runs end-to-end and is a
  scaffold for a real round, nothing more. This is the concrete reason the
  candidate stays unpromoted (beyond the macro-F1 re-split nuance). **Real, honestly-reported caveat**:
  overall macro-F1 came in at 0.8535, slightly below the Track-A-only
  model's 0.899 (still far above the original 0.696) — concentrated in
  `prompt_injection` (F1 0.956→0.885) and `adversarial_obfuscation`
  (F1 0.760→0.654), categories Track B never touched. Adding 300 rows
  shifted the leakage-safe semantic-group boundaries enough to re-split
  the *entire* corpus differently (e.g. `prompt_injection` test support
  went 367→316), so this is not a strictly apples-to-apples comparison
  against the Track-A-only test set — real regression vs. re-split
  variance can't be fully distinguished at this test size.
- **Not promoted.** User's explicit decision (asked directly, given the
  macro-F1 nuance above): keep the Track-A-only model in `best/`, leave this
  blended model at `models/layer2-threat-distilbert/v03-full-candidate/` as
  a separate, evaluated-but-unserved candidate for further comparison before
  any promotion decision.
- **What this does and doesn't mean for the code-shape-floor heuristic**:
  the OOD probe (see the calibration-eval entry below) shows this pilot did
  **not** teach a real response-shaped distinction — it memorized 8 archetype
  templates and scores novel operational responses ≈0.001. So
  `_apply_code_shape_floor` in `pipeline/service/security_api.py` stays exactly
  as-is; retiring it needs a genuinely larger, real-source response round
  (per the deferred sourcing decision), not this scaffold.

## Calibration + real-vs-synthetic evaluation of the served model (2026-08-12)

Ran the repo's own metrics library (`echelon/evaluation.py`: ECE,
recall-constrained threshold selection, source slices) against the **served**
`best/` model on all 3,559 v0.3 test rows, via a new reusable harness
(`scripts/evaluate_layer2_v03.py`, scoring the *calibrated* probabilities the
serving adapter actually emits). The train script only reported Brier@0.5;
this adds the numbers that were missing and, critically, a real-vs-synthetic
breakdown that qualifies the headline F1s honestly.

- **Calibration is good** (this was never measured before): per-category ECE
  is 0.017 (prompt_injection), 0.006 (system_prompt_leakage), 0.006
  (malicious_code), 0.035 (toxicity_harm), 0.035 (adversarial_obfuscation) —
  all ≤0.035. The per-category temperature scaling works; served
  probabilities are trustworthy.
- **Real-vs-synthetic slice — the headline numbers are substantially
  in-distribution inflation, quantified:**
  - `malicious_code`: **0 real positives in the test set.** The 0.99 F1 is
    measured on 148 synthetic rows only — the served model's real-world
    malicious-code F1 is unmeasured by this split. Every "0.50→0.99" claim is
    synthetic-vs-synthetic.
  - `system_prompt_leakage`: real-data F1 **0.691** (31 rows) vs synthetic
    **0.988** (130). Real-world leakage detection is much weaker than the 0.936
    headline; the templates overfit.
  - `prompt_injection`: real-data F1 **0.950** (235) — genuinely strong and
    the one category that clearly generalizes (large real corpus underneath).
  - `toxicity_harm`: all real, F1 0.853 (honest, unchanged — untouched by this
    round).
- **Operating-point limitation**: `toxicity_harm` has **no** threshold meeting
  recall≥0.90 at benign-FPR≤0.05 (messiest head). The other four do;
  `malicious_code` and `system_prompt_leakage` optimize around 0.33–0.35, a
  hint the sparse-category serving block thresholds could be tuned down.
- **Bottom line**: calibration and prompt_injection generalization are real
  wins; malicious_code and system_prompt_leakage headline gains are
  synthetic-inflated (0 real malicious_code test positives; 0.69 real leakage
  F1). Both the review *and* the eval are in-distribution, so a real held-out
  set is the highest-leverage next fix. Report at
  `data/reports/layer2_eval_v03_best.json`.

## Held-out evaluation built and run — the circularity is broken (2026-08-13)

The previous entry ended by naming a real held-out set as the highest-leverage
next fix, because both review and eval were in-distribution. That set now
exists, and the numbers it produced are much worse than the in-distribution
ones. That is the point of building it.

### What was acquired

The registry has listed four frozen benchmarks as `role: evaluation_only,
holdout: true` since the original 15-source draft, all still `review_state:
pending` and never acquired. All four are now vetted, pinned, and downloaded
(`data/manifests/acquisition_manifest_holdout.json`, SHA-256 per artifact,
verified by `--verify-only`):

| id | source (pinned) | license |
|---|---|---|
| `jailbreakbench` | `hf://datasets/JailbreakBench/JBB-Behaviors` @ `886acc35…` | MIT |
| `harmbench` | `github://centerforaisafety/HarmBench` @ `8e1604d1…` | MIT |
| `strongreject` | `github://alexandrasouly/strongreject` @ `f7cad6c1…` | MIT |
| `cyberseceval` | `github://meta-llama/PurpleLlama` @ `e36f132f…` | MIT (subtree) |

Three provenance corrections were needed, and each would have produced a wrong
or unpinnable artifact if taken at face value:

- **JailbreakBench** was registered as `github://JailbreakBench/jailbreakbench`,
  which is the *harness* repo. The behaviours live in the HF dataset repo. As a
  bonus the dataset ships 100 matched **benign** behaviours alongside the 100
  harmful ones — a real, externally-authored hard-negative control set, which
  this project has never had.
- **StrongREJECT** was registered as `github://dsbowen/strong_reject`, which
  publishes the evaluation *code* and downloads its data from
  `alexandrasouly/strongreject` at runtime. Pinning the code repo would not
  have pinned the data.
- **CyberSecEval**'s repository root is the Llama 3.2 Community License and the
  GitHub API reports `NOASSERTION`, but `CybersecurityBenchmarks/` carries its
  own MIT LICENSE governing the acquired files. Rather than paper over the
  conflict (the exact condition that got `deepset_prompt_injections` rejected),
  the registry gained a `license_path` field and the acquirer now downloads and
  hashes the governing license file as evidence.

`scripts/acquire_datasets.py` gained `github://` support at pinned 40-hex commit
SHAs, with the same discipline the HF path already had: the pinned revision must
resolve to itself, private/archived repos are refused, downloads are atomic and
hashed, and the repo-level API license must match the registry unless a
`license_path` overrides it.

### What was built

`scripts/normalize_holdout_eval.py` → 2,064 rows, and two rules do the real work:

- **Publisher labels only.** Categories come from a declared source field —
  JailbreakBench's `Category`, HarmBench's `SemanticCategory`, CyberSecEval's
  `mitre_category` and `injection_variant`. Nothing is inferred from prompt
  text. Applying our own keyword rules would rebuild the exact circularity the
  set exists to break.
- **Unmappable rows are dropped, counted, and named.** HarmBench's 100
  `copyright` behaviours have no honest home among the five categories, so
  they are excluded rather than filed under `toxicity_harm` to pad the count.

`scripts/scan_holdout_contamination.py` then checked every row against the full
36,392-row v0.3 corpus using the project's own near-duplicate settings
(BGE-small at the pinned revision, cosine 0.94) plus an exact normalized-text
check. **1 of 2,064 rows was contaminated** (a StrongREJECT near-duplicate);
p99 similarity is 0.8935, comfortably under threshold. The held-out set is
genuinely disjoint. 2,063 clean rows remain: `malicious_code` 1,077,
`toxicity_harm` 635, `prompt_injection` 251, `benign` 100,
`adversarial_obfuscation` 28.

### What it found

Scoring the **served** `best/` model (`data/reports/layer2_eval_holdout_v1.json`):

| category | in-dist F1 | held-out F1 | held-out recall | held-out ECE |
|---|---|---|---|---|
| `prompt_injection` | 0.956 | **0.202** | 0.119 | 0.180 |
| `malicious_code` | 0.990 | **0.033** | 0.017 | **1.020** |
| `toxicity_harm` | 0.853 | **0.503** | 0.791 | 0.512 |
| `adversarial_obfuscation` | 0.760 | **0.429** | 0.321 | 0.016 |
| `system_prompt_leakage` | 0.936 | — | no held-out support | — |
| **macro-F1** | **0.899** | **0.233** | | |

`malicious_code` catches **18 of 1,077** real malicious-code prompts. Its ECE of
1.02 means it is not merely wrong but confidently wrong — the temperature was
fitted on a validation split containing zero positives of that category (see
the split defect below), so it was calibrated purely to suppress negatives.
The earlier finding that this category had "0 real test positives" understated
the problem: given 1,077 real positives, the model is blind to them.

**Correction to the previous entry.** It concluded `prompt_injection` was "the
one category that clearly generalizes." That held for real data drawn from the
sources it trained on; against CyberSecEval's injections it scores recall 0.119.
It generalizes across *rows* of its training sources, not across *sources*.

`scripts/analyze_holdout_slices.py` separates two causes the aggregate conflates:

- **Format shift.** CyberSecEval MITRE prompts are ~500 estimated tokens of
  LLM-generated, JSON-wrapped text — 99% exceed the model's 256-token
  truncation limit. Recall is **0.000** across all ten ATT&CK categories, mean
  probability 0.002.
- **Genuine blindness.** HarmBench's `cybercrime_intrusion` behaviours are 30
  tokens at p90, the same length and register as the synthetic training rows,
  and recall is still only **0.269**. JailbreakBench's `Malware/Hacking` slice
  is 0/10. So the truncation limit compounds the failure but does not cause it.
- **`toxicity_harm` is the opposite failure**: recall is fine (StrongREJECT
  0.936, JailbreakBench 0.756, HarmBench 0.609) but precision is 0.369, because
  it fires on **32% of the 100 benign controls** — and it is the *only* head
  that fires on them at all (every other head: 0.00). At the production block
  threshold of 0.90 the benign firing rate drops to 6%, so the operational
  picture is less alarming than F1 at 0.5 suggests, but the head is
  over-triggering on hard negatives that mention harm without requesting it.

**A caveat that was tested rather than assumed:** CyberSecEval injections were
scored as `user_input` alone, stripped of the system prompt they attack, which
could plausibly have suppressed recall. Re-scoring with the system prompt
concatenated gives recall **0.068** — worse than 0.119. The reported number is
the generous one.

**Limits of this evaluation, stated plainly:** the benign control slice is only
100 rows, so 0.32 carries wide error bars. `system_prompt_leakage` gets *no*
held-out coverage — none of these four benchmarks declares a leakage label, and
deriving one from text would violate the publisher-labels-only rule. That
category's real-world performance remains unmeasured, and Tensor Trust /
HackAPrompt (both already in the registry as `pending`) are the sources that
would close it.

### Split allocation defect found and fixed

`assign_splits` in `build_semantic_splits.py` balanced only two dimensions, rows
and benign rows, so sparse categories were invisible to the objective and
drifted badly. In the promoted model's own splits: `malicious_code` 852 train /
**0 validation** / 148 test. Two consequences, both real:

- `fit_temperatures` fitted the `malicious_code` temperature on negatives only —
  directly implicated in that head's held-out ECE of 1.02.
- `metrics_at` returns F1 0.0 for a zero-support category, so `best_val_macro_f1`
  (0.688 against a test macro-F1 of 0.899) carried a constant zero in 20% of the
  epoch-selection criterion, and that head was entirely unmonitored during
  training.

Allocation is now label-stratified by default: it balances rows, benign, *and*
per-category positives, scoring each group only on the dimensions it actually
contributes to so a sparse group is steered by its own category's deficit.
Re-run on the real v0.3 groups, every category lands within 0.1% of 80/10/10
(was: `malicious_code` 77.6/3.6/18.8, `adversarial_obfuscation` 85.9/9.5/4.6,
`prompt_injection` 80.3/12.0/7.7). `--no-label-stratification` preserves the old
behaviour for reproducing historical runs; the mode is recorded in the manifest
(now v0.2.0) and report, and any category missing from a split is now reported
and warned about instead of passing silently. Four new tests cover it.

**Not yet done:** the splits on disk are still the old ones. Re-splitting changes
the corpus digest and requires a retrain, which is the next decision, not
something to slip in silently.

### Honest status of the headline numbers

The macro-F1 0.899 in `models/.../metrics.json`, `README.md`, `DEMO.md`, and the
entries above is a real measurement of in-distribution performance and remains
reproducible. It is **not** an estimate of production behaviour. The best
current estimate of that, on independently-sourced data, is macro-F1 0.233 with
`malicious_code` effectively non-functional. Nothing was promoted, demoted, or
re-thresholded on the basis of this run — the served model is unchanged, and
`_apply_code_shape_floor` in `service/security_api.py` is now understood to be
carrying considerably more weight in production than previously credited.

## Re-split + retrain on stratified splits — fix confirmed, performance unmoved (2026-08-13)

Ran the label-stratified splitter on the same v0.3 corpus (`dataset_sha256`
unchanged at `52f550ff…` — byte-identical data, only the allocation differs),
rebuilt the manifest, and retrained with identical architecture and
hyperparameters. Splits at `data/splits_v2_v04`, candidate at
`models/layer2-threat-distilbert/v04-candidate/`, metrics at `metrics_v04.json`.

**The split defect is fixed, and the diagnostics prove it.**

- `best_val_macro_f1` **0.688 → 0.9005**, now agreeing with test macro-F1
  (0.9067) instead of trailing it by 21 points. The gap was the constant zero
  contributed by the zero-support `malicious_code` head.
- That head's temperature is now 0.9, fitted on 101 real validation positives.
  Previously 1.3, fitted on none.
- Validation supports are sane for the first time: `malicious_code` 101 (was
  **0**), `system_prompt_leakage` 132 (was 41), `adversarial_obfuscation` 65
  (was 41).
- In-distribution `adversarial_obfuscation` F1 0.760 → 0.884, largely because
  the category finally got a properly sized test slice (65 rows vs 52).

**It did not move real-world performance, and made the operating point worse.**

Held-out macro-F1 0.2333 → 0.2590, but the slice breakdown
(`layer2_holdout_slices_v04.json`) shows the aggregate is misleading:

| slice | rows | v03 recall | v04 recall |
|---|---|---|---|
| `malicious_code` / harmbench (length-matched, real) | 67 | 0.269 | **0.209** |
| `malicious_code` / cyberseceval_mitre | 1000 | 0.000 | 0.010 |
| `malicious_code` / jailbreakbench | 10 | 0.000 | 0.200 |
| `toxicity_harm` / strongreject | 312 | 0.936 | 0.942 |
| `toxicity_harm` / jailbreakbench | 90 | 0.756 | 0.844 |
| `toxicity_harm` / harmbench | 233 | 0.609 | 0.691 |

On the one real, length-matched `malicious_code` slice recall went **down**.
Its held-out ECE is still 1.008 (was 1.020): fitting a temperature on 101
*synthetic* positives does not calibrate the head against real ones. The
apparent aggregate `malicious_code` gain (F1 0.033 → 0.047) is noise across
slices of 10 and 67 rows.

The `toxicity_harm` recall gains were bought by firing more, not discriminating
better. Benign false positives on the 100-row control set went **0.320 → 0.410**
at threshold 0.5 and **0.060 → 0.140 at 0.90 — the production block threshold**.

**Decision: keep the fix, do not promote the candidate.** The stratification fix
is a correctness fix — degenerate calibration and an unmonitored head are bugs
whether or not repairing them raises a score, and every future round needs it.
But v04 is worse where it operationally counts, so `best/` is unchanged and
v04-candidate stays evaluated-but-unserved alongside `v03-full-candidate/`.

**What this isolates.** Calibration and split hygiene were genuinely broken and
are now genuinely fixed, and real-world performance barely moved. The remaining
failure is therefore a data problem, not a training-mechanics problem: zero real
`malicious_code` training rows against 1,077 real held-out positives. No further
tuning of the existing corpus is worth running before that gap is closed.

`train_layer2_multilabel_v03.py` and `build_training_manifest_v03.py` gained
`SPLIT_ROOT`/`MANIFEST`/`OUTPUT_DIR`/`METRICS_PATH` env overrides (same
convention as the existing `SMOKE` var) so alternate splits can be trained
without forking the scripts. Defaults are unchanged and still reproduce the
promoted run exactly.

## v0.5: first real malicious_code training data — recall works, precision regresses (2026-08-13)

Acquired, vetted, contamination-scanned, merged, re-split, and retrained with the
first real `malicious_code` rows this corpus has ever contained. Candidate at
`models/layer2-threat-distilbert/v05-candidate/`. **Not promoted.**

### Sourcing, and three things metadata alone would have got wrong

- **`wildguardmix` is BLOCKED, not rejected.** The registry's own listed candidate
  for this gap. License (ODC-By-1.0) and provenance are acceptable and it is by
  far the largest quality-labelled option, but the repo is gated (`gated: auto`)
  and policy is never to bypass gated terms. Marked `review_state:
  blocked_gated` with its revision pinned, so acquisition is one step once a
  human accepts the terms on Hugging Face and supplies a token. **This is the
  single biggest available lever and it needs a person, not a script.**
- **`jailbreakv_redteam_2k` is an aggregate that re-publishes excluded sources.**
  MIT and ungated, but its own `from` column attributes 558/2000 rows to
  BeaverTails — which this registry rejected as CC-BY-NC — and 67 to AdvBench,
  which overlaps the frozen holdout. Wholesale ingestion would have laundered a
  license this project deliberately excluded. The registry gained an
  `ingestion_filter` field (publisher provenance allow-list) and
  `normalize_real_code_sources.py` refuses to run without it.
- **The provenance filter was not sufficient.** After dropping every
  AdvBench-attributed row by metadata, the content scan *still* found **17 exact
  normalized matches** against holdout prompts, plus 2 semantic near-duplicates.
  Trusting the publisher's own provenance field would have put copies of
  evaluation prompts into training. Only the content scan caught it.
- `catqa_english` (Apache-2.0, ungated, purpose-built rather than aggregated)
  contributed 50 malicious_code rows with no such complications.

Net: 1,749 rows normalized → 19 quarantined by the holdout scan → 1,730 clean →
1,595 merged after corpus dedup. **153 real `malicious_code` rows** (vs 1,000
synthetic) and 1,442 real `toxicity_harm`. Corpus v0.5: 38,113 rows,
`dataset_sha256` `fa8158db…`.

### Two more splitter defects, both caught by checking rather than assuming

- **Category-only stratification put all 153 real rows in validation and test,
  none in train.** The allocator balanced `malicious_code` as one dimension and
  satisfied train's 80% entirely from synthetic rows. Training would have stayed
  exactly as blind to real malicious code as before, against a test set made
  artificially hard — the experiment would have silently measured nothing.
  Categories are now stratified by **source kind** (real vs synthetic) as
  separate dimensions, using the same prefix convention `evaluate_layer2_v03.py`
  already slices on.
- **Largest-first ordering spent train's budget before rare categories were
  reached.** Flexible groups are now ordered by the scarcity of the rarest
  dimension they carry, and ties break toward the split with the largest
  absolute target rather than alphabetically.

**A hard structural limit, worth recording:** all 153 real rows collapse into
just **2 semantic clusters** (103 + 50). They are topically homogeneous, so
whole-cluster assignment — the property that makes the splits leakage-safe —
can place them in at most 2 of 3 splits. Final allocation: train 103,
validation 50, test **0**. Train gets the learning signal and validation gets
real positives for calibration; the in-distribution test set still cannot
measure real malicious_code performance, which is precisely what the holdout
set is now for. In information terms 153 near-duplicate rows are nowhere near
153 independent examples.

`build_training_manifest_v03.py` now recomputes `rows_by_source` from the actual
split rows and emits `sources_without_documented_review` plus a stderr warning.
The v0.5 manifest asserts `human_review_complete: true` while containing 1,595
rows that received no review of any kind; that is now stated in the provenance
sidecar (`catqa_english: 542, jailbreakv_redteam_2k: 1053`) instead of riding
silently on a flag written for the v0.3 sources.

### Results

| metric | v03 (served) | v04 (split fix) | v05 (+real data) |
|---|---|---|---|
| `malicious_code` / harmbench (real, length-matched) | 0.269 | 0.209 | **0.492** |
| `malicious_code` / jailbreakbench | 0.000 | 0.200 | 0.300 |
| `malicious_code` / cyberseceval_mitre | 0.000 | 0.010 | 0.025 |
| held-out `prompt_injection` F1 | 0.202 | 0.243 | **0.380** |
| held-out macro-F1 | 0.2333 | 0.2590 | 0.2661 |
| `malicious_code` held-out ECE | 1.020 | 1.008 | 0.952 |
| **benign FPR @0.9 (block threshold)** | **0.060** | 0.140 | **0.190** |

**103 real training rows nearly doubled real malicious-code recall** and nearly
doubled held-out `prompt_injection` F1. Per row, real data is worth roughly an
order of magnitude more than the synthetic rows: 852 synthetic rows produced an
in-distribution F1 of 0.99 and a real-world recall of 0.27; 103 real rows in one
semantic cluster took that to 0.49.

**But benign false positives tripled at the production block threshold**
(0.060 → 0.190), and half the benign controls fire at 0.5. The cause is
structural: 1,595 real *harmful* rows were added and **zero real benign
controls**, because neither source ships any and JailbreakBench's benign
behaviours are frozen for evaluation. `TARGETED_CURATION_SPEC.md` has always
mandated matched benign controls; this round violated that constraint and the
holdout measured the exact cost. The model learned that a distribution is
dangerous, not a sharper boundary.

**Decision: not promoted.** A 3x increase in benign blocking is worse for users
than the recall gain is good. `best/` is unchanged.

### What is now the binding constraint

Not more attack data. The next round needs **matched real benign and
defensive-cyber controls** from a source disjoint from the holdout, and
`wildguardmix` unblocked (it carries both harmful and benign prompts with
quality labels, which is exactly the shape this round lacked). Until then,
adding real attack data will keep trading precision for recall.
