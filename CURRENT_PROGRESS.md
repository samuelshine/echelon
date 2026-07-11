# Echelon Current Progress

## Status

**Phase:** 1 — Research plan and architecture initialization  
**Branch:** `rnd`  
**Checkpoint:** Awaiting collaborator review before Python implementation

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

## Decisions pending collaborator approval

- Whether `0.40` and `0.85` are acceptable starting escalation/block boundaries before empirical tuning.
- The acceptable false-positive budget and minimum recall for each threat family.
- Which languages and deployment hardware must be Tier 1.
- Whether harmful cyber prompts should use stricter category-specific thresholds than general toxicity.
- Whether Layer 3 should target a local Llama-family model, an API judge, or both behind one interface.
- Which datasets may be downloaded after license/provenance review, especially large community/synthetic collections.

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

## Next action after approval

Create the dataset registry/schema and research audit tooling only. That step will inventory source revisions, licenses, schemas, label distributions, hashes, and duplication without beginning model training. It will conclude with another interactive checkpoint.

## Bugs

No code was changed in this phase, so there are no implementation bugs yet.
