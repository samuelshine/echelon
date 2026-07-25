# Echelon R&D — Project Handoff and Continuation Brief

**Snapshot date:** 2026-07-24  
**Repository:** `samuelshine/echelon`  
**Working branch:** `rnd`

This document transfers the complete technical context to a new chat or engineer. It records what Echelon is, why the design was chosen, what has been implemented, the verified current state, blockers, and exact continuation commands.

## 1. Executive summary

Echelon is an ultra-low-latency, three-fold prompt-security ingress pipeline. It detects prompt injection/jailbreaks, system-prompt leakage, malicious code intent, toxicity or harmful intent, and obfuscated or emerging attacks while preserving legitimate defensive cybersecurity work.

The system has three separated concerns:

1. **Data governance and human review:** traceable open sources, benign hard negatives, adversarial candidates, semantic/template leakage controls, and human admission gates.
2. **Runtime detection:** fast deterministic heuristics (Layer 1), a local semantic classifier (Layer 2), and a strict judge boundary (Layer 3).
3. **Evaluation and release gates:** calibrated risk, category scores, false-positive controls, slice metrics, latency measurements, and fail-closed training/enforcement gates.

The project is **not production-ready and must not train on the v0.2 pilot yet**. The primary human-review milestone is now complete, but 152 disagreements still require third-party expert adjudication.

## 2. Verified current state

### Git and branch

- Branch: `rnd`.
- Online GitHub branch was verified at commit `df81b1b1eef638bff316f3764d05264d01c49a90`, `feat(pipeline): implement three-fold detection foundations`.
- No pull request was attached to `rnd` at the last online check.
- Current working tree has unrelated untracked Next.js/build artifacts: `.next/`, `node_modules/`, `next-env.d.ts`, and `tsconfig.tsbuildinfo`. Do not stage these without an explicit decision.

### Human review milestone

The canonical 600-item v0.2 queue is bound to:

    11f0ca2e3de5564276533d0a88ec53e66aeaa611478e628839379f1175566e91

Both primary exports cover all 600 items and use the expected blinded-queue hash:

    fafc411907234ed8b21122a0e2084e2f2eccf5b9871ce3c4259519348b69ea1

Verified result from `scripts.validate_distributed_reviews`:

| Resolution | Count | Meaning |
|---|---:|---|
| Accepted by primary agreement | 446 | Both reviewers agreed and passed quality gates |
| Needs expert adjudication | 152 | Primary verdict or label sets disagree |
| Rejected by quality gate | 2 | Agreement existed but quality requirements failed |
| Total | 600 | Complete primary coverage |

Submissions:

- `review_submissions/v0.2/reviewer_a.json`
- `review_submissions/v0.2/reviewer_b.json`

They are prompt-free exports containing controlled decisions, not prompt text, notes, timestamps, or local database metadata. The older `data/reports/targeted_v02_human_review_report.json` still says zero review records because the import/report step has not yet been rerun; do not treat that stale report as the latest result.

### Review ordering lesson

The v0.2 queue is deterministic and grouped by family, not shuffled:

| Positions | Family | Intended class |
|---|---|---|
| 1–100 | `defensive_cyber_benign_v02` | Benign defensive security |
| 101–200 | `encoded_benign_control_v02` | Benign encoded controls |
| 201–300 | `malicious_code_intent_v02` | Malicious code intent |
| 301–400 | `obfuscated_attack_v02` | Obfuscated attacks |
| 401–500 | `system_prompt_benign_v02` | Benign system-prompt controls |
| 501–600 | `system_prompt_leakage_v02` | Leakage attacks |

The reviewer app uses `ORDER BY ordinal`. A partial test can look “all benign” because the first 200 rows are benign by design. The next round should use a documented deterministic interleave or seeded shuffle while retaining reproducibility.

## 3. Original objective and threat model

The ingress firewall must return numeric risk rather than a Boolean. It covers:

- instruction override, jailbreak, DAN, fake authority, delimiter and indirect injection;
- requests to reveal, transform, encode, summarize, or infer system prompts, hidden context, memory, or secrets;
- credential theft, malware, persistence, evasion, destructive automation, unauthorized exploitation, and other malicious code intent;
- hate, harassment, violence, self-harm, and other harmful intent;
- Base64/hex/URL/Unicode encoding, homoglyphs, zero-width characters, typoglycemia, nested role-play, and multi-turn escalation;
- legitimate cybersecurity activity without keyword-only false positives.

Intent and authorization context matter. Defensive education, authorized testing, CTFs, incident response, code review, hardening, vulnerability remediation, and detection engineering may be benign. Credential theft, malware, persistence, evasion, destructive actions, unauthorized exploitation, and system-prompt extraction remain malicious even when framed as research.

## 4. Work completed from start to present

### Phase A — Planning, taxonomy, and governance

- Created `EXECUTION_PLAN.md`, `CURRENT_PROGRESS.md`, and `MEDIUM_DRAFTS.md`.
- Defined multi-label targets: `prompt_injection`, `system_prompt_leakage`, `malicious_code`, `toxicity_harm`, `adversarial_obfuscation`, and `benign`.
- Required provenance, source revision, license, language, transformation, template lineage, confidence, and adjudication metadata.
- Established the release principle that no synthetic candidate becomes training data before human, privacy, and semantic-split gates.
- Chose English native-speaker review as the first gold-set gate, with multilingual expansion later.

Key specifications include `docs/TARGETED_CURATION_SPEC.md` and `docs/BENIGN_CYBER_GOLDSET_SPEC.md`.

### Phase B — Dataset research and acquisition

Approved production-compatible sources:

- NVIDIA Aegis AI Content Safety Dataset 2.0;
- neuralchemy Prompt Injection Dataset;
- jackhhao Jailbreak Classification;
- LibrAI Do-Not-Answer.

Acquisition controls include immutable revision pinning, license checks, atomic downloads, resumability, SHA-256 manifests, structural validation, and quarantine of gated, unverified, redacted, empty, or evaluation-contaminated records. Assistant responses are excluded from prompt-only records.

The normalized eligible corpus contained 32,465 unique records:

- 16,116 benign/regular prompts;
- 16,349 malicious/safety-risk prompts;
- 4,193 consistent duplicate groups collapsed;
- 391 benign-versus-malicious conflict groups quarantined;
- zero response fields in eligible records.

The old 33,188-row processed corpus remains legacy-only because it has cross-split duplicate leakage and insufficient lineage metadata.

### Phase C — Semantic grouping and leakage prevention

- Selected and pinned `BAAI/bge-small-en-v1.5` revision `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a`.
- Combined cosine-0.94 semantic grouping with declared template and transformation-parent grouping.
- Quarantined mixed benign/malicious components.
- Materialized leakage-safe splits: train 25,453, validation 3,198, test 3,162.
- Verified no semantic cluster crosses split boundaries.
- Added embedding caching and exact/normalized/fuzzy checks.

### Phase D — Synthetic candidate pilots

#### v0.1 (failed)

- Generated 6,000 unique English candidates: 3,000 benign and 3,000 malicious-intent.
- Included defensive cyber, system-prompt controls, encoded benign controls, obfuscated attacks, malicious code, and leakage.
- External novelty was strong, but internal collapse was severe: mean nearest similarity 0.9763 and a 4,635-row mixed-safety component (77.25%).
- Result: rejected. No v0.1 candidate is training-eligible.

#### v0.2 (semantic gate passed; human gate pending)

- Generated 1,200 candidates balanced 600 benign / 600 malicious.
- Used 280 template lineages capped at 10 rows, broader frame pools, multiple paraphrase strategies, and separate benign/malicious encoding wrappers.
- Largest semantic component: 34 rows (2.83%).
- Mixed-safety components: zero.
- Mean nearest similarity: 0.9150.
- External novelty: 1,199 below 0.90, one boundary item, none at or above 0.94.
- Created a 600-item review queue with 100 rows per family.
- All 1,200 remain pending/ineligible until human decisions and post-review regrouping.

### Phase E — Human-review infrastructure

Implemented local and distributed workflows:

- SQLite reviewer store bound to queue SHA;
- blinded primary interface;
- two independent primaries;
- third expert only for genuine disagreements;
- naturalness, intent, labels, and non-operational-content quality gates;
- prompt-free JSON export;
- manifest/hash/coverage/identity validation;
- encrypted AES-256-GCM clone-and-run kits using scrypt;
- loopback-only Flask app with token auth, CSP, no-store, anti-framing, and no debug mode;
- GitHub Actions validation for submissions.

Launch commands:

    python3 scripts/review_bootstrap.py reviewer_a
    python3 scripts/review_bootstrap.py reviewer_b

Passphrases are not committed or sent through Git. Reviewers push only completed prompt-free JSON.

### Phase F — Layer 1 heuristic engine

Layer 1 provides:

- Unicode NFKC normalization and case folding;
- bounded length, entropy, printable-ratio, mixed-script, invisible-character, and repetition checks;
- Aho–Corasick phrase matching;
- bounded regex rules for injection, leakage, malicious code, role-play, delimiters, and harm;
- bounded Base64, hex, URL-percent, Unicode-escape, and reversal decoding;
- correlation groups to prevent double-counting;
- category scores and aggregate risk in [0, 1];
- versioned rules in `configs/layer1_rules.json`;
- explicit pass/escalate/block routes.

Regression examples: combined injection plus leakage blocks at risk 0.9808; explicit ransomware/evasion/credential-theft intent blocks near 1.0; authorized defensive reverse-shell incident response remains below block at risk 0.24.

Benchmark:

- median 27.958 µs;
- p95 38.750 µs;
- p99 40.083 µs;
- throughput 33,572 prompts/second.

### Phase G — Layer 2, Layer 3, and cascade foundations

Layer 2 includes provider-neutral local model loading, static/mock adapters, `local_files_only=True`, calibrated/uncalibrated tracking, and deterministic temperature calibration. Existing artifacts are historical binary prompt-injection models, not the final multi-label production detector.

Layer 3 includes a strict judge system prompt/schema, untrusted-prompt context, controlled probabilities and rationale codes, an HTTPS-only timeout-bounded adapter, and a deterministic mock judge.

`EchelonPipeline` supports shadow mode, enforcement mode, Layer 1 short-circuit blocking, Layer 2 routing, Layer 3 uncertainty adjudication, fail-to-escalate behavior, and content-free decisions.

Initial research thresholds are scaffolding:

    risk < 0.35         pass
    0.35 <= risk < 0.90 escalate to Layer 3
    risk >= 0.90        block

They must be replaced by validation-derived, category-aware operating points.

### Phase H — Evaluation and training gates

Implemented precision, recall, F1, benign false-positive rate, Brier score, ECE, slice metrics, constrained threshold selection, semantic split checks, privacy/hash checks, and training-manifest validation.

`scripts/train.py` refuses to train unless human review, privacy review, semantic split validation, eligibility, SHA-256, and split counts are present. The current candidate manifest correctly fails this gate.

Fixture cascade benchmark:

- median 33.750 µs;
- p95 40.000 µs;
- p99 43.916 µs;
- throughput 30,991 prompts/second.

The base suite is 114 tests: 109 pass and five optional Flask/cryptography integrations are skipped when those packages are absent from the active interpreter. Python compilation passes.

## 5. Repository map

Runtime:

- `echelon/contracts.py`: shared typed results and thresholds.
- `echelon/automaton.py`: Aho–Corasick matcher.
- `echelon/layer1.py`: heuristic analyzer.
- `echelon/layer2.py`: local classifier and calibration.
- `echelon/layer3.py`: judge boundary.
- `echelon/pipeline.py`: cascade.
- `echelon/evaluation.py`: metrics and threshold selection.
- `echelon/training_gate.py`: fail-closed training gate.
- `echelon/training_data.py`: lineage/split validation.

Review/data scripts:

- `scripts/validate_distributed_reviews.py`: primary/expert/final validation.
- `scripts/build_expert_review_kit.py`: conflict-only kit.
- `scripts/import_review_decisions.py`: import and accepted export.
- `scripts/check_training_gate.py`: manifest check.
- `scripts/run_pipeline.py`: smoke CLI.
- `scripts/benchmark_layer1.py`, `scripts/benchmark_pipeline.py`: benchmarks.

Key configuration/reports:

- `configs/layer1_rules.json`
- `configs/pipeline.yaml`
- `configs/training_config.yaml`
- `configs/deberta_config.yaml`
- `data/manifests/targeted_v02_distributed_review_manifest.json`
- `data/reports/targeted_v02_distributed_workflow_report.json`
- `data/reports/targeted_v02_human_review_report.json`
- `data/reports/layer1_benchmark.json`
- `data/reports/pipeline_benchmark.json`

## 6. Exact next steps

### Step 1 — Expert adjudication

Build a private kit for the 152 conflicts:

    python -m scripts.build_expert_review_kit \
      --queue data/review_v2/targeted_v0_2_review.jsonl \
      --public-manifest data/manifests/targeted_v02_distributed_review_manifest.json \
      --primary review_submissions/v0.2/reviewer_a.json \
      --primary review_submissions/v0.2/reviewer_b.json \
      --expert-id expert_01 \
      --output data/review_v2/distributed_expert_kit_v02

The expert must adjudicate every conflict and export `review_submissions/v0.2/expert_01.json`. Do not train or admit the 446 agreed items until the final cohort gate runs.

### Step 2 — Validate final cohort

    python -m scripts.validate_distributed_reviews \
      --public-manifest data/manifests/targeted_v02_distributed_review_manifest.json \
      --primary review_submissions/v0.2/reviewer_a.json \
      --primary review_submissions/v0.2/reviewer_b.json \
      --expert review_submissions/v0.2/expert_01.json \
      --normalized-decisions data/review_v2/targeted_v02_normalized_decisions.jsonl \
      --report data/reports/targeted_v02_distributed_review_report.json

Expected: no schema/hash/coverage errors, expert completion for all 152 conflicts, and a final status for all 600 rows.

### Step 3 — Import and export accepted rows

    python -m scripts.import_review_decisions \
      --queue data/review_v2/targeted_v0_2_review.jsonl \
      --database data/review_v2/targeted_v0_2_reviews.sqlite3 \
      --decisions data/review_v2/targeted_v02_normalized_decisions.jsonl \
      --accepted data/review_v2/targeted_v0_2_accepted.jsonl \
      --report data/reports/targeted_v02_human_review_report.json

### Step 4 — Rebuild the training candidate corpus

Merge accepted v0.2 rows with the eligible source corpus only after privacy review. Re-run schema/provenance checks, exact and normalized deduplication, semantic/template/parent grouping, conflict quarantine, lineage-aware splits, English gold-set checks, and defensive-cyber false-positive slice checks. Generate a new `data/manifests/layer2_training_manifest.json` with dataset hash, review/privacy status, split counts, and semantic-split proof.

### Step 5 — Train and calibrate Layer 2

After the training gate passes, train a multi-label category model rather than the current binary prompt-injection artifact. Compare compact encoders, weighted BCE/focal loss, hard-negative mining, calibration methods, category/slice metrics, and latency. Export model, tokenizer, calibration, manifest hash, and metrics together.

### Step 6 — Evaluate Layer 3 and the cascade

Measure local/API judge quality, strict-schema behavior, prompt-injection resistance, timeout rate, cost, privacy, and latency. Keep JailbreakBench, HarmBench, StrongREJECT, CyberSecEval, and private challenge slices held out. Run shadow mode first, tune category-specific thresholds, and enable enforcement only after reviewed-data evidence.

### Step 7 — Production hardening

Add model/ruleset/config version headers, no-raw-prompt metrics, rate/request limits, circuit breakers, judge budgets, multilingual native-speaker gold data, drift monitoring, calibration refresh, retention controls, and an incident-response plan.

## 7. Do not do these things yet

- Do not mark v0.2 training-eligible before expert adjudication and final validation.
- Do not trust the stale zero-review report until it is regenerated from submissions.
- Do not use the old random-split `prepare_data.py` workflow for production claims.
- Do not enable enforcement mode using uncalibrated thresholds.
- Do not treat current binary model artifacts as the final multi-label detector.
- Do not commit plaintext kits, passphrases, SQLite databases, prompt queues, screenshots, or notes.
- Do not equate “benign” with “safe to train” without quality and leakage gates.

## 8. Useful commands

    git branch --show-current
    git status --short --branch

    printf '%s' 'Summarize this meeting agenda.' | \
      python -m scripts.run_pipeline --fixture-risk 0.10 --judge mock

    python -m unittest discover -s tests -p 'test_*.py' -v
    python3 -m py_compile echelon/*.py scripts/*.py reviewer/*.py

    python -m scripts.benchmark_layer1 --iterations 30000 \
      --report data/reports/layer1_benchmark.json

    python -m scripts.benchmark_pipeline --iterations 5000 \
      --report data/reports/pipeline_benchmark.json

    python -m scripts.check_training_gate \
      --manifest data/manifests/layer2_training_manifest.json

## 9. Continuation message for a new chat

Continue Echelon R&D from `PROJECT_HANDOFF.md` on branch `rnd`. Primary review is complete: 600/600 items covered, 446 accepted by agreement, 152 conflicts requiring expert adjudication, and 2 quality-gate rejections. Do not train or admit candidates yet. Build and distribute the conflict-only expert kit, validate the expert submission, import complete decisions, rebuild semantic-safe splits, generate the reviewed training manifest, and only then train/calibrate Layer 2. Preserve the fail-closed training gate and no-raw-prompt logging policy.

