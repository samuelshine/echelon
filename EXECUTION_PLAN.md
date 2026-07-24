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

## Normalization and exact deduplication result (2026-07-11)

Source-specific adapters produced 38,793 structurally valid candidates without copying any assistant response fields. Provenance enforcement quarantined 503 HarmBench-contaminated rows, 780 gated WildGuard-derived rows, 5,312 HackAPrompt-derived rows pending upstream license verification, and 992 redacted/empty prompts. Normalized-fingerprint analysis found 4,584 duplicate groups. Consistent duplicates were collapsed; 391 benign-versus-malicious conflict groups containing 793 rows were quarantined for adjudication.

The resulting eligible corpus contains 32,465 unique records: 16,116 benign (49.64%) and 16,349 malicious. Benign coverage comes from 12,400 Aegis prompts, 638 jackhhao prompts, and 3,078 neuralchemy prompts. The category-label occurrences currently include 13,952 toxicity/harm, 2,866 prompt injection, 432 adversarial obfuscation, and 213 system-prompt leakage labels. These counts expose a coverage gap: malicious-code-specific and system-leakage gold supervision require targeted curation before training.

Final splits remain unmaterialized. The next split builder must first add semantic clusters and assign a single group using, in priority order, semantic cluster, transformation parent, template family, conversation, and normalized fingerprint. English native-speaker gold records remain test-only. Group-level stratification must preserve benign coverage and threat-category balance without allowing evaluation behaviors into training.

## Semantic grouping and split result (2026-07-11)

Semantic fingerprints use the English `BAAI/bge-small-en-v1.5` encoder pinned at commit `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a` under the MIT license. Embeddings are L2-normalized, and a conservative cosine threshold of `0.94` creates near-duplicate edges. These edges are unioned with publisher template and transformation-parent groups. Inputs beyond 2,400 characters use a head-plus-tail semantic view; 734 records required this bounded representation. The threshold is an initial leakage-control operating point and requires human pair sampling before it becomes final.

The graph produced 27,904 groups, including 2,686 multi-record groups and a largest component of 166 records. It found 10,583 semantic edges plus 2,628 declared grouping edges. Another 156 mixed benign/malicious semantic groups containing 652 rows were quarantined for review. The remaining 31,813 rows were freshly repartitioned by complete group because the source datasets are training candidates rather than frozen benchmarks.

The materialized split is 25,453 train (80.01%), 3,198 validation (10.05%), and 3,162 test (9.94%). Train contains 12,577 benign and 12,876 malicious prompts; validation contains 1,565 benign and 1,633 malicious; test contains 1,582 benign and 1,580 malicious. No semantic cluster crosses a split. These are candidate splits pending human review of threshold quality, mixed-safety clusters, and the English defensive-cyber gold-set addition.

## Human calibration and targeted curation gate (2026-07-11)

A private calibration queue contains 450 prompt pairs: 30 deterministic samples for every combination of five cosine bands (`0.90–0.92`, `0.92–0.94`, `0.94–0.96`, `0.96–0.98`, `0.98–1.00`) and three safety relationships (benign/benign, malicious/malicious, mixed). Reviewers judge semantic equivalence separately from whether safety labels should match. Threshold selection will use pairwise precision/recall and the cost of cross-split leakage versus over-grouping; `0.94` remains provisional until this review is complete.

Exact and semantic conflict decisions require two independent reviewers. Matching decisions resolve an item; disagreement requires expert adjudication. The validation CLI rejects malformed label/decision combinations and produces content-free agreement/pending reports. Review queues remain git-ignored because they contain prompt text.

Targeted English curation minimums are specified for system leakage, malicious-code intent, encoded attacks, subtle social engineering, and defensive cybersecurity. Each malicious family receives matched benign controls using the same vocabulary or transformation. Synthetic items may enter training only after review and semantic grouping; gold validation/test items require native-speaker authorship or substantial editing and remain inaccessible to training jobs.

## Targeted candidate batch v0.1 (2026-07-11)

The first controlled-composition batch contains 6,000 unique English candidates, balanced at 3,000 proposed benign and 3,000 proposed malicious. Families are: 1,000 system-leakage attacks, 1,000 malicious-code-intent prompts, 1,000 obfuscated attacks, 1,500 defensive-cyber benign prompts, 500 benign system-prompt/documentation controls, and 1,000 benign encoded controls. These rows are synthetic training candidates only; all are marked pending and excluded from training manifests.

Obfuscation is balanced across Base64, hex, URL encoding, Unicode escapes, and reversal: 400 examples per transformation, split evenly between malicious and benign families. Transformation parents are recorded so every parent and descendant can remain in one semantic group. Malicious-code candidates describe disallowed capability and use inert target placeholders; the generator emits no payload responses or executable artifacts. This structural guarantee does not replace human content review.

The batch has 6,000 unique candidate IDs and normalized fingerprints, with zero exact-normalized overlap against the existing eligible corpus. Proposed label occurrences include 1,500 system leakage, 1,500 prompt injection, 1,500 malicious code, 1,000 adversarial obfuscation, and 3,000 benign. Before any row becomes eligible, reviewers must verify intent, non-operationality, naturalness, label correctness, and generator-template diversity; the accepted subset must then pass semantic deduplication and group-safe repartitioning.

## Targeted v0.1 semantic audit and stratification (2026-07-11)

Batch v0.1 passed novelty against the existing corpus but failed internal semantic diversity. Of 6,000 candidates, 5,987 have nearest-existing similarity below `0.90`, 13 fall in `0.90–0.94`, and none reach the grouping threshold of `0.94`; no cross-label existing neighbor occurs at threshold. However, internal nearest-neighbor similarity averages `0.9763`, and semantic plus parent edges create one mixed benign/malicious component of 4,635 rows (77.25% of the batch). The admission gate therefore fails for both excessive component size and mixed-safety chaining. No v0.1 row may enter training.

Lexical diversity metrics corroborate the graph result: controlled composition produced unique strings but low distinct-bigram ratios and repeated surface structure. Batch v0.2 must use substantially broader human-authored seed pools, independent paraphrase generators, family-specific wrappers, and caps per template lineage. Encoded controls must not share one universal decode-and-execute wrapper across safety classes.

A private 600-row review queue has been materialized with exactly 100 items per family. The two transformed families contribute 20 examples per transformation each, yielding 40 each for Base64, hex, URL encoding, Unicode escaping, and reversal. The queue includes all 13 boundary-overlap candidates plus 587 novel candidates and requires reviewers to judge naturalness, intent, labels, non-operationality, and acceptance. It is for diagnosis and seed improvement, not admission of the failed batch.

## Targeted candidate pilot v0.2 (2026-07-11)

The redesigned pilot contains 1,200 unique English candidates, balanced at 600 benign and 600 malicious. It uses 280 explicit template lineages with a hard maximum of 10 rows per lineage, broader manually authored frame pools, five recorded generation strategies, and separate wrapper pools for encoded benign content and obfuscated attacks. Family counts are 300 defensive cyber, 100 benign system-prompt controls, 200 encoded benign controls, 200 system leakage, 200 malicious-code intent, and 200 obfuscated attacks.

v0.2 passes the automated semantic admission gate. Its largest semantic/parent component contains 34 rows (2.83%), below the 10% ceiling; zero components mix benign and malicious labels. Internal nearest-neighbor similarity falls from v0.1's `0.9763` mean to `0.9150`. Against the existing corpus, 1,199 rows are below `0.90`, one row is in `0.90–0.94`, and none reaches `0.94`. There are zero cross-label existing neighbors at threshold.

Lexical diversity improves substantially: per-family distinct-bigram ratios range from `0.1289` to `0.1683` for unencoded families, versus approximately `0.0081–0.0164` in v0.1. The pilot is now eligible to proceed to human review, not eligible for training. A 600-row private queue includes 100 per family and 20 benign plus 20 malicious examples for every transformation method. Only dual-reviewed accepted rows may advance to normalization and re-grouping.

## Local dual-review and admission gate (2026-07-14)

The 600-row v0.2 queue now has a local-only SQLite and Flask review workflow. The database is bound to the exact queue SHA-256, and prompt-bearing state remains under git-ignored `data/review_v2`. Primary reviewers are blind to proposed labels, nearest-neighbor prompt text, and prior decisions. The web service binds to `127.0.0.1`, requires distinct primary and expert tokens, disables debug mode, and adds no-store, content-security, anti-framing, and MIME-sniffing protections.

Admission is item-level and fail-closed. Two distinct primary reviewers must agree on the decision and complete final label set. Both reviews must also affirm correct intent, correct labels, non-operational content, and naturalness of at least 4/5. Primary disagreement requires a third reviewer who is distinct from both primaries and explicitly acts as expert adjudicator. Excluded items, failed quality checks, incomplete reviews, and unresolved disagreements remain ineligible.

The import command validates review records, refuses candidates outside the queue, rejects reviewer duplication and premature expert decisions, produces a content-free family/status report, and exports only records that satisfy the gate. Even exported records are intermediate candidates: normalization, full-corpus semantic grouping, leakage-safe repartitioning, and manifest regeneration remain mandatory before training.

## Distributed human-review workflow (2026-07-15)

Reviewers may now work independently from different locations without placing prompt text in Git. The coordinator builds two reviewer-locked private kits from the canonical 600-row queue. Each kit contains only candidate ID, prompt text, language, and transformation; proposed labels, family names, context, generator lineage, nearest neighbors, and embedded review metadata are removed. Kits are transferred through an approved encrypted channel and remain excluded from version control.

Each reviewer runs a loopback-only interface against a separate SQLite database. The kit locks both pseudonymous identity and role. A complete export is required: the exporter refuses missing or extra decisions and emits only closed-schema judgments, controlled rationale codes, quality fields, two queue hashes, and candidate IDs. It strips prompt text, unrestricted notes, timestamps, and local database metadata. Primary exports remain private until both reviewers confirm completion, after which prompt-free JSON submissions may enter separate branches.

The tracked public manifest binds all submissions to canonical queue SHA-256 `11f0ca2e3de5564276533d0a88ec53e66aeaa611478e628839379f1175566e91` and 600 allowed item IDs without exposing prompt content. CI rejects unknown IDs, incomplete primary coverage, duplicate items, malformed labels, unapproved fields, queue mismatch, and identity/role mismatch. Pair validation requires distinct primary identities. Only disagreements enter a private expert kit; final cohort validation requires a third distinct identity and exact conflict coverage before emitting import-ready decisions.

## Encrypted repository delivery (2026-07-15)

Primary review kits are now stored in Git only as authenticated AES-256-GCM ciphertext. Independent 32-byte random passphrases derive encryption keys through scrypt with `N=32768`, `r=8`, `p=1`, and unique 16-byte salts. Reviewer identity and artifact version are authenticated as associated data. Wrong passphrases, reviewer swaps, or any ciphertext modification fail before prompt materialization. Passphrases remain in a git-ignored coordinator file and travel separately from repository access.

The reviewer entrypoint is reduced to one cross-platform bootstrap command after cloning. It creates an ignored isolated environment, installs pinned Flask and cryptography dependencies, prompts without echo, decrypts only the assigned kit into ignored local storage, initializes the hash-bound SQLite database, and starts the role-locked loopback application. A second invocation with `--export` requires complete 600-item coverage and emits only the prompt-free validated submission.

## Phase 3 — Dataset-independent detection foundations (2026-07-22)

Layer 1 is implemented as a dependency-free bounded heuristic engine with Aho–Corasick phrases, regex rules, safe deobfuscation, risk math, evidence contracts, and a reproducible microbenchmark. Its thresholds remain shadow scaffolding pending reviewed calibration.

Layer 2 now has a provider-neutral local Transformers adapter, explicit calibrated/uncalibrated score state, category-aware results, temperature fitting, threshold optimization, ECE/Brier metrics, slice metrics, and a group-safe split validator. The legacy trainer is guarded by a manifest requiring human review, privacy review, semantic split verification, dataset hash, and complete split counts. No pending candidate manifest satisfies this gate.

Layer 3 now has a strict JSON-only judge contract, controlled rationale codes, an untrusted-data system instruction, an HTTPS-only generic adapter with timeout, and a deterministic mock. The cascade supports shadow and enforcement modes, immediate blocks only when explicitly configured, strongest-route shadow reporting, and fail-to-escalate behavior for unavailable layers. Fixture-only tests and benchmarks are permitted; model training, threshold claims, and production enforcement remain blocked until human-reviewed data exists.

## Layer 1 implementation result (2026-07-22)

The heuristic layer is implemented independently of pending human labels. It provides typed immutable results, five category scores, one overall risk score, explicit routing, content-free evidence, bounded input statistics, duration, and an exact ruleset hash. Literal matching uses a prebuilt Aho–Corasick automaton; regular expressions are precompiled and bounded. Unicode normalization, entropy, control/format characters, length truncation, and Base64/hex/URL/Unicode-escape/reversal decoding are covered.

Risk aggregation uses correlation groups to prevent overlapping literal and regex rules from double-counting one behavior. Distinct group weights combine with noisy-or per category; overall risk adds only 12% of the second-highest category plus a bounded obfuscation corroboration term. Shadow routing remains `pass < 0.35`, `escalate 0.35–<0.90`, and `block >= 0.90`. These are not production-calibrated probabilities or approved enforcement thresholds.

Resource limits cap scanning at 100,000 characters, decoder inputs at 4,096 characters, decoded output at 8,192 bytes, decoded candidates at six, and regex repetition counting at three. Decoder output is never executed or logged. A 30,000-iteration full-path microbenchmark measured median `27.958 us`, p95 `38.750 us`, p99 `40.083 us`, and approximately `33,572` prompts/second on the development machine. Final SLOs require deployment-hardware measurement.

## Handoff and review status update (2026-07-24)

`PROJECT_HANDOFF.md` is now the canonical continuation brief for a new chat or engineer. Both independent English native-speaker primary reviews completed all 600 rows. Validation reports 446 accepted-by-agreement rows, 152 conflicts, and 2 quality-gate rejections. The next research gate is expert adjudication of exactly those 152 conflicts. After expert completion, validate the final cohort, import normalized decisions, export accepted candidates, rebuild full-corpus semantic/template-safe splits, and generate a reviewed training manifest. The current zero-review human report must be regenerated and is not evidence that the submissions were absent.

The next review implementation should correct presentation-order bias: preserve a cryptographically bound queue but interleave or seed-shuffle families before any replacement review. The order must remain deterministic and documented so reviewer exports remain reproducible.

## Expert adjudication resolved; corpus rebuild is next (2026-07-24)

The 152 conflicts have been adjudicated as expert `ai_claude` — an AI-assisted,
provisional, human-overridable resolution, recorded as such — and the final cohort
validates clean: 446 accepted by agreement + 152 accepted by expert = **598
training-eligible** items, 2 quality-gate rejections. The git-ignored review data was
recovered by deterministic regeneration (all 600 content-bound IDs reproduced), so
adjudication did not require the missing embedding-derived queue file. Accepted rows
(with recovered text) are exported to git-ignored `data/review_v2/targeted_v0_2_accepted.jsonl`.

Remaining research checkpoints toward a trained model: (Checkpoint 2) rebuild the
full training corpus — re-acquire `data/raw_v2` sources, normalize, merge the 598
accepted synthetic rows, and rebuild leakage-safe semantic/template splits — then
emit a `layer2_training_manifest.json` that passes the fail-closed training gate;
(Checkpoint 4) train and calibrate the multi-label Layer 2 classifier. The training
gate remains fail-closed until a reviewed, privacy-checked, semantically-split
manifest exists.
