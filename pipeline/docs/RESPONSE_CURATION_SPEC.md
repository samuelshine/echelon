# Echelon Response-Shaped Curation Specification (Track B)

**Status: design draft — not reviewed, not approved, not authorized to execute.**
This is a companion to `TARGETED_CURATION_SPEC.md`, not a replacement. It exists
because that spec — and every source `acquire_datasets.py` has ever pulled —
covers only *prompt-shaped* text (something a user sends). Egress scanning needs
*response-shaped* text (something an assistant sends back), which this repo has
never generated, sourced, or reviewed for any category. See
`LAYER2_RETRAIN_PLAN.md` §3 for how this fits into the broader retrain plan and
why it is scoped separately from Track A (ingress precision).

Per the same standing rule this repo already applies: do not train on
unreviewed or under-reviewed data, and do not skip the human-review /
training-gate pipeline. Nothing in this document authorizes generation,
acquisition, or training — it defines what would need to happen and the
decisions that must be resolved first.

## Objective

Give the egress `malicious_code` head real response-shaped training signal, so
the code-shape-floor heuristic in `pipeline/service/security_api.py`
(`_apply_code_shape_floor`) can eventually be retired in favor of an actual
learned decision boundary. Today that classifier has never seen an
assistant-authored response as input; it was trained exclusively on
prompt/attack text.

## Why this cannot reuse the prompt-side spec as-is

A prompt *requesting* malware and a response *containing* it are different
objects with different surface features (a request is typically short and
imperative; a response is often long, may mix explanation with code, and its
"shape" — imports, control flow, payload structure — carries most of the
signal). The existing judge-layer instruction
(`OLLAMA_OUTPUT_JUDGE_INSTRUCTION` in `pipeline/echelon/layer3.py`) already
encodes an operational-vs-defensive distinction for response text at the LLM
layer; this spec exists to give the *classifier* layer an analogous,
learned distinction instead of relying on a judge escalation for every
code-shaped response.

## Proposed target additions (draft — subject to design review before locking)

| Slice | Train candidates | Gold validation | Gold test | Required matched negative controls |
|---|---:|---:|---:|---:|
| Malicious-code output (operational) | 4,000 | 400 | 400 | 4,000 defensive/explanatory controls |

Sized to match `TARGETED_CURATION_SPEC.md`'s malicious-code-intent slice
(same 4,000/400/400 shape) since both feed the same `malicious_code` label
head. Negative controls are 1:1 rather than the prompt-side spec's tighter
ratio (2,000 for 4,000 malicious) because response-side false positives are
the documented risk this track exists to close (see "Honest limitations" in
`DEMO.md`) — the boundary needs more negative density to pin down reliably.
This table is a starting proposal, not a locked commitment; revise after a
small pilot batch surfaces real difficulty/cost per item.

## Positive slice: operational malicious-code output

Assistant responses that deliver actually-functioning-shaped code toward
unauthorized capability: credential theft, keyloggers, ransomware/encryption
payloads, C2 beacons, exploit payloads, persistence mechanisms, evasion code,
destructive scripts, malware droppers/loaders. As with the prompt-side spec:
do not include payloads capable of causing real harm if copy-pasted and
executed — use abstracted placeholders for targets, addresses, secrets, and
destructive commands, in the same style `TARGETED_CURATION_SPEC.md` already
mandates. Vary response shape realistically: some responses are code-only,
some mix a short explanation with code, some are multi-turn continuations —
narrow synthetic sourcing (code-only, one style) would teach a shape
fingerprint rather than a real decision boundary.

## Negative slice: defensive/explanatory response controls

Matched controls that are code-shaped or code-adjacent but not operational
malicious output: YARA/Sigma detection-rule write-ups, malware analysis
reports (describing behavior of a sample, not delivering one), code review
comments and refactor suggestions, incident-response runbooks, secure-coding
explanations, CTF writeup narration (post-hoc "here's how the challenge
worked" text, not a ready-to-run exploit), vulnerability-disclosure writeups.
This is precisely the category the code-shape floor's false-positive risk
sits on today — the negative slice's coverage quality determines whether a
retrain actually improves precision or just moves the false-positive floor
elsewhere.

## Labeling boundary for response text

Not identical to `TARGETED_CURATION_SPEC.md`'s "Malicious-code and
defensive-cyber boundary" section — needs its own resolution before any
annotation starts. Candidate axes (to be settled during design review, not
here):

- Does the response, as written, deliver something that runs toward
  unauthorized capability if extracted and executed — versus describing,
  detecting, or remediating that capability?
- Mixed responses (explanation + operational code in the same message):
  label by the operational-code portion's presence, matching how the judge
  instruction already treats mixed content, or by a stricter
  majority-of-content rule? This needs an explicit decision, not reviewer
  discretion — mixed-content is exactly the ambiguous middle that produced
  391 benign-vs-malicious conflict groups in the v0.2 prompt-side round, and
  response text will likely have more mixing than prompt text does.
  Whatever is decided, the two-reviewer + expert-adjudication discipline
  below is not optional for this slice.
- "For research/education" framing, as with the prompt-side rule, never
  determines the label by itself.

## Sourcing options (decision needed, not just generation)

Two paths, likely both needed:

1. **Synthetic generation.** Fastest path, but risks the model learning a
   *generator's* code style rather than real code diversity — worse here
   than the prompt-side risk, since real malicious code has far more
   stylistic range (language, library choice, obfuscation habits, comment
   style) than templated attack prompts do. The v0.1 prompt-side pilot's
   failure mode (mean nearest-neighbor similarity 0.9763, a 4,635-row
   mixed-safety component collapsing to near-duplicates) is the concrete
   precedent to avoid; v0.2 fixed it by broadening frame pools. A response
   generator would need the same discipline from the start, not as a later
   fix.
2. **Real, license-compatible sources.** Public malware-analysis writeups,
   YARA/Sigma rule repositories, CTF writeup corpora, published
   incident-response reports. None of the four sources `acquire_datasets.py`
   currently pulls (Aegis 2.0, neuralchemy, jackhhao, Do-Not-Answer) contain
   response-shaped text — they are all prompt/injection datasets — so this
   needs its own source-vetting pass through the same registry-approval +
   immutable-revision-pinning + license-check discipline
   `acquire_datasets.py` already enforces, not a reuse of the existing four.

Recommend treating synthetic as the volume driver for the positive
(operational) slice, where content must stay non-executable/abstracted by
design, and real sources as the primary driver for the negative
(defensive/explanatory) slice, where genuine writeups are plentiful,
license-clearable, and avoid synthetic staleness in exactly the direction
that matters most for false-positive risk.

## Open modeling question (decide during execution, not now)

Does a single multi-label model trained on a blended prompt+response
distribution generalize adequately for `malicious_code`, or does egress need
a separate model/head? Recommend trying the blended approach first — no
changes needed to `MultiLabelTransformersAdapter` or
`train_layer2_multilabel.py`, only the corpus — and moving to a
egress-specific model only if evaluation shows the two domains need
different decision boundaries. A `text_type` (prompt/response) feature is a
cheap fallback if blending underperforms, before committing to a second
model.

## Generation and review controls

Same discipline as `TARGETED_CURATION_SPEC.md`, with one addition specific to
this slice:

- Use at least three generators or human-authoring/sourcing pools for the
  positive slice; record generator, template version, seed, and parent ID
  exactly as the existing schema does.
- No single generator or source contributes more than 40% of a slice.
- Two independent native-English reviewers label intent, operational-vs-
  defensive boundary, severity, and confidence; disagreements require expert
  adjudication — do not majority-vote the boundary given how much harder it
  is expected to be than the prompt-side call (see "Labeling boundary"
  above).
- Gold sets contain no unreviewed synthetic text and remain inaccessible to
  training jobs, as with every existing slice.
- Run the existing exact/semantic/template/transformation-parent leakage
  checks (`build_semantic_splits.py`, unmodified) after every addition.
- **New for this slice:** real-sourced negative-control text (writeups,
  rule repos) must pass through provenance/license verification
  (`acquire_datasets.py`'s existing atomic-download, immutable-revision, and
  license-check machinery) before entering the same normalization pipeline
  as synthetic candidates — do not hand-copy external text without the
  provenance trail the rest of the corpus already requires.

## What reuses existing machinery unchanged

`build_semantic_splits.py`, `build_training_corpus.py`,
`build_training_manifest.py`, `train_layer2_multilabel.py`,
`echelon/training_gate.py`, and the full distributed-review workflow
(`review_bootstrap.py`, `validate_distributed_reviews.py`,
`build_expert_review_kit.py`, `import_review_decisions.py`) all operate on
the normalized record schema regardless of whether a record is prompt- or
response-shaped. Nothing here changes downstream of "candidates exist and
are provenance-tagged and reviewed."

## Decisions required before generation can start

**Resolved 2026-08-11/12**, as part of executing a pilot round (see
`CURRENT_PROGRESS.md`'s Track B entry for the actual generation/review/
training run these decisions fed). All five were decided by the same author
who wrote this spec, under time pressure to produce a working round in one
session — reasonable engineering calls, not the outcome of the independent
design review this document originally called for. A real review should
still happen before any larger/production round.

1. **Mixed explanation+code labeling: resolved as "operational-portion
   controls."** A response is labeled `malicious_code` if it contains an
   operational (non-defensive) code portion, regardless of surrounding
   explanatory text — matching the judge layer's existing operational-vs-
   defensive distinction (`OLLAMA_OUTPUT_JUDGE_INSTRUCTION`) rather than
   inventing a new rule. A majority-of-content threshold was rejected as
   gameable (padding operational code with defensive-sounding prose would
   flip the label). A code portion that is itself a detection artifact (a
   YARA/Sigma rule, a regex signature) does not count as operational.
2. **Sourcing split: resolved as synthetic-only for this round**, not the
   synthetic-positive/real-negative split recommended above. Real-source
   acquisition (malware-analysis writeups, YARA/Sigma repositories) needs
   its own registry-approval and license-vetting pass that doesn't fit
   inside one session — deferred, not abandoned. This is a real, documented
   deviation from this spec's own recommendation, and the resulting
   negative-control diversity is narrower than a real-source-backed round
   would achieve.
3. **Target volumes: resolved as a pilot scale well below the 4,000/400/400
   table above** — see `CURRENT_PROGRESS.md` for exact counts. Deliberately
   smaller than Track A's already-below-spec v0.3 round, both because Track
   B is "one new slice, not two" (§5 above) and because a bad synthetic
   "operational" response is a worse failure mode than a bad synthetic
   prompt. Full spec volume remains a distinct, larger follow-up.
4. **Reviewer capacity: resolved as the same AI-assisted dual-review
   process used for Track A** (`scripts/ai_reviewers_v03.py`, extended with
   response-specific signals), not native human review. Carries the same
   provisional/AI-assisted caveat as Track A and the v0.2 precedent, and is
   arguably weaker here given point 2 in "Labeling boundary" above — mixed-
   content ambiguity is harder to review than prompt-side ambiguity, and
   operational-code detection misses have higher stakes than prompt-intent
   misses.
5. **Blended vs. separate model: resolved as blended** — Track B's
   reviewed rows are merged into the same training corpus as Track A's v0.3
   round (one combined manifest, one model), per this document's own
   recommendation to try blending first. Per `LAYER2_RETRAIN_PLAN.md` §6's
   instruction not to conflate the two tracks, evaluation still reports
   Track A's prompt-shaped and Track B's response-shaped `malicious_code`
   performance as distinct slices, not one merged number.

---

## Superseded by real data (2026-08-13)

The five decisions above were resolved under session time pressure for a
synthetic-only pilot. Real response-shaped data now exists and overturns two of
them outright. This section records what actually happened; the decisions above
are kept for provenance, not as current guidance.

### Decision 2 (sourcing: "synthetic-only for this round") — superseded

WildGuardMix ships human-labelled assistant responses, already acquired under
the gated path. Track B now has **37,622 training-side** and **1,707
held-out** real response rows, against the pilot's 300 synthetic ones.
Labels are publisher-declared (`response_harm_label`, plus prompt subcategory to
separate `malicious_code` from `toxicity_harm`); the service's own
`_looks_like_code` heuristic is recorded per row as a *slice*, never as a label.

Reading the response columns does not breach the standing no-assistant-response
rule. That rule stops response content leaking into **prompt** classification;
Track B is a response-side model where response text is the feature by
definition. Prompt columns are correspondingly not read.

### Decision 5 (blended vs separate model) — not yet exercised, and now optional

The pilot blended because it had nothing else. The measurement changes the
premise: the **prompt-trained v0.6 model already transfers to response text for
`malicious_code`**, scoring 0.819 on malicious responses against 0.083 on benign
ones. No response-side training was needed to get that. What a response-aware
round would actually buy is `toxicity_harm` on response text, which is the head
that does not transfer (see below).

### What the measurement settled

`_apply_code_shape_floor` is **retired** (no-op whenever egress thresholds are
configured, retained otherwise). Its founding premise — that the model scores
real generated code near zero — was true of the 2026-08-01 model and is false of
v0.6. It had become a near-pure false-positive generator, firing on 86.3% of
benign code-bearing responses and only 13.3% of malicious ones.

Egress gained per-category operating points fitted on the training-side
responses and verified once on the holdout:

| slice | n | today | per-category |
|---|---|---|---|
| benign responses pass | 1424 | 0.354 | **0.834** |
| benign responses blocked | 1424 | 0.098 | **0.014** |
| benign code-shaped pass | 153 | **0.000** | 0.784 |
| `malicious_code` blocked | 25 | **0.000** | 0.400 |
| `malicious_code` code-shaped blocked | 15 | 0.000 | **0.600** |

Malicious code output can be blocked on the model's own evidence for the first
time; the sparse cap previously held it at 0.88, under the gateway's 0.90.

### The one genuine regression, and the one head still broken

- **12% of malicious responses now pass** where today all 25 reach the judge.
  The escalation budget was already loosened (0.05 → 0.10 on the fitting set) to
  recover this from 20%; it cannot go lower, because below ~0.25 the model
  itself no longer scores them.
- **`toxicity_harm` does not transfer to response text.** Its curve has no
  usable operating point: 62% benign false-positive rate at 0.5, and 2.7% recall
  by 0.95. Today's apparent egress coverage is noise, not detection — it
  escalates 58.9% of harmful responses and 54.8% of benign ones, a ratio of 1.07.

**That is the remaining Track B work**, and it is now a well-posed one: a
response-aware training round targeting `toxicity_harm` on assistant output,
with 7,915 real harmful-response rows available for it. Whether that round is
blended (risking the just-promoted ingress model) or trained as a separate
response model (no ingress risk, more serving wiring) is the open decision — and
unlike the original Decision 5, it can now be settled with measurements on both
holdouts rather than by argument.
