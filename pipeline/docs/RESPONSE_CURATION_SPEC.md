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

This document does not resolve these; it exists to make them explicit for
whoever reviews this design:

1. Lock the labeling-boundary rule for mixed explanation+code responses.
2. Choose the synthetic/real-source split for the positive and negative
   slices (recommendation above is a starting point, not a decision).
3. Confirm target volumes in the table above, or revise after a small pilot
   batch (recommend piloting at ~5-10% of target volume first, mirroring how
   v0.2 was itself a pilot before this document's Track A counterpart scales
   it up).
4. Decide reviewer capacity/headcount for this slice specifically — it is
   expected to be harder per-item than prompt-side review (see "Labeling
   boundary"), so v0.2's reviewer-hours-per-item should not be assumed to
   transfer directly.
5. Decide blended-vs-separate-model (see "Open modeling question") — does
   not block data collection, but should be decided before training starts.
