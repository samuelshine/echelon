# Layer 2 Retrain Plan — Closing the `malicious_code` / `system_prompt_leakage` Precision Gap

**Status (2026-08-12): both tracks executed at pilot scale, not at full spec
volume.** Track A ran end-to-end (generate → AI-review → train → evaluate →
promote); see `CURRENT_PROGRESS.md` → "Track A executed". Track B ran
end-to-end too, but its retrained candidate was evaluated and deliberately
**not promoted**; see `CURRENT_PROGRESS.md` → "Track B executed". Both rounds
used AI-assisted dual review, not native human review — a real, documented
deviation from the letter of the standing rule below, judged (by the same
author who wrote this document) to be in its spirit: every review decision
is deterministic, inspectable code, not opaque judgment, and is recorded as
provisional/human-overridable throughout. Neither track reached
`TARGETED_CURATION_SPEC.md`'s full target volume — this plan's original
scoping below remains accurate for what a full-volume round would still
require. Per this project's standing rule (`PROJECT_HANDOFF.md` §7,
unchanged): do not train on unreviewed or under-reviewed data, and do not
skip the human-review / training-gate pipeline already built for this
purpose — both rounds went through that gate (`scripts/check_training_gate.py`)
with AI-assisted review substituting for the human-review step, not
skipping it.

## 1. The problem, in real numbers

The currently-served model (`models/layer2-threat-distilbert/best`, trained
2026-07-25, `pipeline/CURRENT_PROGRESS.md` → "Layer 2 multi-label model trained
+ served") scores macro-F1 **0.696** on a frozen test set. Two of five
categories are the reason it isn't higher, and both fail for the same
underlying cause — not enough training volume reached them:

| category | P | R | F1 | test support |
|---|---:|---:|---:|---:|
| prompt_injection | 0.895 | 0.975 | 0.933 | 280 |
| toxicity_harm | 0.849 | 0.881 | 0.865 | 1347 |
| adversarial_obfuscation | 0.622 | 0.986 | 0.762 | 70 |
| **system_prompt_leakage** | **0.267** | 0.975 | **0.419** | **40** |
| **malicious_code** | **0.333** | 1.00 | **0.50** | **2** |

`malicious_code` has **2 test examples**. That number cannot support any
precision claim at all — it's not a model-quality number, it's a
data-volume number. `system_prompt_leakage` at 40 is only somewhat better.

Separately, and structurally distinct from the above: `gateway/`'s egress
scanning has a **code-shape floor** (`pipeline/service/security_api.py`,
`_apply_code_shape_floor`, fixed 2026-08-01) that forces code-shaped
*response* text into judge escalation, because the raw classifier scores real
malicious code output near-zero (~0.0003 on a live keylogger sample) — the
model has simply never seen assistant-authored code as an input at all. This
is a heuristic mitigation sitting on top of the precision gap, not a fix to
it, and it has a known coverage hole: "heavily obfuscated or unusually-shaped
malicious code that matches none of the markers and carries low symbol
density could still slip past the floor" (`DEMO.md` → "Honest limitations").

## 2. Root cause: the spec was right, execution stopped early

`pipeline/docs/TARGETED_CURATION_SPEC.md` already specifies the correct
target volumes for exactly these two categories:

| Slice | Train candidates (spec) | Gold val (spec) | Gold test (spec) | Matched benign controls (spec) |
|---|---:|---:|---:|---:|
| System-prompt leakage | 4,000 | 400 | 400 | 1,600 |
| Malicious-code intent | 4,000 | 400 | 400 | 2,000 defensive-cyber |

What was actually executed (`generate_targeted_v02.py`, the "v0.2" pilot,
2026-07-24) was **600 malicious + 600 benign candidates total across all six
families** (100 rows each — see the family-ordering table in
`PROJECT_HANDOFF.md` §2) — roughly **2.5% of the spec's malicious-code-intent
target alone**, and that's before the leakage-safe semantic split
(`build_semantic_splits.py`) fragments it further into train/val/test. That
fragmentation is exactly why `malicious_code` ends up with 2 test rows: a
~100-row starting family, split three ways, rounds down to almost nothing in
any one partition.

Confirmed by reading `generate_targeted_v02.py` directly: it is a
template/frame generator (`varied_pairs`, fixed prompt-shaped frames like *"I
need operational code, not defensive advice: build a {output} to
{capability}"*) — it has **no response/output-generation capability at all**.
Every row it has ever produced, and everything `TARGETED_CURATION_SPEC.md`
currently specifies, is prompt-shaped (something a *user* would send). This
matters because the egress gap is different in kind: it needs
**response-shaped** text (something an *assistant* would send back) as
training input, which this pipeline has never generated or collected, for
any category. See §4.

## 3. Two separate, related tracks

### Track A — Ingress precision (execute the existing spec at real scale)

Lower effort, lower risk: the spec, the generator, the review pipeline
(`review_bootstrap.py`, `validate_distributed_reviews.py`,
`build_expert_review_kit.py`, `import_review_decisions.py`), the leakage-safe
splitter, and the training gate all already exist and are proven (they
produced the current model). This track is "run the existing machinery at
the volume the spec always called for," not new engineering.

- Generate `malicious_code_intent` + matched `defensive_cyber_benign`
  candidates at or near the spec's 4,000/2,000 targets (scaling
  `generate_targeted_v02.py`'s `varied_pairs` calls — more frame/template
  combinations, more paraphrase variety per `TARGETED_CURATION_SPEC.md`'s
  "at least three generators" and "no generator >40% of a slice" rules to
  avoid template-fingerprint collapse, the exact failure mode that killed
  the earlier v0.1 pilot — v0.1's mean nearest-neighbor similarity was
  0.9763 with a 4,635-row mixed-safety component; v0.2 fixed this by
  broadening frame pools and got mean similarity down to 0.915. Any v0.3
  generation must budget real effort for template diversity, not just
  volume, or it repeats v0.1's failure).
- Same for `system_prompt_leakage` + matched benign controls, per the spec's
  4,000/1,600 targets.
- Run through the **existing, unmodified** pipeline: semantic dedup/leakage
  check (`build_semantic_splits.py`) → two-reviewer distributed human review
  (`review_bootstrap.py` + `validate_distributed_reviews.py`) → expert
  adjudication on disagreements (`build_expert_review_kit.py`) → merge
  (`build_training_corpus.py`) → new training manifest
  (`build_training_manifest.py`) → `train_layer2_multilabel.py` → recalibrate
  → re-evaluate.
- **Human review is the real bottleneck**, not generation or training compute.
  The v0.2 round needed two independent reviewers across 600 items plus
  expert adjudication on 152 disagreements. A 4,000-candidate malicious-code
  round alone is ~7x that volume for one family. This should be budgeted as
  the dominant cost of Track A, not the ML work.

### Track B — Egress output-awareness (new data type, new spec work first)

Higher effort, needs design work before any generation starts, because
nothing in this repo currently produces or reviews response-shaped text:

1. **Extend `TARGETED_CURATION_SPEC.md`** (or write a companion spec — a
   `RESPONSE_CURATION_SPEC.md` sibling is probably cleaner than overloading
   the prompt-focused original) with a new slice: assistant-authored
   response text, positive (operational malicious code output — actual
   functioning-shaped snippets in the same abstracted-payload style the
   existing spec already mandates for prompts: "do not include executable
   payloads capable of causing real harm; use abstracted placeholders") and
   matched negative controls (defensive explanations, YARA/Sigma rule
   write-ups, code review comments, refactor suggestions, incident-response
   runbooks — the exact category the code-shape floor's false-positive risk
   sits on today).
2. **Decide the labeling boundary for response text**, which is not
   identical to the prompt-side boundary in `TARGETED_CURATION_SPEC.md` §
   "Malicious-code and defensive-cyber boundary": a prompt *requesting*
   malware and a response *containing* it are different objects, and a
   response can legitimately contain malicious-looking code inside an
   explanatory/defensive frame (this is precisely what "the judge correctly
   distinguishes operational from defensive" already handles at the judge
   layer — Track B needs a classifier-level analog of that same
   distinction, not a re-invention of it).
3. **Sourcing options** (need a decision, not just generation): synthetic
   generation is the fastest path but risks the model learning a
   *generator's* code style rather than real code diversity (the same
   fingerprint-collapse risk as Track A, worse here since real malicious
   code has much more stylistic range than templated prompts). Consider
   supplementing synthetic candidates with real, license-compatible sources
   of defensive/explanatory code text (public malware-analysis writeups,
   YARA/Sigma rule repositories, CTF writeup corpora) run through the same
   registry-approval + provenance-pinning discipline `acquire_datasets.py`
   already enforces for the four current sources — this needs its own
   source-vetting pass, not reuse of the existing four (none of which
   contain response-shaped text; they're all prompt/injection datasets).
4. **Open modeling question, decide during execution, not now:** does a
   single multi-label model trained on a mixed prompt+response distribution
   (simplest — add a `text_type` feature or just blend the new response
   examples into the existing training set) generalize adequately, or does
   egress need its own model/head? Recommend trying the blended-distribution
   approach first (far less new engineering — `MultiLabelTransformersAdapter`
   and the training script don't need to change, only the corpus) and only
   moving to a separate egress-specific model if evaluation shows the two
   domains need different decision boundaries.

Track B is the one that actually retires the code-shape-floor heuristic and
its documented coverage hole. Track A alone improves ingress precision but
does **not** touch the egress gap — they should not be conflated as one
deliverable.

## 4. What does NOT need to be rebuilt

Reused as-is, no changes needed: `acquire_datasets.py`,
`build_semantic_splits.py` (BGE-small embeddings, cosine-0.94 grouping,
template/transformation-parent grouping — already proven leakage-safe),
`build_training_corpus.py`, `build_training_manifest.py`,
`train_layer2_multilabel.py` (weighted BCE, per-category temperature
calibration), `echelon/training_gate.py` (fail-closed gate — will and should
reject an under-reviewed v0.3 corpus exactly as it rejected v0.2 before
review completed), the entire distributed-review workflow
(`review_bootstrap.py`, `validate_distributed_reviews.py`,
`build_expert_review_kit.py`, `import_review_decisions.py`).

Track A needs only *more volume* through this existing machinery. Track B
needs the spec/sourcing/labeling-boundary work in §3 before it can use the
same machinery at all — the generation and acquisition steps are the actual
new engineering; everything downstream of "candidates exist and are
provenance-tagged" is reusable unchanged.

## 5. Rough sizing (for planning, not a commitment)

- **Track A**: generation + audit is small (hours to low-single-digit days
  of compute/scripting, mirroring the effort `generate_targeted_v02.py`
  already represents). Human review of ~8,000 combined new candidates
  (4,000 malicious-code + 4,000 system-prompt-leakage, before matched-benign
  controls) at v0.2's observed pace (600 items, 2 reviewers, plus 152-item
  expert adjudication) is the real cost driver — expect this to be the
  majority of Track A's calendar time, and it needs a real reviewer
  headcount decision, not just engineering time.
- **Track B**: spec-writing + sourcing decision is a design task (should be
  scoped and reviewed on its own before any generation starts, per §3.1-3.3
  above). Volume needed is smaller than Track A in absolute terms (this is
  one new slice, not two), but every row costs more to produce and review
  since there's no existing generator to extend and the labeling boundary
  is genuinely harder to get consistent across reviewers.
- Both tracks end at the same fail-closed gate
  (`scripts/check_training_gate.py`) and the same re-evaluation step this
  repo already runs (`echelon/evaluation.py` — precision/recall/F1, benign
  FPR, Brier/ECE, slice metrics) before any new model is served. **A retrain
  is not "done" until the new model clears that gate and its slice metrics
  are reported honestly, including any categories that are still weak** —
  matching how the current model's known limitation was reported rather
  than hidden.

## 6. Recommended sequencing

1. Track A first — it's lower-risk, uses proven machinery end-to-end, and
   directly fixes the two lowest-support categories in the current model
   card. It does not require any new design decisions, only volume and
   review capacity.
2. Track B's spec/sourcing/boundary design (§3.1-3.3) can start in parallel
   as a planning task, but its generation/review/training should not start
   until that design is reviewed — unlike Track A, there's no existing
   proven spec to fall back on here.
3. Do not combine A and B into one training manifest/run. Evaluate them
   separately (or at minimum report slice metrics separately) so a
   regression in one is never masked by improvement in the other.
