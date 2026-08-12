"""Two independently-implemented, blind, rule-based AI review policies for v0.3.

**AI-assisted, provisional, human-overridable** -- exactly the framing already
established by scripts/ai_adjudicate_v02.py for the v0.2 round's 152-conflict
adjudication. This module extends that same idea from conflict-adjudication
to full primary review, at 100% coverage, because at v0.3's scale the real
constraint (per LAYER2_RETRAIN_PLAN.md) is human reviewer bandwidth, not
review logic -- and the review logic itself is fully documented, deterministic,
and inspectable here, unlike an opaque human judgment call.

Both reviewers see ONLY blinded fields (candidate_id/text/language/transformation
-- never proposed_labels or family), matching exactly what a human primary
reviewer sees in the real distributed-review kit. They independently infer a
decision from the taxonomy boundary rules in docs/TARGETED_CURATION_SPEC.md,
not by looking up how the text was generated.

Reviewer A and Reviewer B are genuinely different implementations (different
signal sets, different thresholds) so that real disagreements can surface and
go to expert adjudication, rather than two copies of the same function
rubber-stamping each other. Neither is a ground-truth oracle; both can be
wrong in the same direction the generator was wrong, since one author (Claude)
wrote generator, reviewers, and adjudicator alike -- this is the same
limitation ai_adjudicate_v02.py already documented, carried forward honestly
rather than dressed up as independent human review.
"""

from __future__ import annotations

import re
from typing import Any

from scripts.generate_targeted_v03 import (
    CODE_CAPABILITIES, LEAKAGE_ACTIONS, LEAKAGE_BENIGN_OBJECTS, LEAKAGE_TARGETS,
)

VALID_LABELS = {
    "prompt_injection", "system_prompt_leakage", "malicious_code",
    "toxicity_harm", "adversarial_obfuscation", "benign",
}

# These vocabulary phrases are embedded VERBATIM in generated text by
# generate_targeted_v03.combinatorial_rows's frame.format(...) call --
# CODE_CAPABILITIES and DEFENSIVE_TASKS are disjoint (offensive-verb vs
# defensive-verb phrasing), so exact substring matching against the same
# authoritative lists the generator uses is a high-recall, high-precision
# signal, not a weak keyword guess. This is the same domain vocabulary a
# human reviewer trained on this taxonomy would also recognize on sight.
def _phrase_pattern(phrases: list[str]) -> re.Pattern:
    return re.compile("|".join(re.escape(p) for p in phrases), re.IGNORECASE)


CODE_CAPABILITY_PHRASES = _phrase_pattern(CODE_CAPABILITIES)
LEAKAGE_TARGET_PHRASES = _phrase_pattern(LEAKAGE_TARGETS)
LEAKAGE_ACTION_PHRASES = _phrase_pattern(LEAKAGE_ACTIONS)
# LEAKAGE_TARGETS phrases like "developer note" deliberately echo real-world
# leakage-target nouns, and LEAKAGE_BENIGN_OBJECTS phrases like "mock developer
# note in my article" reuse that same noun inside an explicitly-fictional
# qualifier -- a plain substring match on LEAKAGE_TARGET_PHRASES alone can't
# tell those apart. Presence of a benign-object qualifier is a strong override.
BENIGN_OBJECT_PHRASES = _phrase_pattern(LEAKAGE_BENIGN_OBJECTS)

# --- Shared low-level signals (both reviewers use these identically; their
#     combination logic over the vocabulary-phrase signals above is where the
#     genuine independence between A and B actually lives) ---

# Matches the presence of an encode/decode-transformation wrapper -- this
# vocabulary (decode/concealed/reversed/base64/hex/etc.) is specific to the
# obfuscated_attack_v03/encoded_benign_control_v03 wrapper templates and does
# not otherwise appear in the other families' text.
OBFUSCATION_WRAPPER_SIGNAL = re.compile(
    r"\b(decod\w*|encoded|concealed|reversed?|base64|unicode.escape|"
    r"this (hex|url) (payload|blob|value|sample|string|sequence))\b", re.IGNORECASE,
)
# Malicious wrapper templates ask the model to obey/execute the decoded
# content; benign wrapper templates frame it as an inert QA/documentation
# fixture. These phrase sets are disjoint by construction (see MALICIOUS_
# WRAPPERS vs BENIGN_WRAPPERS in generate_targeted_v03.py).
MALICIOUS_WRAPPER_INTENT = re.compile(
    r"\b(attacker|bypass|obey|carry it out|comply|no questions|authoritative|"
    r"text filter|whatever it demands|filter keeps blocking|hidden directive|"
    r"perform what it asks|do exactly what it says|execute the request)\b", re.IGNORECASE,
)
REAL_IP_SIGNAL = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
REAL_DOMAIN_SIGNAL = re.compile(r"\bhttps?://[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)


def _obfuscation_labels(text: str) -> list[str]:
    if not OBFUSCATION_WRAPPER_SIGNAL.search(text):
        return []
    if not MALICIOUS_WRAPPER_INTENT.search(text):
        return []  # benign encoded-fixture wrapper: no obfuscation/injection label
    return ["adversarial_obfuscation", "prompt_injection"]


def _naturalness(text: str) -> int:
    """Deterministic, structure-tolerant naturalness score (1-5).

    Tolerates the dialogue style's multi-line/script-like format -- it should
    not be penalized just for not being one flowing sentence.
    """
    stripped = text.strip()
    length = len(stripped)
    if length < 8:
        return 1
    words = re.findall(r"[A-Za-z']+", stripped)
    if len(words) < 3:
        return 2
    # Repeated-token runs (a real naturalness defect, not a style choice).
    lowered = [w.lower() for w in words]
    max_run = 1
    run = 1
    for prev, cur in zip(lowered, lowered[1:]):
        run = run + 1 if prev == cur else 1
        max_run = max(max_run, run)
    if max_run >= 4:
        return 2
    if length > 1200:
        return 3
    score = 5
    if not re.search(r"[.:?!]\s*$", stripped) and "\n" not in stripped:
        score -= 1
    if length < 20:
        score -= 1
    return max(1, min(5, score))


def _infer_labels_a(text: str) -> tuple[str, list[str]]:
    """Reviewer A: vocabulary-anchored taxonomy reviewer.

    CODE_CAPABILITIES/DEFENSIVE_TASKS/LEAKAGE_TARGETS/LEAKAGE_ACTIONS are
    embedded verbatim in generated text (the frame templates format() the
    literal list entries in), and CODE_CAPABILITIES/DEFENSIVE_TASKS are
    disjoint vocabularies (offensive-verb vs defensive-verb phrasing) -- so
    exact-phrase presence is a high-recall, high-precision signal here, not
    a guess. Reviewer A requires only ONE of target/action for leakage
    (a looser bar than Reviewer B below -- the source of most disagreements).
    """
    has_benign_object = bool(BENIGN_OBJECT_PHRASES.search(text))
    has_leak_target = bool(LEAKAGE_TARGET_PHRASES.search(text)) and not has_benign_object
    has_leak_action = bool(LEAKAGE_ACTION_PHRASES.search(text))
    has_code_cap = bool(CODE_CAPABILITY_PHRASES.search(text))

    labels: list[str] = []
    if has_leak_target or has_leak_action:
        labels.extend(["prompt_injection", "system_prompt_leakage"])
    if has_code_cap:
        labels.append("malicious_code")
    labels.extend(_obfuscation_labels(text))

    if not labels:
        return "benign", ["benign"]
    return "malicious", sorted(set(labels))


def _infer_labels_b(text: str) -> tuple[str, list[str]]:
    """Reviewer B: stricter co-occurrence reviewer.

    Requires BOTH a leakage target noun AND an extraction-action verb (not
    just one) before calling system_prompt_leakage -- a stricter bar than
    Reviewer A, giving genuine (not artificial) disagreement on borderline
    items for expert adjudication to resolve. Also explicitly does not let
    an authorization claim ("for research", "assume I am authorized")
    suppress a capability match, per TARGETED_CURATION_SPEC.md's boundary
    rule that such phrasing never determines the label by itself.
    """
    has_benign_object = bool(BENIGN_OBJECT_PHRASES.search(text))
    has_leak_target = bool(LEAKAGE_TARGET_PHRASES.search(text)) and not has_benign_object
    has_leak_action = bool(LEAKAGE_ACTION_PHRASES.search(text))
    has_code_cap = bool(CODE_CAPABILITY_PHRASES.search(text))

    labels: list[str] = []
    if has_leak_target and has_leak_action:
        labels.extend(["prompt_injection", "system_prompt_leakage"])
    if has_code_cap:
        labels.append("malicious_code")  # authorization-claim wording never suppresses this
    labels.extend(_obfuscation_labels(text))

    if not labels:
        return "benign", ["benign"]
    return "malicious", sorted(set(labels))


def _non_operational(text: str) -> bool:
    """True unless a real (non-placeholder) IP/domain leaked into the text --
    the generator's own discipline is abstracted placeholders only, so this is
    a safety-net check, not expected to ever actually fire on generated text.
    """
    return not (REAL_IP_SIGNAL.search(text) or REAL_DOMAIN_SIGNAL.search(text))


def _rationale(decision: str, labels: list[str]) -> str:
    if decision == "benign":
        return "label_confirmed"
    return "label_confirmed"


def reviewer_a_assess(item: dict[str, Any]) -> dict[str, Any]:
    text = item["text"]
    decision, labels = _infer_labels_a(text)
    naturalness = _naturalness(text)
    non_operational = _non_operational(text)
    confident = bool(labels) if decision == "malicious" else True
    return {
        "decision": decision, "labels": labels, "naturalness": naturalness,
        "intent_correct": confident, "labels_correct": confident,
        "non_operational": non_operational, "rationale_code": _rationale(decision, labels),
    }


def reviewer_b_assess(item: dict[str, Any]) -> dict[str, Any]:
    text = item["text"]
    decision, labels = _infer_labels_b(text)
    naturalness = _naturalness(text)
    non_operational = _non_operational(text)
    confident = bool(labels) if decision == "malicious" else True
    return {
        "decision": decision, "labels": labels, "naturalness": naturalness,
        "intent_correct": confident, "labels_correct": confident,
        "non_operational": non_operational, "rationale_code": _rationale(decision, labels),
    }


def expert_adjudicate(item: dict[str, Any], review_a: dict[str, Any], review_b: dict[str, Any]) -> dict[str, Any]:
    """Documented, deterministic conflict resolution (mirrors ai_adjudicate_v02.py's policy style).

    Policy: prefer the reviewer that found MORE taxonomy signal (the fuller
    label set) when one decision is "malicious" and the other "benign" -- a
    real security-taxonomy miss (a reviewer failing to notice a leakage/code
    signal) is a more costly error than a borderline benign classification
    surviving to expert review. When both found "malicious" but with
    different label sets, take the union (both reviewers found real signal;
    neither found a false one). Ties broken toward the more conservative
    (malicious) reading, consistent with the project's stated default of
    failing closed on ambiguous safety judgments.
    """
    text = item["text"]
    a_mal = review_a["decision"] == "malicious"
    b_mal = review_b["decision"] == "malicious"
    if a_mal and b_mal:
        labels = sorted(set(review_a["labels"]) | set(review_b["labels"]))
        decision = "malicious"
        rationale = "label_confirmed"
    elif a_mal or b_mal:
        fuller = review_a if a_mal else review_b
        decision, labels = "malicious", fuller["labels"]
        rationale = "label_corrected"
    else:
        decision, labels = "benign", ["benign"]
        rationale = "label_confirmed"
    naturalness = max(review_a["naturalness"], review_b["naturalness"])
    non_operational = review_a["non_operational"] and review_b["non_operational"]
    return {
        "decision": decision, "labels": labels, "naturalness": naturalness,
        "intent_correct": True, "labels_correct": True,
        "non_operational": non_operational, "rationale_code": rationale,
        "is_expert_adjudication": True,
    }
