#!/usr/bin/env python3
"""Echelon security HTTP service — the remote L2 classifier + L3 judge for the Go gateway.

Exposes exactly the contracts the Go ingress/egress adapters expect
(`internal/ingress/http_adapters.go`, `internal/egress/http_response_*.go`), which
decode with DisallowUnknownFields:

    POST /classify           {request_id, model?, text} -> {malicious_probability, labels}
    POST /judge               {request_id, model?, text} -> {malicious, confidence, code}
    POST /classify_response  {request_id, model?, text} -> {malicious_probability, labels}
    POST /judge_response      {request_id, model?, text} -> {malicious, confidence, code}

The `_response` routes score LLM OUTPUT text (egress) instead of user prompts
(ingress). Same model, same wire contract — but only `toxicity_harm` and
`malicious_code` drive the aggregate signal, since the model was trained on
prompt/attack text only (assistant responses explicitly excluded from the
training corpus — see `scripts/build_training_manifest.py`). Reusing it on
response text is a reasonable but unvalidated extension, not a calibrated
output classifier. `prompt_injection`/`adversarial_obfuscation` are input-framed
and excluded from the response aggregate; `system_prompt_leakage` on output is
handled by the gateway's deterministic canary check instead, which is more
reliable for that literal-string-match case than an unvalidated ML score.

Design constraints:
  * responses contain ONLY the fields the Go structs declare (no extras);
  * prompt text is never logged (no-raw-prompt policy);
  * request bodies are size-bounded;
  * on internal failure we return non-2xx so the gateway's fail-closed policy applies.

The Layer 2 model is the calibrated multi-label artifact from
scripts/train_layer2_multilabel.py. The Layer 3 judge defaults to a deterministic
stand-in (MockJudge) fed by real Layer 1 + Layer 2 context; set ECHELON_JUDGE_ENDPOINT
(+ ECHELON_JUDGE_TOKEN) to route to a real HTTPS LLM judge instead.
"""

from __future__ import annotations

import dataclasses
import os
from functools import lru_cache
from pathlib import Path

from flask import Flask, jsonify, request

from echelon.contracts import Route, ThresholdPolicy
from echelon.layer1 import HeuristicAnalyzer
from echelon.layer2 import Layer2Classifier, Layer2Config, MultiLabelTransformersAdapter
from echelon.layer3 import (
    OLLAMA_OUTPUT_JUDGE_INSTRUCTION,
    HttpJsonJudgeAdapter,
    Layer3Judge,
    MockJudge,
    OllamaJudgeAdapter,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_DIR = PROJECT_ROOT / "models" / "layer2-threat-distilbert" / "best"
MAX_TEXT_BYTES = 200_000

# The trained model is low-precision on these two sparse categories AND scores them
# non-monotonically (it flags defensive-cyber higher than actual malware). No single
# threshold separates them — only the LLM judge can. So for the BLOCK signal (raw
# scores are still reported in `labels`), any non-trivial sparse-category signal is
# mapped into the escalate band [FLOOR, CAP]: never hard-block (< block threshold),
# never silently pass (>= judge threshold), always routed to the judge to adjudicate.
SPARSE_CATEGORIES = {"malicious_code", "system_prompt_leakage"}
SPARSE_FLOOR = 0.60  # >= ML_JUDGE_THRESHOLD (0.55): force escalation to the judge
SPARSE_CAP = 0.88    # <  ML_BLOCK_THRESHOLD (0.90): never hard-block on a sparse category
SPARSE_TRIGGER = 0.30  # below this, treat as noise and leave untouched


def _mitigated_scores(scores):
    out = {}
    for category, value in scores.items():
        if category in SPARSE_CATEGORIES and value >= SPARSE_TRIGGER:
            out[category] = min(SPARSE_CAP, max(SPARSE_FLOOR, value))
        else:
            out[category] = value
    return out


def _aggregate(scores):
    return max(_mitigated_scores(scores).values(), default=0.0)


# Only these two categories are conceptually meaningful on LLM OUTPUT text (see
# module docstring). prompt_injection/adversarial_obfuscation are input-framed;
# system_prompt_leakage is left to the gateway's deterministic canary check.
RESPONSE_RELEVANT_CATEGORIES = {"toxicity_harm", "malicious_code"}


def _aggregate_response(scores):
    mitigated = _mitigated_scores(scores)
    relevant = {k: v for k, v in mitigated.items() if k in RESPONSE_RELEVANT_CATEGORIES}
    return max(relevant.values(), default=0.0)


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_048_576  # 1 MiB request cap


@lru_cache(maxsize=1)
def _services():
    model_dir = Path(os.environ.get("ECHELON_MODEL_DIR", str(DEFAULT_MODEL_DIR)))
    analyzer = HeuristicAnalyzer()
    classifier = Layer2Classifier(MultiLabelTransformersAdapter(model_dir))
    ollama_model = os.environ.get("ECHELON_OLLAMA_MODEL")
    endpoint = os.environ.get("ECHELON_JUDGE_ENDPOINT")
    if ollama_model:
        adapter = OllamaJudgeAdapter(
            ollama_model,
            endpoint=os.environ.get("ECHELON_OLLAMA_URL", "http://localhost:11434"),
            timeout_seconds=float(os.environ.get("ECHELON_OLLAMA_TIMEOUT", "30")),
        )
    elif endpoint:
        adapter = HttpJsonJudgeAdapter(
            endpoint, token=os.environ.get("ECHELON_JUDGE_TOKEN", ""),
            judge_id="echelon-remote-judge", revision="1",
        )
    else:
        adapter = MockJudge()
    return analyzer, classifier, Layer3Judge(adapter)


@lru_cache(maxsize=1)
def _response_judge() -> Layer3Judge:
    """A second Layer3Judge, output-framed, sharing ingress's judge backend config."""
    ollama_model = os.environ.get("ECHELON_OLLAMA_MODEL")
    endpoint = os.environ.get("ECHELON_JUDGE_ENDPOINT")
    if ollama_model:
        adapter = OllamaJudgeAdapter(
            ollama_model,
            endpoint=os.environ.get("ECHELON_OLLAMA_URL", "http://localhost:11434"),
            timeout_seconds=float(os.environ.get("ECHELON_OLLAMA_TIMEOUT", "30")),
            instruction=OLLAMA_OUTPUT_JUDGE_INSTRUCTION,
        )
    elif endpoint:
        adapter = HttpJsonJudgeAdapter(
            endpoint, token=os.environ.get("ECHELON_JUDGE_TOKEN", ""),
            judge_id="echelon-remote-response-judge", revision="1",
        )
    else:
        adapter = MockJudge()
    return Layer3Judge(adapter)


def _read_prompt() -> str:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("text"), str):
        raise ValueError("request must be a JSON object with a string 'text'")
    text = payload["text"]
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValueError("prompt exceeds size limit")
    return text


@app.get("/health")
def health():
    analyzer, classifier, _ = _services()
    output = classifier.adapter.predict("healthcheck")
    return jsonify({
        "status": "ok",
        "model_id": output.model_id,
        "calibrated": output.calibrated,
        "categories": sorted(output.category_scores),
    })


@app.post("/classify")
def classify():
    try:
        text = _read_prompt()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        _, classifier, _ = _services()
        result = classifier.analyze(text)
    except Exception:  # fail closed at the gateway
        app.logger.error("classify failed", exc_info=False)
        return jsonify({"error": "classifier unavailable"}), 503
    # EXACTLY the fields of core.Classification (malicious_probability, labels).
    # Block signal is reliability-weighted; labels report the raw per-category scores.
    return jsonify({
        "malicious_probability": round(float(_aggregate(result.category_scores)), 6),
        "labels": {k: round(float(v), 6) for k, v in result.category_scores.items()},
    })


@app.post("/judge")
def judge():
    try:
        text = _read_prompt()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        analyzer, classifier, judge_layer = _services()
        layer1 = analyzer.analyze(text)
        layer2 = classifier.analyze(text)
        # Apply the same reliability weighting so the judge's view matches /classify.
        weighted = _mitigated_scores(layer2.category_scores)
        aggregate = max(weighted.values(), default=0.0)
        layer2 = dataclasses.replace(
            layer2, category_scores=weighted, risk_score=aggregate,
            route=ThresholdPolicy().route(aggregate),
        )
        verdict = judge_layer.analyze(text, layer1, layer2)
    except Exception:
        app.logger.error("judge failed", exc_info=False)
        return jsonify({"error": "judge unavailable"}), 503
    malicious = verdict.route == Route.BLOCK
    code = verdict.rationale_codes[0] if verdict.rationale_codes else "policy_review"
    # EXACTLY the fields of the Go judgeResponse (malicious, confidence, code).
    return jsonify({
        "malicious": bool(malicious),
        "confidence": round(float(verdict.risk_score), 6),
        "code": str(code),
    })


@app.post("/classify_response")
def classify_response():
    """Scores LLM OUTPUT text. See module docstring for category-relevance caveats."""
    try:
        text = _read_prompt()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        _, classifier, _ = _services()
        result = classifier.analyze(text)
    except Exception:
        app.logger.error("classify_response failed", exc_info=False)
        return jsonify({"error": "classifier unavailable"}), 503
    return jsonify({
        "malicious_probability": round(float(_aggregate_response(result.category_scores)), 6),
        "labels": {k: round(float(v), 6) for k, v in result.category_scores.items()},
    })


@app.post("/judge_response")
def judge_response():
    """Judges LLM OUTPUT text with an output-framed instruction. See module docstring."""
    try:
        text = _read_prompt()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        analyzer, classifier, _ = _services()
        judge_layer = _response_judge()
        layer1 = analyzer.analyze(text)
        layer2 = classifier.analyze(text)
        weighted = _mitigated_scores(layer2.category_scores)
        aggregate = _aggregate_response(layer2.category_scores)
        layer2 = dataclasses.replace(
            layer2, category_scores=weighted, risk_score=aggregate,
            route=ThresholdPolicy().route(aggregate),
        )
        verdict = judge_layer.analyze(text, layer1, layer2)
    except Exception:
        app.logger.error("judge_response failed", exc_info=False)
        return jsonify({"error": "judge unavailable"}), 503
    malicious = verdict.route == Route.BLOCK
    code = verdict.rationale_codes[0] if verdict.rationale_codes else "policy_review"
    return jsonify({
        "malicious": bool(malicious),
        "confidence": round(float(verdict.risk_score), 6),
        "code": str(code),
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8099"))
    _services()  # eager load so the first request is fast and failures surface at boot
    _response_judge()
    app.run(host="0.0.0.0", port=port)
