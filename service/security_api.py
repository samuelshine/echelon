#!/usr/bin/env python3
"""Echelon security HTTP service — the remote L2 classifier + L3 judge for the Go gateway.

Exposes exactly the two contracts the Go ingress adapters expect
(`internal/ingress/http_adapters.go`), which decode with DisallowUnknownFields:

    POST /classify  {request_id, model?, text} -> {malicious_probability, labels}
    POST /judge     {request_id, model?, text} -> {malicious, confidence, code}

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
from echelon.layer3 import HttpJsonJudgeAdapter, Layer3Judge, MockJudge

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_DIR = PROJECT_ROOT / "models" / "layer2-threat-distilbert" / "best"
MAX_TEXT_BYTES = 200_000

# Per-category reliability applied to the BLOCK signal only (raw scores are still
# reported in `labels` for transparency). The trained model has low precision and
# tiny support on these two categories, which produced defensive-cyber false blocks;
# down-weighting their contribution to the aggregate escalates such prompts to the
# judge instead of hard-blocking. See models/layer2-threat-distilbert/metrics.json.
CATEGORY_RELIABILITY = {
    "prompt_injection": 1.0,
    "toxicity_harm": 1.0,
    "adversarial_obfuscation": 1.0,
    "system_prompt_leakage": 0.7,
    "malicious_code": 0.7,
}


def _mitigated_scores(scores):
    return {k: v * CATEGORY_RELIABILITY.get(k, 1.0) for k, v in scores.items()}


def _aggregate(scores):
    return max(_mitigated_scores(scores).values(), default=0.0)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_048_576  # 1 MiB request cap


@lru_cache(maxsize=1)
def _services():
    model_dir = Path(os.environ.get("ECHELON_MODEL_DIR", str(DEFAULT_MODEL_DIR)))
    analyzer = HeuristicAnalyzer()
    classifier = Layer2Classifier(MultiLabelTransformersAdapter(model_dir))
    endpoint = os.environ.get("ECHELON_JUDGE_ENDPOINT")
    if endpoint:
        adapter = HttpJsonJudgeAdapter(
            endpoint, token=os.environ.get("ECHELON_JUDGE_TOKEN", ""),
            judge_id="echelon-remote-judge", revision="1",
        )
    else:
        adapter = MockJudge()
    return analyzer, classifier, Layer3Judge(adapter)


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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8099"))
    _services()  # eager load so the first request is fast and failures surface at boot
    app.run(host="127.0.0.1", port=port)
