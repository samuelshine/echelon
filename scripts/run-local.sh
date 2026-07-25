#!/usr/bin/env bash
# Boot the full Echelon stack locally (no Docker) for a live demo.
# Points the gateway at a fake upstream so no OpenAI key is required.
#
# Configure paths to the three checkouts (defaults assume sibling worktrees):
#   PIPELINE_DIR  - rnd branch checkout (has service/, models/, the venv python)
#   GATEWAY_DIR   - backend branch checkout (Go)
#   CONSOLE_DIR   - frontend branch checkout (Next.js)
#   PY            - python interpreter with pipeline deps (torch/transformers/flask)
set -euo pipefail

PIPELINE_DIR="${PIPELINE_DIR:?set PIPELINE_DIR to the rnd checkout}"
GATEWAY_DIR="${GATEWAY_DIR:?set GATEWAY_DIR to the backend checkout}"
CONSOLE_DIR="${CONSOLE_DIR:?set CONSOLE_DIR to the frontend checkout}"
PY="${PY:-python3}"

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT

echo "[1/4] fake upstream LLM on :9100"
"$PY" - <<'PYEOF' &
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length',0)))
        b=b'{"id":"cmpl","choices":[{"message":{"role":"assistant","content":"A safe answer."}}],"usage":{"prompt_tokens":12,"completion_tokens":8}}'
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def do_GET(self):
        b=b'{"data":[{"id":"gpt-4o-mini"}]}';self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def log_message(self,*a): pass
HTTPServer(('127.0.0.1',9100),H).serve_forever()
PYEOF
pids+=($!)

echo "[2/4] security service on :8099 (loads the model)"
( cd "$PIPELINE_DIR" && ECHELON_MODEL_DIR=models/layer2-threat-distilbert/best PORT=8099 "$PY" -m service.security_api ) &
pids+=($!)

echo "[3/4] building + starting gateway on :8080"
( cd "$GATEWAY_DIR" && go build -o /tmp/echelon-gateway ./cmd/server )
ML_BASE_URL=http://127.0.0.1:8099/classify JUDGE_BASE_URL=http://127.0.0.1:8099/judge \
UPSTREAM_BASE_URL=http://127.0.0.1:9100 ECHELON_API_KEYS=sk-demo:acme:key_live:pro \
HTTP_ADDR=:8080 SECURITY_FAIL_CLOSED=true /tmp/echelon-gateway &
pids+=($!)

echo "[4/4] starting console on :3000"
( cd "$CONSOLE_DIR" && NEXT_PUBLIC_ECHELON_API_URL=http://localhost:8080 npm run dev ) &
pids+=($!)

echo "waiting for services..."
for _ in $(seq 1 60); do
  curl -sf localhost:8099/health >/dev/null 2>&1 && curl -sf localhost:8080/healthz >/dev/null 2>&1 && break
  sleep 1
done
echo
echo "Echelon is up:"
echo "  console : http://localhost:3000"
echo "  gateway : http://localhost:8080  (OpenAI-compatible, Bearer sk-demo)"
echo "  drive demo traffic: scripts/demo-drive.sh"
echo "Ctrl-C to stop."
wait
