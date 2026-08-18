# Echelon

An ultra-low-latency AI security firewall that sits between an application and its
target LLM. Echelon evaluates prompts before they reach the model, scans responses
before they leave the trust boundary, and provides the auth, rate-limit, and credit
controls needed to run model access safely — behind an OpenAI-compatible API.

The `demo_backend` branch also includes **[Echelon Policy Desk](policy_assistant/README.md)**,
a policy-review RAG chatbot with a cited chat UI, local document indexing, and an
OpenAI-compatible LLM connection. It runs independently on port `8100` and does
not change the existing security gateway behavior.

This is the consolidated monorepo. The three services previously lived on separate
branches (`rnd`, `backend`, `frontend`) and are merged here as subdirectories with
their history preserved.

```
echelon/
├── pipeline/        Python — detection pipeline + security API (was `rnd`)
│   ├── echelon/         three-fold cascade: layer1 heuristics, layer2 classifier, layer3 judge
│   ├── service/         security_api.py — serves /classify + /judge
│   └── models/…/best    trained multi-label Layer 2 model (weights git-ignored)
├── gateway/         Go — OpenAI-compatible firewall gateway (was `backend`)
│   ├── cmd/server/      composition root
│   └── internal/        auth, ratelimit, credit, ingress cascade, egress, telemetry, gateway
├── console/         Next.js — dashboard & management console (was `frontend`)
├── deploy/          Dockerfiles for each service
├── docker-compose.yml
└── scripts/         run-local.sh, demo-drive.sh
```

## How it fits together

```
Client ──OpenAI request──▶ gateway ──auth▶ rate-limit ▶ ingress cascade
                                                          │ L1 heuristics (in-Go)
                                                          │ L2 classifier ─HTTP /classify─▶ pipeline
                                                          │ L3 judge      ─HTTP /judge────▶ pipeline (Ollama LLM)
                                                          ▼
                                            block? 403 · else ▶ upstream LLM ▶ egress ▶ client
                                                          │
console ◀─ GET /v1/console/* (telemetry) ─────────────────┘
```

The gateway calls the Python pipeline over HTTP for the ML classifier and the LLM
judge; the judge is a **local Ollama model** (set `ECHELON_OLLAMA_MODEL`). The console
reads the gateway's `/v1/console/*` telemetry API. See **[DEMO.md](DEMO.md)** for the
exact contracts, run instructions, verified scenarios, and honest limitations.

## Quick start

```bash
# local (no Docker) — see scripts/run-local.sh for the automated version
PIPELINE_DIR=pipeline GATEWAY_DIR=gateway CONSOLE_DIR=console \
  PY=/path/to/py3.13-venv/bin/python ./scripts/run-local.sh
# then drive demo traffic:
./scripts/demo-drive.sh

# or containerized:
docker compose up --build   # console :3000, gateway :8080, policy desk :8100
```

**Policy Desk** (`policy_assistant/`, port 8100) is the end-user-facing half of the
demo: a real chat UI (upload a policy doc, ask questions, get cited answers) that
calls the gateway's OpenAI-compatible API rather than an LLM directly — so every
question and answer passes through the same ingress/egress safety cascade the
console shows telemetry for. Point it at a real LLM with a free Gemini key:

```bash
# get a free key: https://aistudio.google.com/apikey
GEMINI_API_KEY=... PY=/path/to/py3.13-venv/bin/python ./scripts/run-local.sh
# -> http://localhost:8100, routed through http://localhost:8080/v1 (gateway)
```

Without `GEMINI_API_KEY` it still runs, in local extractive mode (no LLM call —
matching sentences from the uploaded document, no safety cascade involved since
there is no outbound call to scan). See `policy_assistant/README.md`.

## Status

All core modules are built and wired end-to-end, re-verified live 2026-08-18 with
the real Ollama judge (`scripts/run-local.sh` + `scripts/demo-drive.sh`: 9 passed,
0 failed, 2 known defects): auth, rate-limit, three-fold ingress cascade with a
trained multi-label classifier, egress scanning with a dedicated response-side
model, console telemetry, and the management UI. The `/v1/console/*` and `/admin/*`
operator APIs require an operator credential (`CONSOLE_TOKEN`); the gateway refuses
to start without one.

Detection quality is reported two ways on purpose: the served ingress model scores
**macro-F1 0.9047 in-distribution** and **0.522 on a held-out set** built from four
frozen benchmarks it never trained on. The second number is the honest estimate of
production behaviour, and the gap between them is why the held-out set exists.

Two open defects are measured and tracked rather than papered over — legitimate
defensive-security prompts still get blocked, and ordinary benign responses
over-escalate to the LLM judge. Both, along with in-memory state and the
provisional AI-assisted review labels, are documented in [DEMO.md](DEMO.md) under
"Honest limitations", with reproducible probes under `pipeline/scripts/probe_*.py`.
