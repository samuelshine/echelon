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
docker compose up --build   # console :3000, gateway :8080
```

## Status

All core modules are built and wired end-to-end (verified live): auth, rate-limit,
three-fold ingress cascade with a trained multi-label classifier and a local Ollama
LLM judge, egress scanning, console telemetry, and the management UI. Known
limitations (model precision on sparse categories, in-memory state, provisional
AI-assisted review labels) are documented in [DEMO.md](DEMO.md).
