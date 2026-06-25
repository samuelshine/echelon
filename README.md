# Echelon

Go backend for an OpenAI-compatible LLM security gateway. The first milestone is a
fast reverse proxy with pluggable guardrails so model teams can add ONNX
classifiers, vector similarity checks, PII scrubbers, and runtime policy checks
behind stable interfaces.

## Current Backend Shape

- `cmd/server`: gateway executable.
- `internal/config`: environment-based service configuration.
- `internal/gateway`: HTTP routing and upstream proxying.
- `internal/guard`: prompt/output guard interfaces and initial heuristic filters.

## Run Locally

```sh
cp .env.example .env
export $(grep -v '^#' .env | xargs)
go run ./cmd/server
```

Health check:

```sh
curl http://localhost:8080/healthz
```

Point OpenAI-compatible clients at:

```text
http://localhost:8080/v1
```

Set `UPSTREAM_API_KEY` to the provider key that the gateway should use when
forwarding requests.

## Useful Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Basic liveness check. |
| `GET` | `/readyz` | Runtime readiness summary with upstream and guard status. |
| `GET` | `/admin/config` | Redacted configuration summary. |
| `GET` | `/admin/guards` | Lists enabled prompt guards and output scanners. |
| `POST` | `/v1/guard/preflight` | Runs prompt guards without calling the upstream model. |
| `POST` | `/v1/guard/output-scan` | Runs output scanners against a supplied response body. |
| `GET` | `/v1/models` | Proxies OpenAI-compatible model listing to the upstream provider. |
| `POST` | `/v1/chat/completions` | Guarded OpenAI-compatible chat completions proxy. |
| `POST` | `/v1/responses` | Guarded OpenAI-compatible responses proxy. |

Preflight example:

```sh
curl -sS http://localhost:8080/v1/guard/preflight \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"hello"}]}'
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `HTTP_ADDR` | `:8080` | Gateway listen address. |
| `UPSTREAM_BASE_URL` | `https://api.openai.com` | OpenAI-compatible upstream base URL. |
| `UPSTREAM_API_KEY` | empty | Bearer token sent to upstream. |
| `MAX_REQUEST_BYTES` | `1048576` | Request and response size limit. |
| `UPSTREAM_TIMEOUT` | `60s` | HTTP timeout for upstream model provider. |
| `SYSTEM_CANARY` | `[SYSTEM_CANARY_DEV]` | Token blocked if it appears in model output. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |

## Next Backend Milestones

1. Add an ONNX Runtime adapter implementing `guard.PromptGuard` for the injection
   classifier.
2. Add a PII scrubber that can redact, forward, and restore safe entities.
3. Add a tool-call policy layer for RBAC checks before agent actions execute.
4. Add request/decision audit logs with payload hashing instead of raw prompt
   storage.
