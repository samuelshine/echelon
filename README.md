# Echelon

Echelon is an OpenAI-compatible, low-latency API gateway and AI security
firewall written in Go. It evaluates prompts before they reach an LLM, scans
model responses before they leave the trust boundary, and provides the quota and
credit controls needed to keep model usage safe and predictable.

> Build status: Phases 1 through 3 are complete. Typed ingress and egress
> pipelines and their remote classifier adapters are implemented; the existing
> prototype gateway remains wired to local guards until application composition in Phase 5. See
> [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) for the live build ledger.

## Architecture

The code follows hexagonal boundaries: provider-neutral models live in
`internal/core`, dependency contracts live in `internal/ports`, application
pipelines coordinate those contracts, and adapters own HTTP, Redis, classifier,
and LLM-provider details. Plugins are constructed once at startup and are safe
for concurrent use.

```mermaid
flowchart LR
    Client["Client"] --> HTTP["OpenAI-compatible HTTP adapter"]
    HTTP --> Auth["Authentication"]
    Auth --> Quota["Rate and credit admission"]
    Quota --> Ingress["Ingress cascade"]
    Ingress --> H["L1 heuristics"]
    H --> ML["L2 ML classifier"]
    ML --> Judge["L3 LLM judge"]
    Ingress --> Provider["Upstream LLM adapter"]
    Provider --> Egress["Egress pipeline"]
    Egress --> Toxicity["Toxicity"]
    Egress --> PII["PII mask"]
    Egress --> Hallucination["Hallucination check"]
    Egress --> HTTP
    HTTP --> Client
    Ingress -.-> Audit["Privacy-safe audit sink"]
    Egress -.-> Audit
```

The intended request path uses one global deadline. Each remote stage receives a
smaller child deadline and the cascade short-circuits as soon as policy reaches a
terminal decision.

```mermaid
sequenceDiagram
    participant C as Client
    participant G as Gateway
    participant R as Rate limiter
    participant H as Heuristics
    participant M as ML classifier
    participant J as LLM judge
    participant U as Upstream LLM
    participant E as Egress scanners

    C->>G: OpenAI-compatible request
    G->>R: Admit identity and cost
    R-->>G: Allowed and remaining quota
    G->>H: Evaluate prompt
    alt obvious malicious prompt
        H-->>G: Block
        G-->>C: 403 policy error
    else uncertain or safe
        H-->>G: Continue
        G->>M: Classify within ML budget
        alt ambiguous confidence
            M-->>G: Escalate
            G->>J: Judge within fallback budget
            J-->>G: Verdict
        else confident verdict
            M-->>G: Verdict
        end
        G->>U: Invoke model
        U-->>G: Response and usage
        G->>E: Scan and optionally redact
        E-->>G: Response verdict
        G-->>C: Approved response
    end
```

## Repository layout

```text
cmd/server/          executable and dependency composition
internal/config/     validated environment configuration
internal/core/       transport- and provider-neutral domain model
internal/ports/      plugin interfaces for security and infrastructure
internal/ingress/    gated heuristic, ML classifier, and LLM-judge cascade
internal/egress/     toxicity/policy/PII scanners and isolated composition
internal/guard/      prototype local guards (migrated in Phase 2)
internal/gateway/    prototype HTTP adapter (application wiring in Phase 5)
```

## Run locally

Go 1.22 or newer is required.

```sh
cp .env.example .env
set -a; . ./.env; set +a
go test ./...
go run ./cmd/server
```

Check liveness and run a local prompt preflight:

```sh
curl -sS http://localhost:8080/healthz

curl -sS http://localhost:8080/v1/guard/preflight \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"hello"}]}'
```

Set `UPSTREAM_API_KEY` before proxying provider requests. Echelon replaces an
inbound authorization header with this provider credential; it never exposes the
configured value through readiness or admin responses.

## HTTP surface

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Process liveness. |
| `GET` | `/readyz` | Redacted runtime readiness. |
| `GET` | `/admin/config` | Redacted configuration summary. |
| `GET` | `/admin/guards` | Enabled prompt and output plugins. |
| `POST` | `/v1/guard/preflight` | Prompt checks without an upstream call. |
| `POST` | `/v1/guard/output-scan` | Output checks without an upstream call. |
| `GET` | `/v1/models` | Proxied OpenAI-compatible model listing. |
| `POST` | `/v1/chat/completions` | Guarded chat completions. |
| `POST` | `/v1/responses` | Guarded Responses API call. |

## Configuration

The checked-in `.env.example` lists every operational setting. Important groups
are:

| Group | Variables |
| --- | --- |
| Server | `HTTP_ADDR`, `REQUEST_TIMEOUT`, `HTTP_*_TIMEOUT`, `SHUTDOWN_TIMEOUT` |
| Provider | `UPSTREAM_BASE_URL`, `UPSTREAM_API_KEY`, `UPSTREAM_TIMEOUT` |
| Payload | `MAX_REQUEST_BYTES`, `SYSTEM_CANARY` |
| Cascade | `HEURISTIC_TIMEOUT`, `ML_TIMEOUT`, `JUDGE_TIMEOUT`, `EGRESS_TIMEOUT` |
| Classifiers | `ML_BASE_URL`, `JUDGE_BASE_URL`, `ML_*_THRESHOLD` |
| Failure policy | `SECURITY_FAIL_CLOSED` |
| Quota | `RATE_LIMIT_BACKEND`, `REDIS_URL`, `RATE_LIMIT_*` |

Configuration is rejected at startup if URLs are malformed, thresholds are
inverted, Redis is selected without a URL, values are non-positive, or the global
request budget cannot contain the configured sequential stage budgets.

## Design constraints

- Raw prompt and response content must not appear in logs or audit records.
- Network classifiers are optional adapters, not domain dependencies.
- Credit usage uses reserve/commit/release semantics and idempotency keys.
- Redis admission is atomic; the in-memory limiter is development-only.
- Streaming needs an explicit security mode because content cannot be both fully
  scanned and immediately forwarded. Phase 5 will expose that tradeoff rather
  than silently weakening egress guarantees.
