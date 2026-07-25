# Echelon Backend Execution Plan

This document is the build ledger for Echelon. A phase is complete only when its
implementation, tests, documentation, and operational notes are all checked off.

## Engineering invariants

- The gateway owns one end-to-end `context.Context` deadline and every plugin
  receives that context.
- Security decisions fail closed only where policy explicitly requires it;
  availability behavior is configurable per remote layer.
- Domain and port packages do not import transport, vendor, or infrastructure
  packages.
- Plugins are immutable after startup and safe for concurrent use.
- Prompt and response bodies are never written to logs; audit records contain
  identifiers, hashes, findings, timing, and usage only.
- Hot-path work is bounded by request size, concurrency, and latency budgets.

## Phase 1 — Foundation, configuration, and core contracts

Status: **Complete**

- [x] Preserve and baseline the existing OpenAI-compatible prototype.
- [x] Define provider-neutral request, response, verdict, finding, and usage models.
- [x] Define narrow ports for ingress layers, egress scanners, upstreams, rate
  limiting, credit reservation, audit events, and clocks.
- [x] Add validated environment configuration for server limits, per-layer
  budgets, classifier/judge endpoints, rate limiting, and shutdown behavior.
- [x] Document the target architecture and local development workflow.
- [x] Add configuration and domain unit tests.

## Phase 2 — Ingress cascade

Status: **Complete**

- [x] Implement the allocation-conscious heuristic matcher with normalized text,
  compiled expressions, confidence scores, and rule metadata.
- [x] Implement a bounded, context-aware semantic classifier HTTP adapter suitable
  for DistilBERT/DeBERTa services.
- [x] Implement the LLM-judge adapter with strict structured output parsing.
- [x] Build the gated cascade: heuristics → semantic classifier → judge, with
  configurable thresholds, per-stage budgets, fail policy, and short-circuiting.
- [x] Add table, cancellation, timeout, and malformed-response tests.
- [x] Add an allocation benchmark for heuristic evaluation; the Phase 2 baseline
  is approximately 5.2 µs/op and 65 B/op with one allocation on Apple M4 Pro.

## Phase 3 — Egress security pipeline

Status: **Complete**

- [x] Add composite scanner orchestration and deterministic mutation semantics.
- [x] Add toxicity classification, PII detection/masking, canary leakage, policy
  violation, and hallucination-verifier plugin contracts/adapters.
- [x] Guarantee scanners cannot return unapproved partial mutations by isolating
  each scanner input and accepting body changes only with a redact verdict.
- [x] Test blocking, redaction, cancellation, scanner ordering, and fail policy.

## Phase 4 — Gateway protection and wallet controls

Status: **In progress** (in-memory adapters complete; Redis deferred)

- [x] Implement local token bucket for development (`internal/ratelimit`). Redis/Lua
  distributed enforcement deferred to a later pass.
- [x] Add API-key authentication using constant-time digest comparison (`internal/auth`).
- [x] Add idempotent credit reservation, commit, and release (`internal/credit`) —
  reservation semantics refund unused/failed usage. Not yet wired into the request
  path (cost estimation pending).
- [x] Return `Retry-After` + stable machine-readable error codes on 401/403/429.
- [x] Unit-test refunds, duplicate (idempotent) operations, and bucket refill;
  concurrency/Redis-failure tests deferred with Redis.

## Phase 5 — API and provider wiring

Status: **In progress** (security composition wired end-to-end; use-case layer & streaming deferred)

- [x] Compose auth → quota → ingress cascade → upstream → egress on the proxied
  OpenAI path (`internal/gateway`), constructed from config in `cmd/server`. The
  hexagonal `ingress.Cascade` (heuristics → remote ML `/classify` → remote judge
  `/judge`) supersedes the prototype guards when `ML_BASE_URL` is set.
- [x] OpenAI-compatible chat/responses/models endpoints proxy with DI of the
  security ports; the ML classifier scores the extracted user prompt (not role
  labels / model id).
- [ ] Extract a transport-independent application use-case type (currently composed
  in the gateway handler); wire credit reserve/commit around upstream usage.
- [ ] Preserve streaming with an explicit buffered-security mode (still buffered-only).
- [x] Request logging + graceful draining present; add panic recovery + full
  observability in Phase 6.
- [x] End-to-end tests with fake upstream + fake security service
  (`phase5_integration_test.go`): auth 401, benign 200, classifier-flagged 403,
  rate-limit 429. Verified live against the real Python model service end-to-end.

## Console telemetry API (B2)

Status: **Done** (in-memory)

- [x] `internal/telemetry` bounded ring buffer of privacy-safe decision records (no
  raw prompt/response text — verdicts, scores, timing, identifiers only).
- [x] Gateway records each proxied request (block + pass) and serves the console
  read API in the exact shapes the Next.js console consumes:
  `GET /v1/console/{summary,metrics,events,keys,config}` with CORS for the browser.
- [x] Category and per-layer mapping from core verdicts to the console domain model;
  API-key usage aggregated per key. Verified live end-to-end against real traffic.

## Phase 6 — Production hardening and delivery

Status: **Pending**

- [ ] Add Prometheus-compatible metrics, OpenTelemetry spans, and privacy-safe audit
  sinks.
- [ ] Add Docker image, Compose development stack, Kubernetes probes/resources,
  and example production configuration.
- [ ] Run fuzzing, `go test -race`, benchmarks, profiling, static analysis, and
  dependency/security scans.
- [ ] Establish latency SLOs, overload behavior, rollout/rollback, and incident
  runbooks.
- [ ] Publish architecture decision records and the completed engineering article.

## Immediate next steps

1. Implement the atomic in-memory and Redis/Lua token buckets in Phase 4.
2. Add constant-time API-key authentication and quota response metadata.
3. Implement idempotent credit reservation, commit, and release semantics.
