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

Status: **Pending**

- [ ] Implement local token bucket for development and Redis/Lua token bucket for
  atomic distributed enforcement.
- [ ] Add API-key authentication using constant-time digest comparison.
- [ ] Add idempotent credit reservation, commit, and release around upstream usage.
- [ ] Return standard rate-limit headers and stable machine-readable errors.
- [ ] Test concurrency, Redis failure behavior, refunds, and duplicate operations.

## Phase 5 — API and provider wiring

Status: **Pending**

- [ ] Introduce application use cases that orchestrate auth, quota, ingress,
  upstream, egress, credits, and audit without depending on HTTP.
- [ ] Wire OpenAI-compatible chat and responses endpoints with dependency injection.
- [ ] Preserve streaming semantics with an explicitly documented buffered-security
  mode; never imply a stream was scanned before it was buffered.
- [ ] Add request IDs, panic recovery, secure headers, observability, readiness, and
  graceful draining.
- [ ] Add golden HTTP contract tests and end-to-end tests with fake dependencies.

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
