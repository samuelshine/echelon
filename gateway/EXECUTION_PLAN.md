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

### Egress ML cascade addendum (2026-08-01)

- [x] Added a remote ML classifier + LLM-judge escalation stage to the egress
  pipeline (`internal/egress/ml_cascade.go`, `http_response_classifier.go`,
  `http_response_judge.go`), mirroring the ingress cascade's `/classify`→judge
  routing but on response text via `POST /classify_response` /
  `POST /judge_response` on the Python service. Wired into `buildEgress()` in
  `cmd/server/main.go` alongside the pre-existing PII/canary scanners.
- [x] Tests: `http_response_adapters_test.go`, `ml_cascade_test.go`,
  `gateway/phase6_egress_test.go`. `go build`/`go vet`/`go test ./...` all pass.
- **Known real gap (not fixed):** the Layer 2 classifier was trained only on
  prompt/attack text, not assistant responses — operational malicious code in a
  response scores near-zero on the `malicious_code` head, never crosses
  `ML_JUDGE_THRESHOLD`, and the judge is never invoked. Verified live: a working
  keylogger sample returned 200 unblocked. `toxicity_harm` and PII do not share
  this gap. See `DEMO.md` → "Honest limitations."

## Phase 4 — Gateway protection and wallet controls

Status: **Done** (memory + Redis adapters implemented; token-based cost estimation deferred)

- [x] Implement local token bucket for development (`internal/ratelimit`).
- [x] Implement a distributed Redis/Lua token bucket (`internal/ratelimit/redis.go`,
  `RedisTokenBucket`) with the same admission semantics as the in-memory bucket —
  refill + check + decrement executed as a single Lua script (`EVAL`) so multiple
  gateway replicas sharing one Redis instance cannot over-admit.
- [x] Add API-key authentication using constant-time digest comparison (`internal/auth`).
- [x] Add idempotent credit reservation, commit, and release (`internal/credit`) —
  reservation semantics refund unused/failed usage.
- [x] Implement a distributed Redis/Lua credit ledger (`internal/credit/redis.go`,
  `RedisLedger`) mirroring `MemoryLedger`'s reservation semantics — Reserve/Commit/
  Release each run as a single Lua script; abandoned reservations are lazily
  reclaimed via a per-tenant holds ZSET swept on every `Reserve`.
- [x] Wire credit reserve/commit/release into the request path
  (`internal/gateway/gateway.go`, `proxyLLM`): a credit is reserved after
  admission (auth + rate limit) and before the upstream call, released if the
  upstream call errors out, and committed once a response is received. Enforced
  for both the memory and Redis backends — `cmd/server/main.go` constructs
  whichever `ports.CreditLedger` matches `RATE_LIMIT_BACKEND` (the same flag
  now governs both the rate limiter and the credit ledger; there is no separate
  `CREDIT_BACKEND`) and passes it into `gateway.Options.CreditLedger`.
  Cost model is currently **flat 1 credit per completed request**; token-based
  cost estimation (pricing by prompt/completion tokens) is a **deferred
  follow-up**, not yet implemented.
- [x] Return `Retry-After` + stable machine-readable error codes on 401/403/429
  (rate limit) and 402 (insufficient credits).
- [x] Unit-test refunds, duplicate (idempotent) operations, and bucket refill for
  both backends, including Redis-specific coverage (`internal/ratelimit/redis_test.go`,
  `internal/credit/redis_test.go`, via `miniredis`) and end-to-end credit
  enforcement through the gateway handler (`internal/gateway/phase3_credit_test.go`).
  All packages green under `go test -race ./...`.
- **Verified live (2026-08-01) against a real `redis-server`** (not just
  `miniredis`): built the gateway binary, ran it with
  `RATE_LIMIT_BACKEND=redis REDIS_URL=redis://127.0.0.1:6390/0`, confirmed the
  seed landed in Redis at exactly 100,000 (`GET echelon:credit:bal:acme`),
  manually set it to 2, then drove real `POST /v1/chat/completions` requests
  through the live gateway: 200 (balance → 1), 200 (balance → 0), then a real
  **402** `insufficient_credits` on the third — the Redis key, not a mock,
  backing the decision the whole way through.
- **`go.mod` note:** the Redis client + `miniredis` test dependency bumped the
  toolchain requirement from `go 1.22.0` to `go 1.24` — this is the module's
  first external dependency (previously zero). `gateway-ci.yml` and
  `gateway/README.md` were updated to match; `deploy/Dockerfile.gateway`
  already builds on `golang:1.25-alpine`, no change needed there.

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
  in the gateway handler). Credit reserve/commit/release is now wired around
  upstream usage directly in the handler (see Phase 4); extracting it into a
  use-case layer remains open.
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
- [x] **Server-side log filtering + pagination (2026-08-05).** `Store.Query`
  (`internal/telemetry`) applies the console's exact `applyFilters` predicate
  (verdict/direction/layer/apiKeyId/`q`/minRisk) newest-first with an exclusive
  `before` cursor + `limit` (default 100, max 500); an evicted/unknown cursor
  degrades to "start from newest" rather than erroring. `GET /v1/console/events`
  parses these as query params and returns the wrapped
  `{events,nextCursor,hasMore}` shape (a coordinated wire-shape change made in
  lockstep with the console client). Filtering/pagination moved off the client's
  fixed 500-event window.
- [x] **Real SSE live-tail (2026-08-05).** `Store.Subscribe` broadcasts each newly
  recorded event to console subscribers via small buffered channels with the same
  non-blocking-send discipline as the durable sink (a slow/absent subscriber drops
  frames, never adding latency to `Record`); unsubscribe deletes-then-closes under
  the store mutex the send loop holds, so a send can never race a close.
  `GET /v1/console/events/stream` serves this as `text/event-stream`. Replaces the
  console's fabricated `Math.random` live-tail.
- [x] `internal/telemetry/query_test.go` (each filter dimension in isolation +
  combined; multi-page cursor walk with no dupes/gaps; `hasMore` accurate at the
  exact boundary; evicted/unknown cursor degrades; subscriber delivery/unsubscribe/
  slow-subscriber-doesn't-block, all under `-race`) and
  `internal/gateway/console_events_test.go` (HTTP filter subsets in the new shape;
  SSE frame arrival over a real `httptest.Server` with a concurrent `Record`).
  Verified live against the built binary via `curl` (filter combos + cursor pages +
  `-N` stream).

### Console mutation API (Phase 5)

Status: **Done** (durable when Postgres is configured)

- [x] `internal/keystore` mutable API-key store (memory + Postgres). Keys are
  created/re-limited/revoked at runtime; it is the single source of truth for
  both request auth (`ports.Authenticator`) and the console keys UI, replacing
  the three separately-parsed copies of `ECHELON_API_KEYS`
  (`buildAuthenticator` + `buildConsoleKeys` + `buildCreditSeed`).
- [x] New/changed endpoints: `POST /v1/console/keys` (returns the secret once,
  seeds the new key's credit balance), `PATCH`/`DELETE /v1/console/keys/{id}`
  (revoke is a soft status flip so historical telemetry keyed on the id stays
  meaningful), and `GET`/`PATCH /v1/console/config`.
- [x] Live-mutable ingress thresholds (`Cascade.SetThresholds`/`Thresholds`,
  atomic float holders) and egress scanner toggles
  (`Pipeline.SetScannerEnabled`/`ScannerEnabled`). `PATCH /v1/console/config`
  applies them live; heuristics stays non-editable (accepted-but-ignored).
- [x] `internal/runtimeconfig` persists threshold/toggle overrides to Postgres
  (`runtime_config` single-row jsonb); applied at boot before serving so a
  change survives a restart.
- [x] Auth-enable rule change: auth turns on whenever `ECHELON_API_KEYS` **or**
  `AUDIT_DATABASE_URL` is set (Postgres implies a real deployment), enabling a
  from-zero bootstrap with an empty key store.
- [x] Credit-ledger `Seed` hook added to `RedisLedger` (mirrors `MemoryLedger.Credit`)
  so a newly created key's tenant gets a spendable balance without adding a method
  to the `ports.CreditLedger` interface.
- [x] `internal/gateway/console_mutations_test.go`: create-key secret
  authenticates a real request; revoke → 401; `PATCH /v1/console/config` lowers a
  block threshold and a previously-passing probability then blocks. Verified live
  against a real local Postgres, including a **kill/restart** proving the threshold
  and the revoked key survive the restart.
- Known limitations (unchanged by this phase): the `/v1/console/*` surface has no
  operator authentication; per-key `rateLimitRpm` is display/budget-only and is
  not yet enforced independently of the global `RATE_LIMIT_*`.

## Phase 6 — Production hardening and delivery

Status: **Partially done.** Docker/Compose, CI, observability (metrics/tracing/
audit sink), Redis-backed distributed rate-limit/credit, the mutable console
key/config API, and the streaming security-mode fix are all done (see the
addenda below and the "Console mutation API" section above). **Genuinely
still open:** Kubernetes (on hold — deployment target not yet decided),
fuzzing/benchmarks/profiling/static-analysis/dependency scans, latency SLOs
and incident runbooks, and ADRs/the engineering article.

- [x] Add Prometheus-compatible metrics, OpenTelemetry spans, and privacy-safe audit
  sinks. See "Observability addendum" below.
- [x] Add Docker image (`deploy/Dockerfile.gateway`) and Compose development
  stack (`docker-compose.yml`) for all three services.
- [ ] Add Kubernetes probes/resources and example production configuration. **On
  hold** — deployment target (Kubernetes vs. something else) not yet decided.
- [ ] Run fuzzing, `go test -race`, benchmarks, profiling, static analysis, and
  dependency/security scans. (`go test -race` itself runs in CI already; the
  rest of this bullet — fuzzing, profiling, dependency/security scanning — is
  not.)
- [ ] Establish latency SLOs, overload behavior, rollout/rollback, and incident
  runbooks.
- [ ] Publish architecture decision records and the completed engineering article.
- [x] Replace in-memory rate-limit/credit/telemetry with Redis-backed
  distributed state (`internal/ratelimit/redis.go`, `internal/credit/redis.go`,
  `RATE_LIMIT_BACKEND=redis`) and a persistent Postgres audit sink
  (`internal/telemetry/postgres.go`, `AUDIT_DATABASE_URL`) — see the
  Observability addendum and the top-level plan history for verification detail.
- [x] Add CI (GitHub Actions): `.github/workflows/gateway-ci.yml`
  (`go build`/`go vet`/`gofmt -l`/`go test -race`), `console-ci.yml`
  (`tsc --noEmit`/`vitest`/`next build`), `pipeline-ci.yml` (`py_compile` +
  the 123-test suite against lightweight deps only — flask/cryptography/
  numpy, no torch/transformers needed since the transformer adapter
  lazy-imports them and the contract tests use fixture adapters). Also fixed
  `pipeline/.github/workflows/review-submission-validation.yml`, which had
  never actually run: GitHub Actions only reads `.github/workflows` at the
  **repository root**, not per-subdirectory — moved to root with corrected
  paths. All four workflows verified locally end-to-end (2026-08-01) before
  being added: gateway build/vet/fmt/race-test clean (fixed 3 pre-existing
  `gofmt` violations in `gateway_test.go`/`anthropic.go`/`gemini.go`, no
  logic changes), console typecheck/test/build clean, pipeline 123/123 tests
  green in an isolated lightweight venv.

### Observability addendum — metrics, tracing, durable audit sink (2026-08-01)

Delivers the first Phase 6 bullet ("Prometheus-compatible metrics, OpenTelemetry
spans, and privacy-safe audit sinks"). All three additions are optional and
default to today's exact behavior; the gateway still runs with zero external deps.

- **Prometheus metrics** (`internal/observability/metrics.go`, new package).
  `GET /metrics` is exposed unauthenticated in `Routes()`
  (`internal/gateway/gateway.go`, `mux.Handle("GET /metrics", ...)`), same tier as
  `/healthz`/`/readyz`. Five bounded-cardinality families:
  `echelon_http_requests_total{route,status}` +
  `echelon_http_request_duration_seconds{route}` (recorded in `withRequestLog`
  via a `normalizeRoute` allowlist so unknown paths collapse to `other`);
  `echelon_cascade_decisions_total{direction,layer,verdict}` (one per layer,
  emitted inside `recordEvent`); `echelon_rate_limit_rejections_total` (the 429
  branch); `echelon_credit_reservations_total{outcome}` (the four Reserve/
  Insufficient/Commit/Release ledger call sites). Each `Metrics` owns a private
  `prometheus.NewRegistry()`, so the ~12 test files that build many `*Gateway`s in
  one binary never hit promauto's duplicate-registration panic. Metric methods are
  nil-safe. Tests: `internal/observability/metrics_test.go`,
  `internal/gateway/phase6_observability_test.go`.
- **OpenTelemetry tracing** (`internal/observability/tracing.go`). Configured only
  through the standard `OTEL_*` env vars; with no OTLP endpoint set, `InitTracer`
  returns `noop.NewTracerProvider()` (zero overhead, zero behavior change). Wired
  at the composition root (`cmd/server/main.go`). Spans are deliberately coarse
  and confined to `proxyLLM`: one root span per route plus child spans around the
  rate-limit check, `ingress.Evaluate`, `provider.Forward*`, and `egress.Scan` —
  no `context` threading was pushed into the ingress/egress internal packages.
  Attributes are low-cardinality only (route, direction, verdict, provider); no
  raw prompt/response content, honoring the engineering invariant above.
- **Durable audit sink** (`internal/telemetry/postgres.go`, `PostgresSink` via
  `pgxpool`). `telemetry.Store.Record` is unchanged on the hot path: it still does
  the synchronous in-memory ring append and now *additionally* performs a
  non-blocking channel hand-off to a single background drain goroutine
  (`Store.RunSink`, stopped by `main.go`'s `signal.NotifyContext`). A slow or
  unavailable Postgres can never add request latency or fail a request — a full
  buffer drops the event with a rate-limited warning. On startup the ring is
  hydrated from the most recent rows (`Recent` → `Hydrate`) so a restart doesn't
  show an empty console. Enabled only when `AUDIT_DATABASE_URL` is set (new
  optional config in `internal/config/config.go`); unset → in-memory only.
  `docker-compose.yml` gains an additive, internal-only `postgres:16-alpine`
  service (opt-in, not wired into the gateway's default env). Tests:
  `internal/telemetry/sink_test.go` (backpressure/no-block, hydrate ordering,
  fake-sink forwarding) and `postgres_test.go` (live round-trip, **skips cleanly**
  when no `AUDIT_TEST_DATABASE_URL`/reachable DB — Docker is unavailable here).
- **Cleanup:** removed the dead `ports.AuditEvent` struct and `ports.AuditSink`
  interface (`internal/ports/ports.go`) — scaffolding from an earlier design pass,
  referenced nowhere; the real audit trail is `telemetry.PromptEvent`.
- **`go.mod`:** added `github.com/prometheus/client_golang`,
  `go.opentelemetry.io/otel` (+ `sdk`, `trace`, `otlptracehttp` exporter), and
  `github.com/jackc/pgx/v5`. These transitively require Go ≥ 1.25, bumping the
  `go` directive from 1.24 → 1.25.0 (README updated to match).
- **Verification:** `go build ./...`, `go vet ./...`, `gofmt -l .` (empty), and
  `go test -race ./...` all pass locally (2026-08-01).
- **Verified live (2026-08-01) against a real `postgres` server** (not just the
  automated test suite, which skips without one): installed Postgres locally,
  built the gateway binary, ran it with `AUDIT_DATABASE_URL` set, drove 3 real
  `POST /v1/chat/completions` requests, confirmed 3 privacy-safe rows landed in
  `prompt_events` (`excerpt='[redacted]'`, real `tokens_in`/`tokens_out`/verdict),
  scraped `/metrics` and saw the exact expected counters (`echelon_http_requests_total`,
  `echelon_credit_reservations_total{outcome="reserved"|"committed"}`, per-layer
  `echelon_cascade_decisions_total`), then **killed and restarted the gateway
  process** and confirmed the log line `audit ring hydrated from postgres
  events=3` and that `GET /v1/console/events` immediately served the 3
  historical events on a cold process — the exact "console shows empty after
  restart" gap this addendum exists to close, closed and proven, not just
  unit-tested.
- **Not done / deferred honestly:** no live-Postgres path in **CI** (Docker
  unavailable in this environment — the automated `postgres_test.go` skips
  without a reachable test DB, my live verification above was manual, not
  CI-automated); OTel tracing verified only against the no-op path, not a live
  OTLP collector; metrics/spans are gateway-request-scoped only (no runtime
  `go_*`/process collectors registered, no spans inside the security cascades
  by design — see "coarse span granularity" above).

### Streaming security mode addendum — bypass fix + opt-in fast streaming (2026-08-04)

Closes the "preserve streaming with an explicit buffered-security mode" next step
below, and fixes a real egress-scan bypass found while building it.

- **Bypass found (and closed).** `proxyLLM` never inspected the request's `stream`
  field: a `stream:true` body was forwarded byte-for-byte, the upstream's raw SSE
  response was fully buffered by `readLimited`, then handed to egress. But
  `egress.ExtractAssistantText` (`internal/egress/http_response_classifier.go`)
  `json.Unmarshal`s a normal chat-completion object; raw SSE frames fail that parse
  and it returns `""` silently. The ML/judge egress classifier was therefore scored
  on an empty string for **every** streamed response — any client could bypass
  malicious-code/toxicity egress detection with `stream:true` whenever
  `EGRESS_ML_BASE_URL` was set. (PII/policy scan raw bytes, so they were unaffected.)
  The response was also mislabeled `text/event-stream` *with* a `Content-Length`.
- **Part A — safety fix (new default, always on).** `internal/gateway/streaming.go`
  adds `isStreamRequested`/`forceNonStreaming`. When a client requests streaming and
  fast mode is off, `proxyLLM` rewrites the outbound body to `stream:false` (every
  other field preserved) so the upstream returns a normal JSON completion that
  `ExtractAssistantText` always parses and egress fully scans. The scanned content is
  then delivered as a spec-correct single-chunk SSE response (`chat.completion.chunk`
  → `finish_reason:"stop"` → `[DONE]`, chunked, no `Content-Length`). Falls back to
  raw JSON when the body isn't chat-completion-shaped (keeps `/v1/responses` safe).
  `extractAssistantText` was exported to `ExtractAssistantText` so there is exactly
  one implementation of "pull assistant text out of a completion body".
- **Part B — opt-in fast mode (`STREAM_FAST_MODE`, `internal/config/config.go`).**
  When on and the client requested streaming, `proxyLLM` branches into `streamFast`
  (shares all earlier auth/ratelimit/ingress/credit-reserve setup). It reads upstream
  SSE frames incrementally, runs `Pipeline.ScanFast` (PII + policy only — the new
  `ScanFast`/`MLScanner` accessors on `internal/egress/pipeline.go` skip the sole
  network-bound `response_classifier` scanner and respect the console disabled-set),
  redacts or truncates per chunk (one-chunk lag; policy block truncates mid-stream
  since headers are already committed), and defers the full ML/judge cascade to a
  detached post-hoc goroutine that can flag+log (and increment
  `echelon_cascade_decisions_total{...,response_classifier}`) but cannot block an
  already-delivered response. `statusRecorder` gained a `Flush` method so streaming
  flushes through the request-log middleware.
- **Verification.** `go build`/`go vet`/`gofmt -l`/`go test -race ./...` all pass.
  New tests (`internal/gateway/streaming_test.go`): bypass-closed regression (asserts
  the classifier receives real non-empty text via a recording fake security service),
  buffered single-flush, fast-mode PII redaction, fast-mode policy-block truncation,
  and fast-mode deferred-ML-flag recorded in Prometheus. Verified live against a real
  gateway binary + mock SSE upstream: fast mode TTFB ≈ 2.5ms vs total ≈ 1.51s (genuine
  incremental delivery); default mode TTFB ≈ total ≈ 1.51s (buffered) with well-formed
  SSE headers and no contradictory `Content-Length`.

## Immediate next steps

Everything tracked directly against this repo's own roadmap is done except the
still-open Phase 6 bullets above (Kubernetes on hold; fuzzing/benchmarks/
SLOs/runbooks/ADRs not started). Two smaller, real architecture items remain,
neither blocking anything else:

1. Extract a transport-independent application use-case type out of the
   `proxyLLM` handler in `internal/gateway/gateway.go` — it has grown large
   across Phases 3–7 (auth, rate-limit, credit, ingress, egress, streaming all
   live in one function) and would benefit from being split into a use-case
   layer independent of `net/http`.
2. Implement token-based cost estimation for the credit ledger (replacing the
   current, deliberately-simple flat 1-credit-per-completed-request model).

Also carried as known, documented gaps rather than silently left unmentioned
(see `DEMO.md` → "Honest limitations" for the canonical list): no operator
authentication on `/v1/console/*`; per-key `rateLimitRpm` is display/budget
metadata only, not independently enforced; `STREAM_FAST_MODE`'s per-chunk PII
scanning can miss a pattern split across a chunk boundary.
