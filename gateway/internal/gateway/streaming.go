package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/egress"
)

// isStreamRequested reports whether a request body opts into streaming via a
// top-level "stream": true. It is deliberately tolerant: an absent field, a
// non-boolean value, or an unparseable body all yield false (the safe default).
func isStreamRequested(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var payload struct {
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return payload.Stream != nil && *payload.Stream
}

// forceNonStreaming rewrites an outbound request body to set "stream": false while
// preserving every other field byte-for-byte. Returns (rewritten, true) on
// success, or (nil, false) if the body is not parseable JSON (the caller then
// forwards the original body unchanged rather than erroring the request).
func forceNonStreaming(body []byte) ([]byte, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, false
	}
	fields["stream"] = json.RawMessage("false")
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, false
	}
	return out, true
}

// --- SSE framing --------------------------------------------------------------

// sseChunk is a minimal OpenAI chat.completion.chunk. Content/Role are omitempty
// so a terminal chunk marshals delta as {} rather than {"content":""}.
type sseChunk struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Created int64       `json:"created"`
	Model   string      `json:"model,omitempty"`
	Choices []sseChoice `json:"choices"`
}

type sseChoice struct {
	Index        int      `json:"index"`
	Delta        sseDelta `json:"delta"`
	FinishReason *string  `json:"finish_reason"`
}

type sseDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

func setSSEHeaders(h http.Header) {
	// No Content-Length: chunked transfer is what makes this real SSE rather than a
	// fixed-length blob mislabeled as an event stream.
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
}

// sseFrame encodes one chunk as a `data: <json>\n\n` SSE frame.
func sseFrame(chunk sseChunk) []byte {
	encoded, _ := json.Marshal(chunk)
	out := make([]byte, 0, len(encoded)+8)
	out = append(out, "data: "...)
	out = append(out, encoded...)
	out = append(out, '\n', '\n')
	return out
}

func contentChunk(id, model string, created int64, content string) sseChunk {
	return sseChunk{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
		Choices: []sseChoice{{Index: 0, Delta: sseDelta{Content: content}}},
	}
}

func stopChunk(id, model string, created int64) sseChunk {
	stop := "stop"
	return sseChunk{
		ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
		Choices: []sseChoice{{Index: 0, Delta: sseDelta{}, FinishReason: &stop}},
	}
}

const sseDone = "data: [DONE]\n\n"

// writeSyntheticSSE (Part A) delivers an already-scanned, fully-buffered response
// as a spec-correct single content chunk + terminal stop chunk + [DONE]. Returns
// false without writing anything when the body is not chat-completion shaped (so
// the caller falls back to a raw application/json write) — this keeps /v1/responses
// and any non-standard body shape safe rather than emitting malformed SSE.
func (g *Gateway) writeSyntheticSSE(w http.ResponseWriter, respBody []byte, model string) bool {
	content := strings.TrimRight(egress.ExtractAssistantText(respBody), "\n")
	if content == "" {
		return false
	}
	id := "chatcmpl-" + newRequestID()
	created := time.Now().Unix()

	setSSEHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	_, _ = w.Write(sseFrame(contentChunk(id, model, created, content)))
	_, _ = w.Write(sseFrame(stopChunk(id, model, created)))
	_, _ = io.WriteString(w, sseDone)
	if flusher != nil {
		flusher.Flush()
	}
	return true
}

// --- Fast streaming path (Part B) --------------------------------------------

type fastStreamParams struct {
	resp         *http.Response
	identity     core.Identity
	model        string
	upstreamPath string
	providerName string
	requestID    string
	start        time.Time
	creditRes    core.CreditReservation
	creditHeld   bool
}

// streamFast reads the upstream SSE response incrementally and forwards it to the
// client with a one-chunk-granularity security lag: PII redaction and policy
// blocking are enforced per chunk as content flows, while the ML/judge cascade is
// necessarily deferred to a post-hoc background scan (it can flag/log an
// already-delivered response but cannot block it — the documented fast-mode
// tradeoff). The whole response is never buffered before writing — that is the
// exact bug this path avoids.
func (g *Gateway) streamFast(w http.ResponseWriter, r *http.Request, p fastStreamParams) {
	setSSEHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}

	// The ML cascade ("response_classifier") is deliberately excluded from per-chunk
	// scanning (ScanFast); it runs once, post-hoc, against the full text below.
	pipeline, hasPipeline := g.egress.(*egress.Pipeline)

	created := time.Now().Unix()
	var accumulated strings.Builder
	var findings []core.Finding
	redacted := false

	committed := false
	commit := func() {
		// The upstream produced a response and we streamed (some of) it, so the
		// tenant is charged — identical semantics to the buffered path, which also
		// commits regardless of the egress decision. Guarded so block and normal-end
		// exits never double-commit or leak the reservation.
		if p.creditHeld && !committed && g.creditLedger != nil {
			_ = g.creditLedger.Commit(r.Context(), p.creditRes, 1)
			g.metrics.CreditReservation("committed")
			committed = true
		}
	}

	reader := bufio.NewReader(p.resp.Body)
	for {
		frame, err := readSSEEvent(reader)
		if len(bytes.TrimSpace(frame)) > 0 {
			data := sseData(frame)
			switch {
			case data == nil:
				// Not a data: line (comment/keep-alive/blank) — forward verbatim.
				_, _ = w.Write(frame)
				flush()
			case bytes.Equal(data, []byte("[DONE]")):
				// Terminal sentinel: forward verbatim and finish normally.
				_, _ = w.Write([]byte(sseDone))
				flush()
				g.finishFastStream(w, r, p, &accumulated, findings, redacted, commit, pipeline)
				return
			default:
				delta := extractDeltaContent(data)
				accumulated.WriteString(delta)

				action, redactedBody, verdict := g.fastChunkVerdict(r.Context(), p, delta, hasPipeline, pipeline)
				findings = append(findings, verdict.Findings...)

				switch action {
				case core.ActionBlock:
					// A genuine block, one-chunk-granularity delayed rather than
					// zero-delay: headers are already committed, so we cannot change
					// the HTTP status — we truncate the stream instead. This is a real
					// (if narrow) weakening relative to the buffered path.
					id := sseChunkID(data)
					notice := "\n[response truncated by Echelon: policy violation]"
					_, _ = w.Write(sseFrame(contentChunk(id, p.model, created, notice)))
					_, _ = w.Write(sseFrame(stopChunk(id, p.model, created)))
					_, _ = io.WriteString(w, sseDone)
					flush()
					commit()
					// Record as blocked, same as the buffered path does for a block.
					// Do NOT proceed to the deferred ML scan — there is nothing more
					// to protect against once forwarding has stopped.
					g.recordEvent(p.identity, core.Verdict{Action: core.ActionBlock, Findings: verdict.Findings}, p.start, []byte(accumulated.String()), p.providerName, "egress")
					return
				case core.ActionRedact:
					id := sseChunkID(data)
					_, _ = w.Write(sseFrame(contentChunk(id, p.model, created, string(redactedBody))))
					redacted = true
					flush()
				default:
					_, _ = w.Write(frame)
					flush()
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				// Upstream closed uncleanly mid-stream. Response headers are already
				// committed, so we cannot signal an error status — close out cleanly.
				g.logger.Warn("upstream stream ended uncleanly", "route", p.upstreamPath, "request_id", p.requestID, "error", err)
			}
			g.finishFastStream(w, r, p, &accumulated, findings, redacted, commit, pipeline)
			return
		}
	}
}

// finishFastStream runs the normal end-of-stream bookkeeping (step 5): commit
// credit, emit one telemetry event synchronously, and launch the detached
// post-hoc ML scan. Safe to call once per request; commit is idempotent.
func (g *Gateway) finishFastStream(w http.ResponseWriter, r *http.Request, p fastStreamParams, accumulated *strings.Builder, findings []core.Finding, redacted bool, commit func(), pipeline *egress.Pipeline) {
	commit()

	// FinalVerdict reflects only what is known synchronously here: pass, unless a
	// fast-scanner redaction already happened. We deliberately do NOT block emitting
	// this event on the deferred ML scan below — that would defeat the entire point
	// of fast mode (the content has already been delivered to the client).
	verdict := core.Allow()
	if redacted {
		verdict = core.Verdict{Action: core.ActionRedact, Findings: findings}
	}
	g.recordEvent(p.identity, verdict, p.start, []byte(accumulated.String()), p.providerName, "egress")

	if !g.egressMLEnabled || pipeline == nil {
		return
	}
	ml := pipeline.MLScanner()
	if ml == nil {
		return
	}

	// Fire-and-forget post-hoc ML/judge scan of the full accumulated text. The
	// string is copied into the goroutine's argument here (evaluated before `go`),
	// so nothing the request handler still touches is shared — race-safe. The
	// request's own r.Context() will already be canceled by the time this runs, so
	// the goroutine uses a fresh detached context with its own budget.
	fullText := accumulated.String()
	requestID, tenantID, model, route := p.requestID, p.identity.TenantID, p.model, p.upstreamPath
	timeout := g.cfg.Pipeline.MLTimeout + g.cfg.Pipeline.JudgeTimeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_, verdict, err := ml.Scan(ctx, core.ModelResponse{
			RequestID: requestID, TenantID: tenantID, Route: route, Model: model, Body: []byte(fullText),
		})
		if err != nil {
			// Never log raw prompt/response content — only identifiers, matching the
			// codebase's privacy constraint.
			g.logger.Warn("post-hoc egress scan errored", "request_id", requestID, "tenant_id", tenantID, "error", err)
			return
		}
		switch verdict.Action {
		case core.ActionBlock:
			g.logger.Warn("post-hoc egress scan flagged an already-streamed response", "request_id", requestID, "tenant_id", tenantID)
			g.metrics.CascadeDecision("egress", "response_classifier", "block")
		case core.ActionRedact:
			g.logger.Warn("post-hoc egress scan flagged an already-streamed response", "request_id", requestID, "tenant_id", tenantID)
			g.metrics.CascadeDecision("egress", "response_classifier", "flag")
		}
	}()
}

// fastChunkVerdict runs the fast-only egress scanners (PII + policy, never the ML
// cascade) against a single delta fragment. Returns the action, the redacted body
// (for ActionRedact), and the verdict (for its findings).
//
// NOTE: scanning is per-chunk, so a pattern (e.g. a credit card) split across two
// chunk boundaries is a known, accepted limitation of chunk-granularity scanning —
// cross-chunk pattern matching is deliberately out of scope here.
func (g *Gateway) fastChunkVerdict(ctx context.Context, p fastStreamParams, delta string, hasPipeline bool, pipeline *egress.Pipeline) (core.Action, []byte, core.Verdict) {
	if !hasPipeline || delta == "" {
		return core.ActionAllow, nil, core.Allow()
	}
	scanned, verdict, err := pipeline.ScanFast(ctx, core.ModelResponse{
		RequestID: p.requestID, TenantID: p.identity.TenantID, Route: p.upstreamPath,
		Model: p.model, Body: []byte(delta),
	})
	if err != nil {
		if g.cfg.Pipeline.FailClosed {
			return core.ActionBlock, nil, verdict
		}
		g.logger.Warn("fast egress scan errored; forwarding unscanned chunk", "route", p.upstreamPath, "request_id", p.requestID, "error", err)
		return core.ActionAllow, nil, core.Allow()
	}
	switch verdict.Action {
	case core.ActionBlock:
		return core.ActionBlock, nil, verdict
	case core.ActionRedact:
		return core.ActionRedact, scanned.Body, verdict
	default:
		return core.ActionAllow, nil, verdict
	}
}

// --- SSE parsing helpers ------------------------------------------------------

// readSSEEvent reads one SSE event — everything up to and including the blank line
// that terminates it — without buffering the whole body. It returns the raw event
// bytes (possibly with a trailing io.EOF if the stream ended without a final blank
// line).
func readSSEEvent(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		line, err := r.ReadBytes('\n')
		buf = append(buf, line...)
		if err != nil {
			return buf, err
		}
		// A blank line ("\n" or "\r\n") terminates the event.
		if line[0] == '\n' || (len(line) >= 2 && line[0] == '\r' && line[1] == '\n') {
			return buf, nil
		}
	}
}

// sseData returns the JSON payload of an event's `data:` line (trimmed), or nil
// when the event carries no data line.
func sseData(frame []byte) []byte {
	for _, line := range bytes.Split(frame, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("data:")) {
			return bytes.TrimSpace(line[len("data:"):])
		}
	}
	return nil
}

// extractDeltaContent pulls the incremental text from a streaming chunk
// (choices[].delta.content), which is a different shape than a full completion's
// choices[].message.content. Tolerant of a missing/differently-shaped delta.
func extractDeltaContent(frame []byte) string {
	var payload struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(frame, &payload); err != nil {
		return ""
	}
	var b strings.Builder
	for _, choice := range payload.Choices {
		b.WriteString(choice.Delta.Content)
	}
	return b.String()
}

// sseChunkID extracts the "id" from a chunk's JSON so a rewritten (redacted or
// truncation) chunk can reuse it. Falls back to a generated id when absent.
func sseChunkID(data []byte) string {
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &payload); err == nil && payload.ID != "" {
		return payload.ID
	}
	return "chatcmpl-" + newRequestID()
}
