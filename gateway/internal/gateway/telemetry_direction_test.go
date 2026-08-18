package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jscyril/echelon/internal/config"
	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/gateway"
	"github.com/jscyril/echelon/internal/keystore"
	"github.com/jscyril/echelon/internal/telemetry"
)

// allowIngress always allows, satisfying ports.IngressLayer. Named so a failure
// message identifies which fake is at fault.
type allowIngress struct{}

func (allowIngress) Name() string { return "allow_ingress" }
func (allowIngress) Evaluate(context.Context, core.Prompt) (core.Verdict, error) {
	return core.Allow(), nil
}

// allowEgress always allows, satisfying ports.EgressScanner.
type allowEgress struct{}

func (allowEgress) Name() string { return "allow_egress" }
func (allowEgress) Scan(_ context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	return response, core.Allow(), nil
}

// TestAllowedRequestRecordsBothDirections is the regression test for the
// finding that an ALLOWED request's ingress scan was never recorded at all: the
// only ingress-direction telemetry event ever emitted was on an ingress BLOCK,
// and the one event a passing request did produce had its `direction` field
// overwritten to "egress" the moment an egress pipeline was configured. The
// console's Logs page and per-event drill-down therefore only ever showed
// egress detail for real, non-blocked traffic -- ingress had genuinely run
// (the classifier and judge were both called) but left no visible trace.
func TestAllowedRequestRecordsBothDirections(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"cmpl-1","choices":[{"message":{"content":"hi"}}]}`))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	telemetryStore := telemetry.NewStore(64)
	ks := keystore.NewMemoryStore(nil)
	handler := gateway.New(gateway.Options{
		Config:         config.Config{UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20},
		KeyStore:       ks,
		Ingress:        allowIngress{},
		Egress:         allowEgress{},
		Telemetry:      telemetryStore,
		UpstreamRouter: testRouter(upstream.URL, "", http.DefaultTransport),
	}).Routes()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("request: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	summary := telemetryStore.Summary(1_000_000)

	// One real API call must still count as exactly one call, not two, even
	// though it now produces two telemetry rows (ingress-pass + final egress).
	if got := summary["totalCalls"]; got != 1 {
		t.Errorf("totalCalls = %v, want 1 (an allowed request must not double-count "+
			"just because it now emits an ingress-pass event in addition to the final one)", got)
	}
	if got := summary["blockedPct"]; got != 0.0 {
		t.Errorf("blockedPct = %v, want 0", got)
	}

	events := telemetryStore.Events(10)
	var sawIngress, sawEgress bool
	for _, e := range events {
		if e.Direction == "ingress" {
			sawIngress = true
			if e.FinalVerdict != "pass" {
				t.Errorf("ingress event verdict = %q, want pass", e.FinalVerdict)
			}
		}
		if e.Direction == "egress" {
			sawEgress = true
		}
	}
	if !sawIngress {
		t.Error("no ingress-direction event was recorded for an allowed request " +
			"-- this is the exact bug: ingress ran (classifier+judge were called) but " +
			"left no visible record once an egress pipeline was configured")
	}
	if !sawEgress {
		t.Error("no egress-direction event was recorded")
	}
	if len(events) != 2 {
		t.Errorf("got %d events for one API call, want exactly 2 (ingress-pass + final)", len(events))
	}
}

// TestExcerptsRedactedByDefault pins the privacy property the console depends
// on: telemetry carries verdicts, not content, so operating the dashboard never
// grants access to user prompts. The dev flag that trades this away must be
// opt-in and must never be inferred from any other setting.
func TestExcerptsRedactedByDefault(t *testing.T) {
	for _, tc := range []struct {
		name        string
		show        bool
		wantExcerpt string
	}{
		{name: "default_redacts", show: false, wantExcerpt: "[redacted]"},
		{name: "opt_in_reveals", show: true, wantExcerpt: "tell me about the leave policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"id":"c","choices":[{"message":{"content":"ok"}}]}`))
			}))
			defer upstream.Close()
			upstreamURL, _ := url.Parse(upstream.URL)

			store := telemetry.NewStore(16)
			handler := gateway.New(gateway.Options{
				Config: config.Config{
					UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20,
					ShowExcerpts: tc.show,
				},
				KeyStore:       keystore.NewMemoryStore(nil),
				Ingress:        allowIngress{},
				Telemetry:      store,
				UpstreamRouter: testRouter(upstream.URL, "", http.DefaultTransport),
			}).Routes()

			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
				strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"tell me about the leave policy"}]}`))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			events := store.Events(10)
			if len(events) == 0 {
				t.Fatal("no telemetry recorded")
			}
			var ingress *telemetry.PromptEvent
			for i := range events {
				if events[i].Direction == "ingress" {
					ingress = &events[i]
				}
			}
			if ingress == nil {
				t.Fatal("no ingress event recorded")
			}
			if !strings.Contains(ingress.Excerpt, tc.wantExcerpt) {
				t.Errorf("excerpt = %q, want it to contain %q", ingress.Excerpt, tc.wantExcerpt)
			}
			if !tc.show && strings.Contains(ingress.Excerpt, "leave policy") {
				t.Errorf("prompt text leaked into telemetry with the flag off: %q", ingress.Excerpt)
			}
		})
	}
}

// TestEgressExcerptShowsTheAnswerNotTheEnvelope: an operator reading the audit
// log needs the answer that was judged, not the provider's JSON wrapper.
func TestEgressExcerptShowsTheAnswerNotTheEnvelope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"cmpl-1","choices":[{"message":{"role":"assistant","content":"Your order ships Tuesday."}}]}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	store := telemetry.NewStore(16)
	handler := gateway.New(gateway.Options{
		Config: config.Config{
			UpstreamBaseURL: upstreamURL, MaxRequestBytes: 1 << 20, ShowExcerpts: true,
		},
		KeyStore:       keystore.NewMemoryStore(nil),
		Ingress:        allowIngress{},
		Egress:         allowEgress{},
		Telemetry:      store,
		UpstreamRouter: testRouter(upstream.URL, "", http.DefaultTransport),
	}).Routes()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"when does my order ship"}]}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	var egressEvent *telemetry.PromptEvent
	events := store.Events(10)
	for i := range events {
		if events[i].Direction == "egress" {
			egressEvent = &events[i]
		}
	}
	if egressEvent == nil {
		t.Fatal("no egress event recorded")
	}
	if !strings.Contains(egressEvent.Excerpt, "Your order ships Tuesday.") {
		t.Errorf("excerpt = %q, want the assistant's answer", egressEvent.Excerpt)
	}
	if strings.Contains(egressEvent.Excerpt, `"choices"`) {
		t.Errorf("excerpt still contains the provider envelope: %q", egressEvent.Excerpt)
	}
}
