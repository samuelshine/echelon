package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsIncrementsWithLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)

	m.ObserveHTTP("/v1/chat/completions", "200", 12*time.Millisecond)
	m.ObserveHTTP("/v1/chat/completions", "200", 8*time.Millisecond)
	m.ObserveHTTP("/v1/models", "403", 3*time.Millisecond)
	m.CascadeDecision("ingress", "heuristics", "block")
	m.CascadeDecision("egress", "pii", "flag")
	m.RateLimitRejection()
	m.RateLimitRejection()
	m.CreditReservation("reserved")
	m.CreditReservation("committed")

	if got := testutil.ToFloat64(m.httpRequests.WithLabelValues("/v1/chat/completions", "200")); got != 2 {
		t.Fatalf("http_requests_total{/v1/chat/completions,200} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.httpRequests.WithLabelValues("/v1/models", "403")); got != 1 {
		t.Fatalf("http_requests_total{/v1/models,403} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.cascadeDecisions.WithLabelValues("ingress", "heuristics", "block")); got != 1 {
		t.Fatalf("cascade_decisions{ingress,heuristics,block} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.cascadeDecisions.WithLabelValues("egress", "pii", "flag")); got != 1 {
		t.Fatalf("cascade_decisions{egress,pii,flag} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.rateLimitRejections); got != 2 {
		t.Fatalf("rate_limit_rejections_total = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.creditReservations.WithLabelValues("reserved")); got != 1 {
		t.Fatalf("credit_reservations_total{reserved} = %v, want 1", got)
	}
}

func TestMetricsScrapeExposesSeries(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)
	m.ObserveHTTP("/healthz", "200", time.Millisecond)
	m.CascadeDecision("ingress", "llm_judge", "pass")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"echelon_http_requests_total",
		"echelon_http_request_duration_seconds",
		"echelon_cascade_decisions_total",
		`direction="ingress"`,
		`layer="llm_judge"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("scrape output missing %q\n%s", want, body)
		}
	}
}

func TestNilMetricsAreSafe(t *testing.T) {
	var m *Metrics
	// None of these should panic on a nil receiver.
	m.ObserveHTTP("/x", "200", time.Millisecond)
	m.CascadeDecision("ingress", "heuristics", "pass")
	m.RateLimitRejection()
	m.CreditReservation("released")
	if m.Handler() == nil {
		t.Fatal("nil Metrics.Handler() returned nil")
	}
}
