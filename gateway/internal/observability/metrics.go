// Package observability holds the gateway's Prometheus metrics and OpenTelemetry
// tracing wiring. Both are optional and privacy-safe: metrics carry only
// low-cardinality enum labels (route/status/direction/layer/verdict/outcome) and
// never raw tenant IDs, API keys, request IDs, or prompt/response content; traces
// carry only the same small set of low-cardinality attributes.
package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is a self-contained bundle of the gateway's Prometheus collectors plus
// the registry they are registered against. Each Metrics owns its own
// *prometheus.Registry, so constructing many of them in the same process (as the
// gateway test suite does, one per *Gateway) never triggers promauto's
// duplicate-registration panic against the global default registry.
type Metrics struct {
	reg *prometheus.Registry

	httpRequests        *prometheus.CounterVec
	httpDuration        *prometheus.HistogramVec
	cascadeDecisions    *prometheus.CounterVec
	rateLimitRejections prometheus.Counter
	creditReservations  *prometheus.CounterVec
}

// NewMetrics builds a Metrics against a fresh private registry.
func NewMetrics() *Metrics {
	return NewMetricsWithRegistry(prometheus.NewRegistry())
}

// NewMetricsWithRegistry builds a Metrics against the supplied registry. Exposed
// for tests that want to scrape a known registry via testutil.
func NewMetricsWithRegistry(reg *prometheus.Registry) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		reg: reg,
		httpRequests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "echelon_http_requests_total",
			Help: "Total HTTP requests handled, by normalized route and status code.",
		}, []string{"route", "status"}),
		httpDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "echelon_http_request_duration_seconds",
			Help:    "HTTP request handling duration in seconds, by normalized route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"}),
		cascadeDecisions: f.NewCounterVec(prometheus.CounterOpts{
			Name: "echelon_cascade_decisions_total",
			Help: "Security cascade decisions, by direction, layer, and verdict.",
		}, []string{"direction", "layer", "verdict"}),
		rateLimitRejections: f.NewCounter(prometheus.CounterOpts{
			Name: "echelon_rate_limit_rejections_total",
			Help: "Total requests rejected by the rate limiter (HTTP 429).",
		}),
		creditReservations: f.NewCounterVec(prometheus.CounterOpts{
			Name: "echelon_credit_reservations_total",
			Help: "Credit-ledger operations, by outcome.",
		}, []string{"outcome"}),
	}
}

// Handler serves the Prometheus exposition format for this Metrics' registry.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return promhttp.Handler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Registry exposes the underlying registry (for tests).
func (m *Metrics) Registry() *prometheus.Registry {
	if m == nil {
		return nil
	}
	return m.reg
}

// All observe/increment methods are nil-safe so call sites need no guards.

// ObserveHTTP records one request's count and duration under a normalized route.
func (m *Metrics) ObserveHTTP(route, status string, d time.Duration) {
	if m == nil {
		return
	}
	m.httpRequests.WithLabelValues(route, status).Inc()
	m.httpDuration.WithLabelValues(route).Observe(d.Seconds())
}

// CascadeDecision records a single per-layer cascade ruling.
func (m *Metrics) CascadeDecision(direction, layer, verdict string) {
	if m == nil {
		return
	}
	m.cascadeDecisions.WithLabelValues(direction, layer, verdict).Inc()
}

// RateLimitRejection records one rate-limit 429.
func (m *Metrics) RateLimitRejection() {
	if m == nil {
		return
	}
	m.rateLimitRejections.Inc()
}

// CreditReservation records one credit-ledger operation outcome
// (reserved|insufficient|committed|released).
func (m *Metrics) CreditReservation(outcome string) {
	if m == nil {
		return
	}
	m.creditReservations.WithLabelValues(outcome).Inc()
}
