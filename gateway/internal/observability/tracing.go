package observability

import (
	"context"
	"os"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// ShutdownFunc flushes and stops a tracer provider. It is always safe to call
// (the no-op path returns a no-op ShutdownFunc), so callers can defer it
// unconditionally.
type ShutdownFunc func(context.Context) error

// InitTracer builds a TracerProvider from the standard OTel environment
// variables (OTEL_EXPORTER_OTLP_ENDPOINT / OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
// OTEL_SERVICE_NAME, OTEL_EXPORTER_OTLP_HEADERS, ...). When no OTLP endpoint is
// configured it returns a no-op provider and a no-op ShutdownFunc: zero overhead
// and zero behavior change, matching every other optional port in this codebase.
//
// The OTLP exporter reads its own configuration (endpoint, headers, TLS,
// timeouts) from the standard env vars via otlptracehttp's option defaults, so no
// gateway-specific config is introduced.
func InitTracer(ctx context.Context) (trace.TracerProvider, ShutdownFunc, error) {
	if !otlpEndpointConfigured() {
		return noop.NewTracerProvider(), func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return noop.NewTracerProvider(), func(context.Context) error { return nil }, err
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(), // honors OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES
		resource.WithAttributes(semconv.ServiceName(serviceName())),
	)
	if err != nil {
		res = resource.Default()
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	return tp, tp.Shutdown, nil
}

func otlpEndpointConfigured() bool {
	return strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) != "" ||
		strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) != ""
}

func serviceName() string {
	if v := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); v != "" {
		return v
	}
	return "echelon-gateway"
}
