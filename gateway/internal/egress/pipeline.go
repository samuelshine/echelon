// Package egress implements deterministic response security and redaction.
package egress

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/ports"
)

var _ ports.EgressScanner = (*Pipeline)(nil)

type PipelineConfig struct {
	ScannerTimeout time.Duration
	FailClosed     bool
}

type Pipeline struct {
	config   PipelineConfig
	scanners []ports.EgressScanner
	// disabled records which scanners (by Name()) are currently toggled off, so
	// the console can enable/disable a scanner at runtime without a restart. A
	// name never present here defaults to enabled.
	mu       sync.RWMutex
	disabled map[string]bool
}

func (p *Pipeline) Name() string { return "egress_pipeline" }

func NewPipeline(config PipelineConfig, scanners ...ports.EgressScanner) (*Pipeline, error) {
	for i, scanner := range scanners {
		if scanner == nil {
			return nil, fmt.Errorf("egress scanner %d is nil", i)
		}
	}
	return &Pipeline{
		config:   config,
		scanners: append([]ports.EgressScanner(nil), scanners...),
		disabled: make(map[string]bool),
	}, nil
}

// SetScannerEnabled toggles the scanner with the given Name() on or off at
// runtime. Toggling a name that no scanner in the pipeline actually has (e.g.
// "response_classifier" when no ML cascade was wired) is a harmless no-op at
// Scan time — it simply records intent that never matches a real scanner.
func (p *Pipeline) SetScannerEnabled(name string, enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if enabled {
		delete(p.disabled, name)
		return
	}
	p.disabled[name] = true
}

// ScannerEnabled reports whether the named scanner is currently active. Any name
// never explicitly disabled defaults to true.
func (p *Pipeline) ScannerEnabled(name string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return !p.disabled[name]
}

func (p *Pipeline) Scan(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	return p.scan(ctx, response, func(string) bool { return true })
}

// ScanFast runs the pipeline exactly like Scan but skips the sole network-bound,
// slow scanner ("response_classifier" — the ML/judge cascade), keeping only the
// fast/local PII ("pii") and policy ("response_policy") scanners. It backs the
// per-chunk scanning of STREAM_FAST_MODE, where the ML cascade is instead run
// post-hoc against the full accumulated response (see gateway/streaming.go). A
// console-disabled scanner stays disabled here too — the same disabled-set governs
// both Scan and ScanFast.
func (p *Pipeline) ScanFast(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	return p.scan(ctx, response, func(name string) bool { return name != "response_classifier" })
}

// MLScanner returns the pipeline's "response_classifier" scanner (the ML/judge
// cascade) when present and currently enabled, else nil. The fast-mode deferred
// goroutine uses it to run just that one scanner against the full response after
// the content has already been streamed to the client.
func (p *Pipeline) MLScanner() ports.EgressScanner {
	if !p.ScannerEnabled("response_classifier") {
		return nil
	}
	for _, scanner := range p.scanners {
		if scanner.Name() == "response_classifier" {
			return scanner
		}
	}
	return nil
}

// scan is the shared pipeline loop. include selects which scanners (by Name())
// participate, so Scan (all) and ScanFast (all but the ML cascade) share one
// findings/redact/block accumulation implementation rather than duplicating it.
func (p *Pipeline) scan(ctx context.Context, response core.ModelResponse, include func(name string) bool) (core.ModelResponse, core.Verdict, error) {
	started := time.Now()
	current := response
	action := core.ActionAllow
	var findings []core.Finding

	for _, scanner := range p.scanners {
		// A scanner excluded by the selection predicate (e.g. the ML cascade under
		// ScanFast) is skipped as if it were not in the pipeline at all.
		if !include(scanner.Name()) {
			continue
		}
		// A disabled scanner is skipped entirely — no finding, no verdict
		// contribution — as if it were not in the pipeline at all.
		if !p.ScannerEnabled(scanner.Name()) {
			continue
		}
		input := current
		input.Body = bytes.Clone(current.Body)
		stageCtx, cancel := scannerContext(ctx, p.config.ScannerTimeout)
		candidate, verdict, err := scanner.Scan(stageCtx, input)
		cancel()
		if err != nil {
			return p.scannerFailure(current, scanner.Name(), started, findings, err)
		}
		if err := validateScannerResult(current, candidate, verdict); err != nil {
			return p.scannerFailure(current, scanner.Name(), started, findings, err)
		}

		findings = append(findings, verdict.Findings...)
		switch verdict.Action {
		case core.ActionBlock:
			return current, core.Verdict{
				Action: core.ActionBlock, Findings: findings, Duration: time.Since(started),
			}, nil
		case core.ActionRedact:
			current = candidate
			action = core.ActionRedact
		case core.ActionAllow:
			// Deliberately retain current rather than the scanner's copy.
		default:
			return p.scannerFailure(current, scanner.Name(), started, findings, fmt.Errorf("unknown action %d", verdict.Action))
		}
	}

	return current, core.Verdict{Action: action, Findings: findings, Duration: time.Since(started)}, nil
}

func (p *Pipeline) scannerFailure(response core.ModelResponse, layer string, started time.Time, findings []core.Finding, err error) (core.ModelResponse, core.Verdict, error) {
	finding := core.Finding{
		Layer: layer, Code: "egress_scanner_unavailable",
		Message: "response security evaluation could not be completed",
	}
	findings = append(findings, finding)
	action := core.ActionAllow
	if p.config.FailClosed {
		action = core.ActionBlock
	}
	return response, core.Verdict{Action: action, Findings: findings, Duration: time.Since(started)}, fmt.Errorf("%s: %w", layer, err)
}

func validateScannerResult(before, after core.ModelResponse, verdict core.Verdict) error {
	if before.RequestID != after.RequestID || before.TenantID != after.TenantID ||
		before.Route != after.Route || before.Model != after.Model || before.Usage != after.Usage {
		return fmt.Errorf("scanner modified immutable response metadata")
	}
	changed := !bytes.Equal(before.Body, after.Body)
	if verdict.Action == core.ActionRedact && !changed {
		return fmt.Errorf("redact verdict did not replace the response body")
	}
	if verdict.Action != core.ActionRedact && changed {
		return fmt.Errorf("scanner modified response body without a redact verdict")
	}
	return nil
}

func scannerContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}
