// Package egress implements deterministic response security and redaction.
package egress

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/ports"
)

type PipelineConfig struct {
	ScannerTimeout time.Duration
	FailClosed     bool
}

type Pipeline struct {
	config   PipelineConfig
	scanners []ports.EgressScanner
}

func (p *Pipeline) Name() string { return "egress_pipeline" }

func NewPipeline(config PipelineConfig, scanners ...ports.EgressScanner) (*Pipeline, error) {
	for i, scanner := range scanners {
		if scanner == nil {
			return nil, fmt.Errorf("egress scanner %d is nil", i)
		}
	}
	return &Pipeline{config: config, scanners: append([]ports.EgressScanner(nil), scanners...)}, nil
}

func (p *Pipeline) Scan(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	started := time.Now()
	current := response
	action := core.ActionAllow
	var findings []core.Finding

	for _, scanner := range p.scanners {
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
