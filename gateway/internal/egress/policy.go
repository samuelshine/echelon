package egress

import (
	"bytes"
	"context"

	"github.com/jscyril/echelon/internal/core"
)

type PolicyScanner struct {
	canary  []byte
	blocked [][]byte
}

func NewPolicyScanner(canary string, blockedTerms ...string) *PolicyScanner {
	terms := make([][]byte, 0, len(blockedTerms))
	for _, term := range blockedTerms {
		if term != "" {
			terms = append(terms, []byte(term))
		}
	}
	return &PolicyScanner{canary: []byte(canary), blocked: terms}
}

func (s *PolicyScanner) Name() string { return "response_policy" }

func (s *PolicyScanner) Scan(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	if err := ctx.Err(); err != nil {
		return response, core.Verdict{}, err
	}
	if len(s.canary) > 0 && bytes.Contains(response.Body, s.canary) {
		return response, core.Block(core.Finding{
			Layer: s.Name(), Code: "system_prompt_leakage",
			Message: "response contained the configured system canary", Confidence: 1,
		}), nil
	}
	for _, term := range s.blocked {
		if bytes.Contains(response.Body, term) {
			return response, core.Block(core.Finding{
				Layer: s.Name(), Code: "blocked_output_structure",
				Message: "response matched a blocked policy structure", Confidence: 1,
			}), nil
		}
	}
	return response, core.Allow(), nil
}
