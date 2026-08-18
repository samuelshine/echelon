package egress

import (
	"bytes"
	"context"
	"regexp"

	"github.com/jscyril/echelon/internal/core"
)

type PIIMode uint8

const (
	PIIBlock PIIMode = iota + 1
	PIIMask
)

type piiPattern struct {
	code        string
	expression  *regexp.Regexp
	replacement []byte
	validate    func([]byte) bool
}

type PIIScanner struct {
	mode     PIIMode
	patterns []piiPattern
}

func NewPIIScanner(mode PIIMode) *PIIScanner {
	return &PIIScanner{mode: mode, patterns: []piiPattern{
		{code: "email", expression: regexp.MustCompile(`[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`), replacement: []byte(`[REDACTED_EMAIL]`)},
		{code: "ssn", expression: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), replacement: []byte(`[REDACTED_SSN]`)},
		{code: "payment_card", expression: regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), replacement: []byte(`[REDACTED_CARD]`), validate: validLuhn},
		{code: "secret", expression: regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}`), replacement: []byte(`[REDACTED_SECRET]`)},
	}}
}

func (s *PIIScanner) Name() string { return "pii" }

func (s *PIIScanner) Scan(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	output := response
	var findings []core.Finding
	for _, pattern := range s.patterns {
		if err := ctx.Err(); err != nil {
			return response, core.Verdict{}, err
		}
		matches := pattern.expression.FindAllIndex(output.Body, -1)
		matched := false
		for _, location := range matches {
			if pattern.validate == nil || pattern.validate(output.Body[location[0]:location[1]]) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		action := core.ActionRedact
		if s.mode == PIIBlock {
			action = core.ActionBlock
		}
		findings = append(findings, core.Finding{
			Layer: s.Name(), Code: pattern.code, Action: action,
			Message: "response contained sensitive data", Confidence: 1,
		})
		if s.mode == PIIBlock {
			return response, core.Block(findings...), nil
		}
		output.Body = pattern.expression.ReplaceAllFunc(output.Body, func(candidate []byte) []byte {
			if pattern.validate != nil && !pattern.validate(candidate) {
				return candidate
			}
			return pattern.replacement
		})
	}
	if len(findings) == 0 {
		return response, core.Allow(), nil
	}
	return output, core.Verdict{Action: core.ActionRedact, Findings: findings}, nil
}

func validLuhn(candidate []byte) bool {
	digits := bytes.Map(func(char rune) rune {
		if char >= '0' && char <= '9' {
			return char
		}
		return -1
	}, candidate)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	parity := len(digits) % 2
	for i, char := range digits {
		value := int(char - '0')
		if i%2 == parity {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
	}
	return sum%10 == 0
}
