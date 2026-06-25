package guard

import (
	"context"
	"regexp"
	"strings"
)

type TokenLimitFilter struct {
	maxBytes int64
}

func NewTokenLimitFilter(maxBytes int64) TokenLimitFilter {
	return TokenLimitFilter{maxBytes: maxBytes}
}

func (f TokenLimitFilter) Name() string {
	return "token_limit"
}

func (f TokenLimitFilter) Check(_ context.Context, req PromptRequest) Decision {
	if int64(len(req.Body)) > f.maxBytes {
		return Block("request_too_large", "request exceeds configured size limit")
	}
	return Allow()
}

type PIIFilter struct {
	patterns []namedPattern
}

func NewPIIFilter() PIIFilter {
	return PIIFilter{patterns: []namedPattern{
		{name: "credit_card", pattern: regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)},
		{name: "ssn", pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
		{name: "api_key", pattern: regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}`)},
	}}
}

func (f PIIFilter) Name() string {
	return "pii_heuristics"
}

func (f PIIFilter) Check(_ context.Context, req PromptRequest) Decision {
	for _, item := range f.patterns {
		if item.pattern.MatchString(req.Text) {
			return Block("sensitive_data_detected", "request contains possible "+item.name)
		}
	}
	return Allow()
}

type InjectionFilter struct {
	patterns []namedPattern
}

func NewInjectionFilter() InjectionFilter {
	return InjectionFilter{patterns: []namedPattern{
		{name: "instruction_override", pattern: regexp.MustCompile(`(?i)\b(ignore|forget|disregard)\b.{0,80}\b(previous|prior|above|system|developer)\b.{0,80}\b(instruction|prompt|message|rule)s?\b`)},
		{name: "system_prompt_exfiltration", pattern: regexp.MustCompile(`(?i)\b(reveal|print|show|dump|repeat|exfiltrate)\b.{0,80}\b(system|developer)\b.{0,80}\b(prompt|message|instruction)s?\b`)},
		{name: "jailbreak_persona", pattern: regexp.MustCompile(`(?i)\b(DAN|do anything now|developer mode|jailbreak)\b`)},
	}}
}

func (f InjectionFilter) Name() string {
	return "injection_heuristics"
}

func (f InjectionFilter) Check(_ context.Context, req PromptRequest) Decision {
	text := strings.TrimSpace(req.Text)
	if text == "" {
		return Allow()
	}

	for _, item := range f.patterns {
		if item.pattern.MatchString(text) {
			return Block("prompt_injection_detected", "request matched "+item.name+" rule")
		}
	}
	return Allow()
}

type CanaryOutputScanner struct {
	canary string
}

func NewOutputScanner(canary string) CanaryOutputScanner {
	return CanaryOutputScanner{canary: canary}
}

func (s CanaryOutputScanner) Name() string {
	return "canary_output_scanner"
}

func (s CanaryOutputScanner) Scan(_ context.Context, resp OutputResponse) Decision {
	if s.canary == "" {
		return Allow()
	}
	if strings.Contains(string(resp.Body), s.canary) {
		return Block("system_prompt_leakage", "upstream response contained the configured system canary")
	}
	return Allow()
}

type namedPattern struct {
	name    string
	pattern *regexp.Regexp
}
