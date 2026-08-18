// Package core contains Echelon's provider-neutral domain model. It deliberately
// has no transport or infrastructure dependencies.
package core

import "time"

// Direction identifies which side of the model invocation is being evaluated.
type Direction uint8

const (
	DirectionIngress Direction = iota + 1
	DirectionEgress
)

// Action is the terminal policy action produced by a security pipeline.
type Action uint8

const (
	ActionAllow Action = iota + 1
	ActionBlock
	ActionRedact
	// ActionEscalate is an INTERNAL, non-terminal action: a layer reporting
	// "I found something, but I cannot judge intent from it alone". Only the
	// ingress cascade consumes it, by routing to the LLM judge with the
	// escalating layer's findings attached as evidence. It must never reach the
	// gateway's response path -- Cascade.Evaluate always resolves it into
	// Allow/Block before returning, and the gateway additionally treats any
	// non-Allow action as a block so a future leak fails closed, not open.
	ActionEscalate
)

// Finding is evidence produced by one plugin. Evidence must be safe to log and
// must never contain raw prompt or response content.
type Finding struct {
	Layer      string            `json:"layer"`
	Code       string            `json:"code"`
	Message    string            `json:"message,omitempty"`
	Confidence float64           `json:"confidence,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Verdict is the aggregate security decision for one direction.
type Verdict struct {
	Action   Action        `json:"action"`
	Findings []Finding     `json:"findings,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

// Classification is the calibrated result returned by a semantic prompt model.
// MaliciousProbability must be in the closed interval [0, 1].
type Classification struct {
	MaliciousProbability float64            `json:"malicious_probability"`
	Labels               map[string]float64 `json:"labels,omitempty"`
}

func Allow() Verdict { return Verdict{Action: ActionAllow} }

func Block(findings ...Finding) Verdict {
	return Verdict{Action: ActionBlock, Findings: findings}
}

// Escalate marks evidence that needs adjudication rather than a decision. See
// ActionEscalate: non-terminal, resolved by the cascade before it returns.
func Escalate(findings ...Finding) Verdict {
	return Verdict{Action: ActionEscalate, Findings: findings}
}

// Prompt is the canonical input passed through ingress plugins.
type Prompt struct {
	RequestID string
	TenantID  string
	APIKeyID  string
	Route     string
	Model     string
	Text      string
	Body      []byte
}

// ModelResponse is the canonical output passed through egress plugins. Scanners
// may return a replacement Body when their policy action is ActionRedact.
type ModelResponse struct {
	RequestID string
	TenantID  string
	Route     string
	Model     string
	Body      []byte
	Usage     Usage
}

type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

func (u Usage) TotalTokens() int64 { return u.InputTokens + u.OutputTokens }

// Identity is the authenticated principal attached to a request.
type Identity struct {
	TenantID string
	APIKeyID string
	Plan     string
}

// RateLimit describes one admission request in abstract cost units.
type RateLimit struct {
	Key   string
	Cost  int64
	Limit int64
	Burst int64
	Every time.Duration
}

type RateLimitDecision struct {
	Allowed   bool
	Remaining int64
	ResetAt   time.Time
}

type CreditReservation struct {
	ID       string
	TenantID string
	Reserved int64
}
