// Package ports defines the boundaries between Echelon's application core and
// swappable security, persistence, and provider adapters.
package ports

import (
	"context"
	"time"

	"github.com/jscyril/echelon/internal/core"
)

type IngressLayer interface {
	Name() string
	Evaluate(ctx context.Context, prompt core.Prompt) (core.Verdict, error)
}

type PromptClassifier interface {
	Name() string
	Classify(ctx context.Context, prompt core.Prompt) (core.Classification, error)
}

type PromptJudge interface {
	Name() string
	Judge(ctx context.Context, prompt core.Prompt) (core.Verdict, error)
}

type EgressScanner interface {
	Name() string
	Scan(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error)
}

type Upstream interface {
	Invoke(ctx context.Context, prompt core.Prompt) (core.ModelResponse, error)
}

type RateLimiter interface {
	Allow(ctx context.Context, request core.RateLimit) (core.RateLimitDecision, error)
}

// CreditLedger uses reservation semantics so rejected or failed upstream calls
// cannot permanently consume a tenant's balance.
type CreditLedger interface {
	Reserve(ctx context.Context, tenantID, idempotencyKey string, maximum int64) (core.CreditReservation, error)
	Commit(ctx context.Context, reservation core.CreditReservation, actual int64) error
	Release(ctx context.Context, reservation core.CreditReservation) error
}

type Authenticator interface {
	Authenticate(ctx context.Context, credential string) (core.Identity, error)
}

type AuditEvent struct {
	RequestID   string
	TenantID    string
	Direction   core.Direction
	Action      core.Action
	Findings    []core.Finding
	PayloadHash string
	OccurredAt  time.Time
}

type AuditSink interface {
	Record(ctx context.Context, event AuditEvent) error
}

type Clock interface {
	Now() time.Time
}
