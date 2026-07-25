package guard

import "context"

type PromptRequest struct {
	Route string
	Body  []byte
	Text  string
}

type OutputResponse struct {
	Route string
	Body  []byte
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type PromptGuard interface {
	Check(ctx context.Context, req PromptRequest) Decision
}

type NamedGuard interface {
	PromptGuard
	Name() string
}

type OutputScanner interface {
	Scan(ctx context.Context, resp OutputResponse) Decision
}

type NamedOutputScanner interface {
	OutputScanner
	Name() string
}

func Allow() Decision {
	return Decision{Allowed: true}
}

func Block(code string, message string) Decision {
	return Decision{
		Allowed: false,
		Code:    code,
		Message: message,
	}
}

type Chain struct {
	guards []PromptGuard
}

func NewChain(guards ...PromptGuard) Chain {
	return Chain{guards: guards}
}

func (c Chain) Check(ctx context.Context, req PromptRequest) Decision {
	for _, next := range c.guards {
		decision := next.Check(ctx, req)
		if !decision.Allowed {
			return decision
		}
	}
	return Allow()
}

func (c Chain) Names() []string {
	names := make([]string, 0, len(c.guards))
	for _, next := range c.guards {
		named, ok := next.(interface{ Name() string })
		if ok {
			names = append(names, named.Name())
			continue
		}
		names = append(names, "unnamed")
	}
	return names
}
