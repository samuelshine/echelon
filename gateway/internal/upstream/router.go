package upstream

import (
	"fmt"
	"strings"
)

// routeRule maps a model-name glob pattern to a provider name.
type routeRule struct {
	pattern  string // e.g. "gpt-*", "claude-*", or "*"
	provider string // e.g. "openai", "anthropic"
}

// Router selects a Provider for each request based on the model field.
type Router struct {
	providers map[string]Provider
	routes    []routeRule
	fallback  string
}

// RouterConfig controls how the Router is built.
type RouterConfig struct {
	// ModelRoutes is a comma-separated list of "glob:provider" pairs, e.g.
	// "gpt-*:openai,gemini-*:gemini,claude-*:anthropic,*:ollama".
	ModelRoutes string
	// DefaultProvider is used when no route matches. If empty, the first
	// registered provider is used.
	DefaultProvider string
}

// well-known model prefixes when no explicit routes are configured.
var defaultRoutes = []routeRule{
	{"gpt-*", "openai"},
	{"o1-*", "openai"},
	{"o3-*", "openai"},
	{"o4-*", "openai"},
	{"chatgpt-*", "openai"},
	{"gemini-*", "gemini"},
	{"claude-*", "anthropic"},
}

// NewRouter constructs a Router from a set of providers and routing config.
func NewRouter(providers []Provider, cfg RouterConfig) (*Router, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("at least one provider is required")
	}

	providerMap := make(map[string]Provider, len(providers))
	for _, p := range providers {
		if _, exists := providerMap[p.Name()]; exists {
			return nil, fmt.Errorf("duplicate provider name: %s", p.Name())
		}
		providerMap[p.Name()] = p
	}

	routes := parseRoutes(cfg.ModelRoutes)
	// Append well-known defaults for any provider that is registered but has
	// no explicit route yet.
	covered := make(map[string]bool, len(routes))
	for _, r := range routes {
		covered[r.provider] = true
	}
	for _, dr := range defaultRoutes {
		if _, ok := providerMap[dr.provider]; ok && !covered[dr.provider] {
			routes = append(routes, dr)
		}
	}

	fallback := cfg.DefaultProvider
	if fallback == "" {
		fallback = providers[0].Name()
	}
	if _, ok := providerMap[fallback]; !ok {
		return nil, fmt.Errorf("default provider %q is not registered", fallback)
	}

	return &Router{
		providers: providerMap,
		routes:    routes,
		fallback:  fallback,
	}, nil
}

// Resolve returns the Provider that should handle the given model.
func (r *Router) Resolve(model string) Provider {
	lower := strings.ToLower(model)
	for _, rule := range r.routes {
		if globMatch(rule.pattern, lower) {
			if p, ok := r.providers[rule.provider]; ok {
				return p
			}
		}
	}
	return r.providers[r.fallback]
}

// Providers returns all registered providers.
func (r *Router) Providers() map[string]Provider {
	return r.providers
}

// DefaultProvider returns the fallback provider.
func (r *Router) DefaultProvider() Provider {
	return r.providers[r.fallback]
}

func parseRoutes(raw string) []routeRule {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var rules []routeRule
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		rules = append(rules, routeRule{
			pattern:  strings.ToLower(strings.TrimSpace(parts[0])),
			provider: strings.ToLower(strings.TrimSpace(parts[1])),
		})
	}
	return rules
}

// globMatch performs simple prefix-glob matching: "gpt-*" matches "gpt-4o-mini".
// An exact "*" matches everything. No other wildcard positions are supported.
func globMatch(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	return pattern == value
}
