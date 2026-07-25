// Package upstream provides multi-provider LLM adapters. Each provider
// translates between the gateway's OpenAI-compatible wire format and the
// provider's native API, normalising responses back to the OpenAI shape so
// clients always receive a consistent contract.
package upstream

import (
	"context"
	"net/http"
)

// Provider is the boundary between the gateway and a specific LLM vendor.
// Implementations must be safe for concurrent use.
type Provider interface {
	// Name returns a stable, human-readable identifier (e.g. "openai", "gemini").
	Name() string

	// ForwardChat translates the inbound OpenAI-format body, calls the upstream,
	// and returns the raw HTTP response (caller drains and closes the body).
	// The response body MUST be normalised to OpenAI /v1/chat/completions format.
	ForwardChat(ctx context.Context, model string, body []byte) (*http.Response, error)

	// ForwardModels returns the provider's available models. Implementations
	// may cache aggressively since model lists rarely change.
	ForwardModels(ctx context.Context) (*http.Response, error)
}

// ProviderConfig is the configuration needed to construct any provider adapter.
type ProviderConfig struct {
	Name    string // stable identifier, e.g. "openai"
	BaseURL string // e.g. "https://api.openai.com"
	APIKey  string // empty for keyless providers like Ollama
	Format  string // "openai", "gemini", "anthropic", "ollama"
}
