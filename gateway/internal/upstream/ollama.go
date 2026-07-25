package upstream

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Ollama implements the Provider interface for local Ollama instances.
// Ollama provides an OpenAI-compatible API at /v1/chat/completions natively.
type Ollama struct {
	name    string
	baseURL *url.URL
	client  *http.Client
}

func NewOllama(cfg ProviderConfig, client *http.Client) (*Ollama, error) {
	base := cfg.BaseURL
	if base == "" {
		base = "http://127.0.0.1:11434"
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("ollama: invalid base URL %q", base)
	}
	name := cfg.Name
	if name == "" {
		name = "ollama"
	}
	return &Ollama{name: name, baseURL: parsed, client: client}, nil
}

func (o *Ollama) Name() string { return o.name }

func (o *Ollama) ForwardChat(ctx context.Context, model string, body []byte) (*http.Response, error) {
	target := *o.baseURL
	target.Path = joinPath(o.baseURL.Path, "/v1/chat/completions")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ollama: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Ollama doesn't require auth.
	req.Host = target.Host

	return o.client.Do(req)
}

func (o *Ollama) ForwardModels(ctx context.Context) (*http.Response, error) {
	target := *o.baseURL
	target.Path = joinPath(o.baseURL.Path, "/v1/models")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("ollama: build models request: %w", err)
	}
	req.Host = target.Host

	return o.client.Do(req)
}
