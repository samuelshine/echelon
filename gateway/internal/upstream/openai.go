package upstream

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// OpenAI implements the Provider interface for OpenAI-compatible APIs.
// Since the gateway's wire format is already OpenAI, this adapter is a
// straightforward pass-through proxy.
type OpenAI struct {
	name    string
	baseURL *url.URL
	apiKey  string
	client  *http.Client
}

// NewOpenAI constructs an OpenAI provider adapter.
func NewOpenAI(cfg ProviderConfig, client *http.Client) (*OpenAI, error) {
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("openai: invalid base URL %q", cfg.BaseURL)
	}
	name := cfg.Name
	if name == "" {
		name = "openai"
	}
	return &OpenAI{name: name, baseURL: parsed, apiKey: cfg.APIKey, client: client}, nil
}

func (o *OpenAI) Name() string { return o.name }

func (o *OpenAI) ForwardChat(ctx context.Context, model string, body []byte) (*http.Response, error) {
	target := *o.baseURL
	target.Path = joinPath(o.baseURL.Path, "/v1/chat/completions")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("openai: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
	}
	req.Host = target.Host

	return o.client.Do(req)
}

func (o *OpenAI) ForwardModels(ctx context.Context) (*http.Response, error) {
	target := *o.baseURL
	target.Path = joinPath(o.baseURL.Path, "/v1/models")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("openai: build models request: %w", err)
	}
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
	}
	req.Host = target.Host

	return o.client.Do(req)
}

func joinPath(base, next string) string {
	b := strings.TrimRight(base, "/")
	n := "/" + strings.TrimLeft(next, "/")
	if b == "" {
		return n
	}
	return b + n
}
