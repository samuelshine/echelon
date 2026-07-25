package upstream

import (
	"context"
	"net/http"
	"testing"
)

type mockProvider struct {
	name string
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) ForwardChat(ctx context.Context, model string, body []byte) (*http.Response, error) {
	return nil, nil
}
func (m *mockProvider) ForwardModels(ctx context.Context) (*http.Response, error) {
	return nil, nil
}

func TestRouterResolution(t *testing.T) {
	providers := []Provider{
		&mockProvider{name: "openai"},
		&mockProvider{name: "gemini"},
		&mockProvider{name: "anthropic"},
		&mockProvider{name: "ollama"},
	}

	tests := []struct {
		name       string
		cfg        RouterConfig
		model      string
		want       string
		expectFail bool
	}{
		{
			name:  "built-in default openai",
			cfg:   RouterConfig{DefaultProvider: "openai"},
			model: "gpt-4o-mini",
			want:  "openai",
		},
		{
			name:  "built-in default gemini",
			cfg:   RouterConfig{DefaultProvider: "openai"},
			model: "gemini-1.5-pro",
			want:  "gemini",
		},
		{
			name:  "built-in default anthropic",
			cfg:   RouterConfig{DefaultProvider: "openai"},
			model: "claude-3-5-sonnet",
			want:  "anthropic",
		},
		{
			name:  "fallback to default",
			cfg:   RouterConfig{DefaultProvider: "ollama"},
			model: "unknown-model-xyz",
			want:  "ollama",
		},
		{
			name:  "explicit exact route override",
			cfg:   RouterConfig{ModelRoutes: "gpt-4:gemini", DefaultProvider: "openai"},
			model: "gpt-4",
			want:  "gemini", // overridden
		},
		{
			name:  "explicit wildcard route",
			cfg:   RouterConfig{ModelRoutes: "my-custom-*:ollama", DefaultProvider: "openai"},
			model: "my-custom-model",
			want:  "ollama",
		},
		{
			name:  "catch-all wildcard",
			cfg:   RouterConfig{ModelRoutes: "*:anthropic", DefaultProvider: "openai"},
			model: "literally-anything",
			want:  "anthropic",
		},
		{
			name:       "invalid default provider",
			cfg:        RouterConfig{DefaultProvider: "missing"},
			model:      "gpt-4",
			expectFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewRouter(providers, tt.cfg)
			if tt.expectFail {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := r.Resolve(tt.model).Name()
			if got != tt.want {
				t.Errorf("Resolve(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}
