package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Anthropic implements the Provider interface for Anthropic's Claude API.
type Anthropic struct {
	name    string
	baseURL *url.URL
	apiKey  string
	client  *http.Client
}

func NewAnthropic(cfg ProviderConfig, client *http.Client) (*Anthropic, error) {
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.anthropic.com"
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("anthropic: invalid base URL %q", base)
	}
	name := cfg.Name
	if name == "" {
		name = "anthropic"
	}
	return &Anthropic{name: name, baseURL: parsed, apiKey: cfg.APIKey, client: client}, nil
}

func (a *Anthropic) Name() string { return a.name }

// --- Anthropic request types ------------------------------------------------

type anthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []anthropicMessage `json:"messages"`
	System      string             `json:"system,omitempty"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature *float64           `json:"temperature,omitempty"`
	TopP        *float64           `json:"top_p,omitempty"`
	Stop        []string           `json:"stop_sequences,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// --- Anthropic response types -----------------------------------------------

type anthropicResponse struct {
	ID           string             `json:"id"`
	Type         string             `json:"type"`
	Role         string             `json:"role"`
	Content      []anthropicContent `json:"content"`
	Model        string             `json:"model"`
	StopReason   string             `json:"stop_reason"`
	StopSequence string             `json:"stop_sequence"`
	Usage        anthropicUsage     `json:"usage"`
}

type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func (a *Anthropic) ForwardChat(ctx context.Context, model string, body []byte) (*http.Response, error) {
	var oaiReq openAIRequest
	if err := json.Unmarshal(body, &oaiReq); err != nil {
		return nil, fmt.Errorf("anthropic: parse request: %w", err)
	}
	if model != "" {
		oaiReq.Model = model
	}

	antReq := translateToAnthropic(oaiReq)
	antBody, err := json.Marshal(antReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic: marshal request: %w", err)
	}

	target := *a.baseURL
	target.Path = joinPath(a.baseURL.Path, "/v1/messages")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(antBody))
	if err != nil {
		return nil, fmt.Errorf("anthropic: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01") // Required by Anthropic
	if a.apiKey != "" {
		req.Header.Set("x-api-key", a.apiKey)
	}
	req.Host = target.Host

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic: upstream call: %w", err)
	}

	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("anthropic: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		errBody := wrapProviderError("anthropic", resp.StatusCode, respBody)
		return buildResponse(resp.StatusCode, errBody), nil
	}

	var antResp anthropicResponse
	if err := json.Unmarshal(respBody, &antResp); err != nil {
		return nil, fmt.Errorf("anthropic: parse response: %w", err)
	}

	oaiResp := normaliseAnthropicResponse(antResp)
	normalised, err := json.Marshal(oaiResp)
	if err != nil {
		return nil, fmt.Errorf("anthropic: marshal normalised response: %w", err)
	}

	return buildResponse(http.StatusOK, normalised), nil
}

func (a *Anthropic) ForwardModels(ctx context.Context) (*http.Response, error) {
	// Anthropic doesn't have a standard /v1/models endpoint, mock a response.
	mockModels := `{"object":"list","data":[{"id":"claude-3-opus-20240229","object":"model"},{"id":"claude-3-sonnet-20240229","object":"model"},{"id":"claude-3-haiku-20240307","object":"model"}]}`
	return buildResponse(http.StatusOK, []byte(mockModels)), nil
}

func translateToAnthropic(oai openAIRequest) anthropicRequest {
	ant := anthropicRequest{
		Model:       oai.Model,
		Temperature: oai.Temperature,
		TopP:        oai.TopP,
		MaxTokens:   4096, // Anthropic requires max_tokens
	}
	if oai.MaxTokens != nil && *oai.MaxTokens > 0 {
		ant.MaxTokens = *oai.MaxTokens
	}

	var system strings.Builder
	for _, msg := range oai.Messages {
		if msg.Role == "system" {
			system.WriteString(msg.TextContent())
			system.WriteByte('\n')
		} else {
			// Anthropic only allows "user" and "assistant" roles.
			role := "user"
			if msg.Role == "assistant" {
				role = "assistant"
			}
			ant.Messages = append(ant.Messages, anthropicMessage{
				Role:    role,
				Content: msg.TextContent(),
			})
		}
	}
	ant.System = strings.TrimSpace(system.String())

	if len(oai.Stop) > 0 {
		var stops []string
		var single string
		if json.Unmarshal(oai.Stop, &single) == nil {
			stops = []string{single}
		} else {
			_ = json.Unmarshal(oai.Stop, &stops)
		}
		ant.Stop = stops
	}

	return ant
}

func normaliseAnthropicResponse(ant anthropicResponse) openAIResponse {
	resp := openAIResponse{
		ID:      ant.ID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   ant.Model,
	}

	var text strings.Builder
	for _, c := range ant.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}

	reason := "stop"
	switch ant.StopReason {
	case "end_turn", "stop_sequence":
		reason = "stop"
	case "max_tokens":
		reason = "length"
	}

	resp.Choices = append(resp.Choices, openAIChoice{
		Index:        0,
		Message:      openAIMessage{Role: "assistant", Content: text.String()},
		FinishReason: reason,
	})

	resp.Usage = openAIUsage{
		PromptTokens:     ant.Usage.InputTokens,
		CompletionTokens: ant.Usage.OutputTokens,
		TotalTokens:      ant.Usage.InputTokens + ant.Usage.OutputTokens,
	}

	return resp
}
