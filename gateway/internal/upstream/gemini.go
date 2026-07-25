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

// Gemini implements the Provider interface for Google's Generative Language API.
// It translates OpenAI chat/completions requests to Gemini generateContent and
// normalises responses back to the OpenAI shape.
type Gemini struct {
	name    string
	baseURL *url.URL
	apiKey  string
	client  *http.Client
}

// NewGemini constructs a Gemini provider adapter.
func NewGemini(cfg ProviderConfig, client *http.Client) (*Gemini, error) {
	base := cfg.BaseURL
	if base == "" {
		base = "https://generativelanguage.googleapis.com"
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("gemini: invalid base URL %q", base)
	}
	name := cfg.Name
	if name == "" {
		name = "gemini"
	}
	return &Gemini{name: name, baseURL: parsed, apiKey: cfg.APIKey, client: client}, nil
}

func (g *Gemini) Name() string { return g.name }

// --- OpenAI request types (inbound) -----------------------------------------

type openAIRequest struct {
	Model       string           `json:"model"`
	Messages    []openAIMessage  `json:"messages"`
	MaxTokens   *int             `json:"max_tokens,omitempty"`
	Temperature *float64         `json:"temperature,omitempty"`
	TopP        *float64         `json:"top_p,omitempty"`
	Stop        json.RawMessage  `json:"stop,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string or []contentPart
}

func (m openAIMessage) TextContent() string {
	switch v := m.Content.(type) {
	case string:
		return v
	case []any:
		var b strings.Builder
		for _, part := range v {
			if mp, ok := part.(map[string]any); ok {
				if text, ok := mp["text"].(string); ok {
					b.WriteString(text)
				}
			}
		}
		return b.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// --- Gemini request types (outbound) ----------------------------------------

type geminiRequest struct {
	Contents          []geminiContent          `json:"contents"`
	SystemInstruction *geminiContent           `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenerationConfig  `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens *int      `json:"maxOutputTokens,omitempty"`
	Temperature     *float64  `json:"temperature,omitempty"`
	TopP            *float64  `json:"topP,omitempty"`
	StopSequences   []string  `json:"stopSequences,omitempty"`
}

// --- Gemini response types --------------------------------------------------

type geminiResponse struct {
	Candidates    []geminiCandidate  `json:"candidates"`
	UsageMetadata *geminiUsage       `json:"usageMetadata,omitempty"`
	ModelVersion  string             `json:"modelVersion,omitempty"`
}

type geminiCandidate struct {
	Content      geminiContent `json:"content"`
	FinishReason string        `json:"finishReason"`
	Index        int           `json:"index"`
}

type geminiUsage struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

// --- OpenAI response types (normalised output) ------------------------------

type openAIResponse struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []openAIChoice `json:"choices"`
	Usage   openAIUsage    `json:"usage"`
}

type openAIChoice struct {
	Index        int            `json:"index"`
	Message      openAIMessage  `json:"message"`
	FinishReason string         `json:"finish_reason"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ForwardChat translates an OpenAI chat request to Gemini and normalises the
// response back to OpenAI format.
func (g *Gemini) ForwardChat(ctx context.Context, model string, body []byte) (*http.Response, error) {
	var oaiReq openAIRequest
	if err := json.Unmarshal(body, &oaiReq); err != nil {
		return nil, fmt.Errorf("gemini: parse request: %w", err)
	}
	if model != "" {
		oaiReq.Model = model
	}

	gemReq := translateToGemini(oaiReq)

	gemBody, err := json.Marshal(gemReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshal request: %w", err)
	}

	target := *g.baseURL
	target.Path = joinPath(g.baseURL.Path, fmt.Sprintf("/v1beta/models/%s:generateContent", oaiReq.Model))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(gemBody))
	if err != nil {
		return nil, fmt.Errorf("gemini: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if g.apiKey != "" {
		req.Header.Set("x-goog-api-key", g.apiKey)
	}
	req.Host = target.Host

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gemini: upstream call: %w", err)
	}

	// Read, translate, and re-wrap the response.
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("gemini: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Pass through error responses as-is, wrapping in OpenAI error format.
		errBody := wrapProviderError("gemini", resp.StatusCode, respBody)
		return buildResponse(resp.StatusCode, errBody), nil
	}

	var gemResp geminiResponse
	if err := json.Unmarshal(respBody, &gemResp); err != nil {
		return nil, fmt.Errorf("gemini: parse response: %w", err)
	}

	oaiResp := normaliseGeminiResponse(gemResp, oaiReq.Model)
	normalised, err := json.Marshal(oaiResp)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshal normalised response: %w", err)
	}

	return buildResponse(http.StatusOK, normalised), nil
}

func (g *Gemini) ForwardModels(ctx context.Context) (*http.Response, error) {
	target := *g.baseURL
	target.Path = joinPath(g.baseURL.Path, "/v1beta/models")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("gemini: build models request: %w", err)
	}
	if g.apiKey != "" {
		req.Header.Set("x-goog-api-key", g.apiKey)
	}
	req.Host = target.Host

	return g.client.Do(req)
}

// --- Translation helpers ----------------------------------------------------

func translateToGemini(oai openAIRequest) geminiRequest {
	var gem geminiRequest

	for _, msg := range oai.Messages {
		switch msg.Role {
		case "system":
			gem.SystemInstruction = &geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: msg.TextContent()}},
			}
		case "assistant":
			gem.Contents = append(gem.Contents, geminiContent{
				Role:  "model",
				Parts: []geminiPart{{Text: msg.TextContent()}},
			})
		default: // "user" and anything else
			gem.Contents = append(gem.Contents, geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: msg.TextContent()}},
			})
		}
	}

	if oai.MaxTokens != nil || oai.Temperature != nil || oai.TopP != nil || len(oai.Stop) > 0 {
		gc := &geminiGenerationConfig{
			MaxOutputTokens: oai.MaxTokens,
			Temperature:     oai.Temperature,
			TopP:            oai.TopP,
		}
		if len(oai.Stop) > 0 {
			var stops []string
			// "stop" can be a string or []string in OpenAI format.
			var single string
			if json.Unmarshal(oai.Stop, &single) == nil {
				stops = []string{single}
			} else {
				_ = json.Unmarshal(oai.Stop, &stops)
			}
			gc.StopSequences = stops
		}
		gem.GenerationConfig = gc
	}

	return gem
}

func normaliseGeminiResponse(gem geminiResponse, model string) openAIResponse {
	resp := openAIResponse{
		ID:      fmt.Sprintf("chatcmpl-gemini-%d", time.Now().UnixNano()),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
	}

	for _, c := range gem.Candidates {
		var text strings.Builder
		for _, p := range c.Content.Parts {
			text.WriteString(p.Text)
		}
		finishReason := mapGeminiFinishReason(c.FinishReason)
		resp.Choices = append(resp.Choices, openAIChoice{
			Index:        c.Index,
			Message:      openAIMessage{Role: "assistant", Content: text.String()},
			FinishReason: finishReason,
		})
	}

	if gem.UsageMetadata != nil {
		resp.Usage = openAIUsage{
			PromptTokens:     gem.UsageMetadata.PromptTokenCount,
			CompletionTokens: gem.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      gem.UsageMetadata.TotalTokenCount,
		}
	}

	return resp
}

func mapGeminiFinishReason(reason string) string {
	switch strings.ToUpper(reason) {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY":
		return "content_filter"
	default:
		return "stop"
	}
}
