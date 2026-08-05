package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/jscyril/echelon/internal/core"
)

const defaultResponseScannerLimit int64 = 64 << 10

// HTTPResponseClassifier scores the assistant's response text (egress), mirroring
// ingress.HTTPClassifier's request/response contract against a different route.
type HTTPResponseClassifier struct {
	name     string
	endpoint *url.URL
	client   HTTPDoer
}

func NewHTTPResponseClassifier(name string, endpoint *url.URL, client HTTPDoer) (*HTTPResponseClassifier, error) {
	if name == "" || endpoint == nil || endpoint.Scheme == "" || endpoint.Host == "" || client == nil {
		return nil, fmt.Errorf("invalid egress adapter: classifier requires a name, absolute endpoint, and HTTP client")
	}
	copyURL := *endpoint
	return &HTTPResponseClassifier{name: name, endpoint: &copyURL, client: client}, nil
}

func (c *HTTPResponseClassifier) Name() string { return c.name }

func (c *HTTPResponseClassifier) Classify(ctx context.Context, response core.ModelResponse) (core.Classification, error) {
	payload := responseSecurityRequest{
		RequestID: response.RequestID, Model: response.Model,
		Text: ExtractAssistantText(response.Body),
	}
	var result core.Classification
	if err := postResponseSecurityJSON(ctx, c.client, c.endpoint, payload, &result); err != nil {
		return core.Classification{}, err
	}
	if result.MaliciousProbability < 0 || result.MaliciousProbability > 1 {
		return core.Classification{}, fmt.Errorf("response classifier probability is outside [0,1]")
	}
	return result, nil
}

type responseSecurityRequest struct {
	RequestID string `json:"request_id"`
	Model     string `json:"model,omitempty"`
	Text      string `json:"text"`
}

type responseJudgeResult struct {
	Malicious  bool    `json:"malicious"`
	Confidence float64 `json:"confidence"`
	Code       string  `json:"code"`
}

// ExtractAssistantText pulls the assistant's reply text out of an OpenAI-shaped
// chat-completion body (choices[].message.content), the shape every upstream
// provider adapter normalizes its response into before egress ever sees it. It is
// exported so the gateway can reuse the exact same completion-shape parsing when
// synthesizing a single-chunk SSE response — there must be exactly one
// implementation of "pull assistant text out of a chat-completion JSON body".
func ExtractAssistantText(body []byte) string {
	var payload struct {
		Choices []struct {
			Message struct {
				Content any `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	var b bytes.Buffer
	for _, choice := range payload.Choices {
		writeResponseContent(&b, choice.Message.Content)
	}
	return b.String()
}

func writeResponseContent(b *bytes.Buffer, value any) {
	switch typed := value.(type) {
	case string:
		b.WriteString(typed)
		b.WriteByte('\n')
	case []any:
		for _, item := range typed {
			if part, ok := item.(map[string]any); ok {
				if text, ok := part["text"].(string); ok {
					b.WriteString(text)
					b.WriteByte('\n')
				}
				continue
			}
			writeResponseContent(b, item)
		}
	}
}

func postResponseSecurityJSON(ctx context.Context, client HTTPDoer, endpoint *url.URL, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode egress security request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create egress security request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call egress security service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, defaultResponseScannerLimit))
		return fmt.Errorf("egress security service returned HTTP %d", resp.StatusCode)
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, defaultResponseScannerLimit+1))
	if err != nil {
		return fmt.Errorf("read egress security response: %w", err)
	}
	if int64(len(responseBody)) > defaultResponseScannerLimit {
		return fmt.Errorf("egress security response exceeds %d bytes", defaultResponseScannerLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode egress security response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode egress security response: expected one JSON document")
	}
	return nil
}
