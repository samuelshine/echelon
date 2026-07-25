package ingress

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

const defaultSecurityResponseLimit int64 = 64 << 10

type HTTPDoer interface {
	Do(request *http.Request) (*http.Response, error)
}

type HTTPClassifier struct {
	name     string
	endpoint *url.URL
	client   HTTPDoer
}

func NewHTTPClassifier(name string, endpoint *url.URL, client HTTPDoer) (*HTTPClassifier, error) {
	if name == "" || endpoint == nil || endpoint.Scheme == "" || endpoint.Host == "" || client == nil {
		return nil, errorsForAdapter("classifier requires a name, absolute endpoint, and HTTP client")
	}
	copyURL := *endpoint
	return &HTTPClassifier{name: name, endpoint: &copyURL, client: client}, nil
}

func (c *HTTPClassifier) Name() string { return c.name }

func (c *HTTPClassifier) Classify(ctx context.Context, prompt core.Prompt) (core.Classification, error) {
	payload := classifierRequest{RequestID: prompt.RequestID, Model: prompt.Model, Text: prompt.Text}
	var result core.Classification
	if err := postSecurityJSON(ctx, c.client, c.endpoint, payload, &result); err != nil {
		return core.Classification{}, err
	}
	if result.MaliciousProbability < 0 || result.MaliciousProbability > 1 {
		return core.Classification{}, fmt.Errorf("classifier probability is outside [0,1]")
	}
	return result, nil
}

type HTTPJudge struct {
	name     string
	endpoint *url.URL
	client   HTTPDoer
}

func NewHTTPJudge(name string, endpoint *url.URL, client HTTPDoer) (*HTTPJudge, error) {
	if name == "" || endpoint == nil || endpoint.Scheme == "" || endpoint.Host == "" || client == nil {
		return nil, errorsForAdapter("judge requires a name, absolute endpoint, and HTTP client")
	}
	copyURL := *endpoint
	return &HTTPJudge{name: name, endpoint: &copyURL, client: client}, nil
}

func (j *HTTPJudge) Name() string { return j.name }

func (j *HTTPJudge) Judge(ctx context.Context, prompt core.Prompt) (core.Verdict, error) {
	payload := classifierRequest{RequestID: prompt.RequestID, Model: prompt.Model, Text: prompt.Text}
	var result judgeResponse
	if err := postSecurityJSON(ctx, j.client, j.endpoint, payload, &result); err != nil {
		return core.Verdict{}, err
	}
	if result.Confidence < 0 || result.Confidence > 1 || result.Code == "" {
		return core.Verdict{}, fmt.Errorf("judge returned an invalid structured verdict")
	}
	if !result.Malicious {
		return core.Allow(), nil
	}
	return core.Block(core.Finding{
		Layer: j.name, Code: result.Code,
		Message: "LLM judge detected a policy violation", Confidence: result.Confidence,
	}), nil
}

type classifierRequest struct {
	RequestID string `json:"request_id"`
	Model     string `json:"model,omitempty"`
	Text      string `json:"text"`
}

type judgeResponse struct {
	Malicious  bool    `json:"malicious"`
	Confidence float64 `json:"confidence"`
	Code       string  `json:"code"`
}

func postSecurityJSON(ctx context.Context, client HTTPDoer, endpoint *url.URL, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode security request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create security request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call security service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, defaultSecurityResponseLimit))
		return fmt.Errorf("security service returned HTTP %d", resp.StatusCode)
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, defaultSecurityResponseLimit+1))
	if err != nil {
		return fmt.Errorf("read security response: %w", err)
	}
	if int64(len(responseBody)) > defaultSecurityResponseLimit {
		return fmt.Errorf("security response exceeds %d bytes", defaultSecurityResponseLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode security response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode security response: expected one JSON document")
	}
	return nil
}

func errorsForAdapter(message string) error {
	return fmt.Errorf("invalid security adapter: %s", message)
}
