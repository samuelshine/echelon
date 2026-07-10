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

type HTTPDoer interface {
	Do(request *http.Request) (*http.Response, error)
}

// RemoteScoreScanner adapts toxicity, hallucination, and policy classifiers
// that expose the same bounded score contract.
type RemoteScoreScanner struct {
	name      string
	code      string
	endpoint  *url.URL
	client    HTTPDoer
	threshold float64
}

func NewRemoteScoreScanner(name, code string, endpoint *url.URL, client HTTPDoer, threshold float64) (*RemoteScoreScanner, error) {
	if name == "" || code == "" || endpoint == nil || endpoint.Scheme == "" || endpoint.Host == "" || client == nil {
		return nil, fmt.Errorf("remote scanner requires a name, code, absolute endpoint, and HTTP client")
	}
	if threshold < 0 || threshold > 1 {
		return nil, fmt.Errorf("remote scanner threshold must be within [0,1]")
	}
	copyURL := *endpoint
	return &RemoteScoreScanner{name: name, code: code, endpoint: &copyURL, client: client, threshold: threshold}, nil
}

func (s *RemoteScoreScanner) Name() string { return s.name }

func (s *RemoteScoreScanner) Scan(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	payload, err := json.Marshal(struct {
		RequestID string          `json:"request_id"`
		Model     string          `json:"model,omitempty"`
		Response  json.RawMessage `json:"response"`
	}{RequestID: response.RequestID, Model: response.Model, Response: response.Body})
	if err != nil {
		return response, core.Verdict{}, fmt.Errorf("encode scanner request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return response, core.Verdict{}, fmt.Errorf("create scanner request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return response, core.Verdict{}, fmt.Errorf("call scanner: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return response, core.Verdict{}, fmt.Errorf("scanner returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Score float64 `json:"score"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, (64<<10)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result.Score < 0 || result.Score > 1 {
		return response, core.Verdict{}, fmt.Errorf("scanner returned an invalid score")
	}
	if result.Score < s.threshold {
		return response, core.Allow(), nil
	}
	return response, core.Block(core.Finding{
		Layer: s.name, Code: s.code,
		Message: "response classifier threshold exceeded", Confidence: result.Score,
	}), nil
}
