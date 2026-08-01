package egress

import (
	"context"
	"fmt"
	"net/url"

	"github.com/jscyril/echelon/internal/core"
)

// HTTPResponseJudge escalates ambiguous response-classifier scores to the LLM
// judge, mirroring ingress.HTTPJudge's contract against the /judge_response route.
type HTTPResponseJudge struct {
	name     string
	endpoint *url.URL
	client   HTTPDoer
}

func NewHTTPResponseJudge(name string, endpoint *url.URL, client HTTPDoer) (*HTTPResponseJudge, error) {
	if name == "" || endpoint == nil || endpoint.Scheme == "" || endpoint.Host == "" || client == nil {
		return nil, fmt.Errorf("invalid egress adapter: judge requires a name, absolute endpoint, and HTTP client")
	}
	copyURL := *endpoint
	return &HTTPResponseJudge{name: name, endpoint: &copyURL, client: client}, nil
}

func (j *HTTPResponseJudge) Name() string { return j.name }

func (j *HTTPResponseJudge) Judge(ctx context.Context, response core.ModelResponse) (core.Verdict, error) {
	payload := responseSecurityRequest{
		RequestID: response.RequestID, Model: response.Model,
		Text: extractAssistantText(response.Body),
	}
	var result responseJudgeResult
	if err := postResponseSecurityJSON(ctx, j.client, j.endpoint, payload, &result); err != nil {
		return core.Verdict{}, err
	}
	if result.Confidence < 0 || result.Confidence > 1 || result.Code == "" {
		return core.Verdict{}, fmt.Errorf("response judge returned an invalid structured verdict")
	}
	if !result.Malicious {
		return core.Allow(), nil
	}
	return core.Block(core.Finding{
		Layer: j.name, Code: result.Code,
		Message: "LLM judge detected a policy violation in the response", Confidence: result.Confidence,
	}), nil
}
