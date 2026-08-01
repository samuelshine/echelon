package egress

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jscyril/echelon/internal/core"
)

func TestHTTPResponseClassifier(t *testing.T) {
	var gotBody string
	client := egressRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request: method=%s content-type=%s", r.Method, r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"malicious_probability":0.62,"labels":{"toxicity_harm":0.62}}`)),
		}, nil
	})

	endpoint, _ := url.Parse("https://security.example/classify_response")
	classifier, err := NewHTTPResponseClassifier("response_classifier", endpoint, client)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"choices":[{"message":{"content":"you are worthless"}}]}`)
	result, err := classifier.Classify(context.Background(), core.ModelResponse{RequestID: "req-1", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if result.MaliciousProbability != 0.62 {
		t.Fatalf("probability = %f", result.MaliciousProbability)
	}
	if !strings.Contains(gotBody, "you are worthless") {
		t.Fatalf("expected extracted assistant text in request body, got %s", gotBody)
	}
	if strings.Contains(gotBody, "choices") {
		t.Fatalf("expected only extracted text sent, not the raw envelope: %s", gotBody)
	}
}

func TestHTTPResponseJudgeRejectsUnstructuredResponse(t *testing.T) {
	client := egressRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"answer":"probably bad"}`)),
		}, nil
	})
	endpoint, _ := url.Parse("https://security.example/judge_response")
	judge, err := NewHTTPResponseJudge("response_judge", endpoint, client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := judge.Judge(context.Background(), core.ModelResponse{Body: []byte(`{}`)}); err == nil {
		t.Fatal("expected strict response parsing error")
	}
}

func TestHTTPResponseJudgeBlocksStructuredMaliciousVerdict(t *testing.T) {
	client := egressRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"malicious":true,"confidence":0.95,"code":"malicious_code"}`)),
		}, nil
	})
	endpoint, _ := url.Parse("https://security.example/judge_response")
	judge, _ := NewHTTPResponseJudge("response_judge", endpoint, client)
	verdict, err := judge.Judge(context.Background(), core.ModelResponse{Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionBlock || verdict.Findings[0].Code != "malicious_code" {
		t.Fatalf("unexpected verdict: %#v", verdict)
	}
}

func TestExtractAssistantText(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "string content", body: `{"choices":[{"message":{"content":"hello there"}}]}`, want: "hello there\n"},
		{name: "no choices", body: `{}`, want: ""},
		{name: "invalid json", body: `not json`, want: ""},
		{
			name: "array-of-parts content",
			body: `{"choices":[{"message":{"content":[{"type":"text","text":"part one"}]}}]}`,
			want: "part one\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAssistantText([]byte(tt.body))
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
