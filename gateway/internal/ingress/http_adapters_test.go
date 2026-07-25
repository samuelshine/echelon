package ingress

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jscyril/echelon/internal/core"
)

func TestHTTPClassifier(t *testing.T) {
	client := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request: method=%s content-type=%s", r.Method, r.Header.Get("Content-Type"))
		}
		return jsonResponse(`{"malicious_probability":0.73,"labels":{"injection":0.73}}`), nil
	})

	endpoint, _ := url.Parse("https://classifier.example/v1/classify")
	classifier, err := NewHTTPClassifier("deberta", endpoint, client)
	if err != nil {
		t.Fatal(err)
	}
	result, err := classifier.Classify(context.Background(), core.Prompt{RequestID: "req-1", Text: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if result.MaliciousProbability != 0.73 {
		t.Fatalf("probability = %f", result.MaliciousProbability)
	}
}

func TestHTTPJudgeRejectsUnstructuredResponse(t *testing.T) {
	client := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(`{"answer":"probably bad"}`), nil
	})
	endpoint, _ := url.Parse("https://judge.example/v1/judge")
	judge, err := NewHTTPJudge("fast-judge", endpoint, client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := judge.Judge(context.Background(), core.Prompt{Text: "hello"}); err == nil {
		t.Fatal("expected strict response parsing error")
	}
}

func TestHTTPJudgeBlocksStructuredMaliciousVerdict(t *testing.T) {
	client := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(`{"malicious":true,"confidence":0.88,"code":"indirect_injection"}`), nil
	})
	endpoint, _ := url.Parse("https://judge.example/v1/judge")
	judge, _ := NewHTTPJudge("fast-judge", endpoint, client)
	verdict, err := judge.Judge(context.Background(), core.Prompt{Text: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionBlock || verdict.Findings[0].Code != "indirect_injection" {
		t.Fatalf("unexpected verdict: %#v", verdict)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(request *http.Request) (*http.Response, error) { return f(request) }

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
