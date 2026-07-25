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

func TestRemoteScoreScannerBlocksAtThreshold(t *testing.T) {
	client := egressRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected content type: %s", request.Header.Get("Content-Type"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"score":0.91}`)),
			Header:     make(http.Header),
		}, nil
	})
	endpoint, _ := url.Parse("https://toxicity.example/v1/score")
	scanner, err := NewRemoteScoreScanner("toxicity", "toxic_output", endpoint, client, 0.8)
	if err != nil {
		t.Fatal(err)
	}
	_, verdict, err := scanner.Scan(context.Background(), core.ModelResponse{Body: []byte(`{"content":"example"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionBlock || verdict.Findings[0].Confidence != 0.91 {
		t.Fatalf("unexpected verdict: %#v", verdict)
	}
}

type egressRoundTripFunc func(*http.Request) (*http.Response, error)

func (f egressRoundTripFunc) Do(request *http.Request) (*http.Response, error) { return f(request) }
