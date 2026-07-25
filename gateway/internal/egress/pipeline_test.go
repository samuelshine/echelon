package egress

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/core"
)

func TestPipelineAppliesRedactionBeforeLaterScanner(t *testing.T) {
	redactor := scannerFunc{name: "redactor", scan: func(_ context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
		response.Body = []byte(`{"email":"[REDACTED]"}`)
		return response, core.Verdict{Action: core.ActionRedact, Findings: []core.Finding{{Layer: "redactor", Code: "email"}}}, nil
	}}
	observer := scannerFunc{name: "observer", scan: func(_ context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
		if string(response.Body) != `{"email":"[REDACTED]"}` {
			t.Fatalf("observer received %s", response.Body)
		}
		return response, core.Allow(), nil
	}}
	pipeline, _ := NewPipeline(PipelineConfig{FailClosed: true}, redactor, observer)

	response := core.ModelResponse{RequestID: "req-1", Body: []byte(`{"email":"user@example.com"}`)}
	output, verdict, err := pipeline.Scan(context.Background(), response)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionRedact || string(output.Body) != `{"email":"[REDACTED]"}` {
		t.Fatalf("unexpected output: body=%s verdict=%#v", output.Body, verdict)
	}
}

func TestPipelineRejectsUnapprovedMutationWithoutChangingOriginal(t *testing.T) {
	malicious := scannerFunc{name: "malicious", scan: func(_ context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
		response.Body[0] = 'X'
		return response, core.Allow(), nil
	}}
	pipeline, _ := NewPipeline(PipelineConfig{FailClosed: true}, malicious)
	original := core.ModelResponse{Body: []byte(`{"safe":true}`)}

	output, verdict, err := pipeline.Scan(context.Background(), original)
	if err == nil {
		t.Fatal("expected invalid mutation error")
	}
	if verdict.Action != core.ActionBlock || string(output.Body) != `{"safe":true}` || string(original.Body) != `{"safe":true}` {
		t.Fatalf("mutation escaped isolation: output=%s original=%s verdict=%#v", output.Body, original.Body, verdict)
	}
}

func TestPipelineHonorsScannerTimeout(t *testing.T) {
	slow := scannerFunc{name: "slow", scan: func(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
		<-ctx.Done()
		return response, core.Verdict{}, ctx.Err()
	}}
	pipeline, _ := NewPipeline(PipelineConfig{ScannerTimeout: time.Millisecond, FailClosed: true}, slow)
	_, verdict, err := pipeline.Scan(context.Background(), core.ModelResponse{})
	if !errors.Is(err, context.DeadlineExceeded) || verdict.Action != core.ActionBlock {
		t.Fatalf("error=%v verdict=%#v", err, verdict)
	}
}

type scannerFunc struct {
	name string
	scan func(context.Context, core.ModelResponse) (core.ModelResponse, core.Verdict, error)
}

func (s scannerFunc) Name() string { return s.name }
func (s scannerFunc) Scan(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	return s.scan(ctx, response)
}
