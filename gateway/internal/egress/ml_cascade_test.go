package egress

import (
	"context"
	"errors"
	"testing"

	"github.com/jscyril/echelon/internal/core"
)

func TestMLCascadeGating(t *testing.T) {
	tests := []struct {
		name        string
		probability float64
		judgeBlock  bool
		wantAction  core.Action
		wantJudge   int
	}{
		{name: "low confidence allows", probability: 0.10, wantAction: core.ActionAllow},
		{name: "ambiguous invokes allowing judge", probability: 0.70, wantAction: core.ActionAllow, wantJudge: 1},
		{name: "ambiguous invokes blocking judge", probability: 0.70, judgeBlock: true, wantAction: core.ActionBlock, wantJudge: 1},
		{name: "high confidence blocks without judge", probability: 0.95, wantAction: core.ActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifier := &fakeResponseClassifier{probability: tt.probability}
			judge := &fakeResponseJudge{block: tt.judgeBlock}
			cascade, err := NewMLCascade(MLCascadeConfig{
				JudgeThreshold: 0.55, BlockThreshold: 0.90,
			}, classifier, judge)
			if err != nil {
				t.Fatal(err)
			}
			_, verdict, err := cascade.Scan(context.Background(), core.ModelResponse{Body: []byte(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			if verdict.Action != tt.wantAction {
				t.Fatalf("action = %v, want %v", verdict.Action, tt.wantAction)
			}
			if judge.calls != tt.wantJudge {
				t.Fatalf("judge calls = %d, want %d", judge.calls, tt.wantJudge)
			}
		})
	}
}

func TestMLCascadeNeverMutatesBody(t *testing.T) {
	classifier := &fakeResponseClassifier{probability: 0.95}
	cascade, err := NewMLCascade(MLCascadeConfig{JudgeThreshold: 0.55, BlockThreshold: 0.90}, classifier, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"choices":[{"message":{"content":"hi"}}]}`)
	response, verdict, err := cascade.Scan(context.Background(), core.ModelResponse{Body: original})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action == core.ActionRedact {
		t.Fatal("MLCascade must never redact")
	}
	if string(response.Body) != string(original) {
		t.Fatalf("body mutated: got %q, want %q", response.Body, original)
	}
}

func TestMLCascadeErrorsOnClassifierFailure(t *testing.T) {
	classifier := &fakeResponseClassifier{err: errors.New("unavailable")}
	cascade, err := NewMLCascade(MLCascadeConfig{JudgeThreshold: 0.55, BlockThreshold: 0.90}, classifier, &fakeResponseJudge{})
	if err != nil {
		t.Fatal(err)
	}
	_, verdict, scanErr := cascade.Scan(context.Background(), core.ModelResponse{})
	if scanErr == nil {
		t.Fatal("expected an error so the outer pipeline can apply its own fail-open/closed policy")
	}
	if verdict.Action != 0 {
		t.Fatalf("expected a zero-value verdict on error, got %#v", verdict)
	}
}

func TestMLCascadeErrorsWhenJudgeMissingOnAmbiguousScore(t *testing.T) {
	classifier := &fakeResponseClassifier{probability: 0.70}
	cascade, err := NewMLCascade(MLCascadeConfig{JudgeThreshold: 0.55, BlockThreshold: 0.90}, classifier, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, scanErr := cascade.Scan(context.Background(), core.ModelResponse{})
	if scanErr == nil {
		t.Fatal("expected an error when the ambiguous band has no judge to escalate to")
	}
}

func TestMLCascadeInvalidConfig(t *testing.T) {
	classifier := &fakeResponseClassifier{}
	if _, err := NewMLCascade(MLCascadeConfig{JudgeThreshold: 0.9, BlockThreshold: 0.5}, classifier, nil); err == nil {
		t.Fatal("expected an error when judge threshold exceeds block threshold")
	}
	if _, err := NewMLCascade(MLCascadeConfig{}, nil, nil); err == nil {
		t.Fatal("expected an error when classifier is nil")
	}
}

type fakeResponseClassifier struct {
	probability    float64
	err            error
	waitForContext bool
	calls          int
}

func (f *fakeResponseClassifier) Name() string { return "response_classifier" }
func (f *fakeResponseClassifier) Classify(ctx context.Context, _ core.ModelResponse) (core.Classification, error) {
	f.calls++
	if f.waitForContext {
		<-ctx.Done()
		return core.Classification{}, ctx.Err()
	}
	return core.Classification{MaliciousProbability: f.probability}, f.err
}

type fakeResponseJudge struct {
	block bool
	calls int
}

func (f *fakeResponseJudge) Name() string { return "response_judge" }
func (f *fakeResponseJudge) Judge(context.Context, core.ModelResponse) (core.Verdict, error) {
	f.calls++
	if f.block {
		return core.Block(core.Finding{Layer: "response_judge", Code: "malicious_code"}), nil
	}
	return core.Allow(), nil
}
