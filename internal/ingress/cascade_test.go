package ingress

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jscyril/echelon/internal/core"
)

func TestCascadeGating(t *testing.T) {
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
			classifier := &fakeClassifier{probability: tt.probability}
			judge := &fakeJudge{block: tt.judgeBlock}
			cascade, err := NewCascade(CascadeConfig{
				JudgeThreshold: 0.55, BlockThreshold: 0.90, FailClosed: true,
			}, allowLayer{}, classifier, judge)
			if err != nil {
				t.Fatal(err)
			}
			verdict, err := cascade.Evaluate(context.Background(), core.Prompt{Text: "test"})
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

func TestCascadeShortCircuitsAfterHeuristicBlock(t *testing.T) {
	classifier := &fakeClassifier{probability: 0.99}
	cascade, err := NewCascade(CascadeConfig{JudgeThreshold: 0.5, BlockThreshold: 0.9}, blockLayer{}, classifier, &fakeJudge{})
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := cascade.Evaluate(context.Background(), core.Prompt{Text: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionBlock || classifier.calls != 0 {
		t.Fatalf("unexpected result: verdict=%#v classifier_calls=%d", verdict, classifier.calls)
	}
}

func TestCascadeFailsClosedOnClassifierTimeout(t *testing.T) {
	classifier := &fakeClassifier{waitForContext: true}
	cascade, err := NewCascade(CascadeConfig{
		ClassifierTimeout: time.Millisecond,
		JudgeThreshold:    0.5, BlockThreshold: 0.9, FailClosed: true,
	}, allowLayer{}, classifier, &fakeJudge{})
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := cascade.Evaluate(context.Background(), core.Prompt{Text: "test"})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if verdict.Action != core.ActionBlock || verdict.Findings[0].Code != "security_layer_unavailable" {
		t.Fatalf("unexpected fail-closed verdict: %#v", verdict)
	}
}

func TestCascadeFailsOpenWhenConfigured(t *testing.T) {
	classifier := &fakeClassifier{err: errors.New("unavailable")}
	cascade, err := NewCascade(CascadeConfig{
		JudgeThreshold: 0.5, BlockThreshold: 0.9, FailClosed: false,
	}, allowLayer{}, classifier, &fakeJudge{})
	if err != nil {
		t.Fatal(err)
	}
	verdict, evalErr := cascade.Evaluate(context.Background(), core.Prompt{Text: "test"})
	if evalErr == nil {
		t.Fatal("expected operational error for observability")
	}
	if verdict.Action != core.ActionAllow {
		t.Fatalf("unexpected fail-open verdict: %#v", verdict)
	}
}

type allowLayer struct{}

func (allowLayer) Name() string { return "allow" }
func (allowLayer) Evaluate(context.Context, core.Prompt) (core.Verdict, error) {
	return core.Allow(), nil
}

type blockLayer struct{}

func (blockLayer) Name() string { return "block" }
func (blockLayer) Evaluate(context.Context, core.Prompt) (core.Verdict, error) {
	return core.Block(core.Finding{Layer: "block", Code: "blocked"}), nil
}

type fakeClassifier struct {
	probability    float64
	err            error
	waitForContext bool
	calls          int
}

func (f *fakeClassifier) Name() string { return "classifier" }
func (f *fakeClassifier) Classify(ctx context.Context, _ core.Prompt) (core.Classification, error) {
	f.calls++
	if f.waitForContext {
		<-ctx.Done()
		return core.Classification{}, ctx.Err()
	}
	return core.Classification{MaliciousProbability: f.probability}, f.err
}

type fakeJudge struct {
	block bool
	calls int
}

func (f *fakeJudge) Name() string { return "judge" }
func (f *fakeJudge) Judge(context.Context, core.Prompt) (core.Verdict, error) {
	f.calls++
	if f.block {
		return core.Block(core.Finding{Layer: "judge", Code: "malicious"}), nil
	}
	return core.Allow(), nil
}
