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

// escalateLayer stands in for the real heuristic's lexical-match path.
type escalateLayer struct{}

func (escalateLayer) Name() string { return "heuristic" }
func (escalateLayer) Evaluate(context.Context, core.Prompt) (core.Verdict, error) {
	return core.Escalate(core.Finding{
		Layer: "heuristic", Code: "instruction_override", Confidence: 0.5,
	}), nil
}

// TestLexicalHeuristicHitReachesTheJudge is the regression test for the
// architecture fix: a context-dependent heuristic match used to terminate the
// request with a hard block, so the LLM judge -- the only layer that can read
// intent -- never saw it. Legitimate security discussion that happens to use
// attack vocabulary was rejected with no possibility of appeal.
func TestLexicalHeuristicHitReachesTheJudge(t *testing.T) {
	// Classifier scores it BELOW the judge threshold: on its own this prompt
	// would have been allowed outright. The heuristic's evidence is the only
	// reason it warrants a look, which is exactly the case that used to be
	// decided by regex alone.
	classifier := &fakeClassifier{probability: 0.01}
	judge := &fakeJudge{block: false}
	cascade, err := NewCascade(CascadeConfig{JudgeThreshold: 0.4, BlockThreshold: 0.9},
		escalateLayer{}, classifier, judge)
	if err != nil {
		t.Fatal(err)
	}

	verdict, err := cascade.Evaluate(context.Background(), core.Prompt{Text: "irrelevant"})
	if err != nil {
		t.Fatal(err)
	}
	if judge.calls != 1 {
		t.Fatalf("judge called %d times, want 1 -- a lexical heuristic hit must be "+
			"adjudicated, not decided by the regex", judge.calls)
	}
	if verdict.Action != core.ActionAllow {
		t.Fatalf("action = %v, want allow: the judge cleared it, so the cascade must "+
			"honour that over the heuristic's suspicion (%#v)", verdict.Action, verdict)
	}
}

// TestLexicalHeuristicHitBlocksWhenTheJudgeAgrees proves the escalation is a
// real adjudication, not a bypass: the same evidence blocks when the judge
// rules against it, and the heuristic's finding is preserved for telemetry.
func TestLexicalHeuristicHitBlocksWhenTheJudgeAgrees(t *testing.T) {
	classifier := &fakeClassifier{probability: 0.01}
	judge := &fakeJudge{block: true}
	cascade, err := NewCascade(CascadeConfig{JudgeThreshold: 0.4, BlockThreshold: 0.9},
		escalateLayer{}, classifier, judge)
	if err != nil {
		t.Fatal(err)
	}

	verdict, err := cascade.Evaluate(context.Background(), core.Prompt{Text: "irrelevant"})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionBlock {
		t.Fatalf("action = %v, want block", verdict.Action)
	}
	var sawHeuristic, sawJudge bool
	for _, f := range verdict.Findings {
		switch f.Layer {
		case "heuristic":
			sawHeuristic = true
		case "judge":
			sawJudge = true
		}
	}
	if !sawHeuristic {
		t.Error("heuristic finding lost: telemetry must still show which layer first flagged it")
	}
	if !sawJudge {
		t.Error("judge finding missing from the block verdict")
	}
}

// TestEscalateNeverEscapesTheCascade guards the invariant that makes
// ActionEscalate safe to add: it is internal, and must always be resolved into
// a terminal action before Evaluate returns. A leak would reach the gateway's
// response path, which only understands allow/block/redact.
func TestEscalateNeverEscapesTheCascade(t *testing.T) {
	for _, tc := range []struct {
		name       string
		judgeBlock bool
	}{{"judge_allows", false}, {"judge_blocks", true}} {
		t.Run(tc.name, func(t *testing.T) {
			cascade, err := NewCascade(CascadeConfig{JudgeThreshold: 0.4, BlockThreshold: 0.9},
				escalateLayer{}, &fakeClassifier{probability: 0.01}, &fakeJudge{block: tc.judgeBlock})
			if err != nil {
				t.Fatal(err)
			}
			verdict, err := cascade.Evaluate(context.Background(), core.Prompt{Text: "x"})
			if err != nil {
				t.Fatal(err)
			}
			if verdict.Action == core.ActionEscalate {
				t.Fatal("ActionEscalate escaped the cascade; the gateway cannot interpret it")
			}
		})
	}
}
