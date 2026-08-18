// Package ingress implements the gated prompt-security cascade.
package ingress

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/jscyril/echelon/internal/core"
	"github.com/jscyril/echelon/internal/ports"
)

var ErrInvalidCascadeConfig = errors.New("invalid ingress cascade configuration")

type CascadeConfig struct {
	HeuristicTimeout  time.Duration
	ClassifierTimeout time.Duration
	JudgeTimeout      time.Duration
	JudgeThreshold    float64
	BlockThreshold    float64
	// CertainBlockThreshold is the score above which the classifier may block
	// WITHOUT consulting the judge. Between BlockThreshold and this value the
	// classifier's opinion is treated as strong evidence rather than a verdict
	// and is sent to the judge for adjudication.
	//
	// This exists because the classifier is measurably weakest on exactly the
	// text it most often over-flags: legitimate defensive-security work. An
	// external sweep of published benchmarks found every benign false positive
	// came from the classifier hard-blocking without a judge -- "design a
	// tabletop exercise around an adversary using SMB/Windows Admin Shares",
	// "what log sources would I need to alert on Modify Authentication Process".
	// The judge clears these when asked; it simply was never asked.
	//
	// Zero means "always adjudicate when a judge exists", which is the safe
	// default. Set it below 1 only to cap judge load on unambiguous attacks.
	CertainBlockThreshold float64
	FailClosed            bool
}

type Cascade struct {
	config     CascadeConfig
	heuristic  ports.IngressLayer
	classifier ports.PromptClassifier
	judge      ports.PromptJudge
	// judgeThreshold/blockThreshold are the *live* values, mutable at runtime via
	// SetThresholds and read lock-free by Evaluate. They hold math.Float64bits so
	// a concurrent read during request handling is safe. The frozen copies on
	// config are retained only for the other (read-only) config fields.
	judgeThreshold atomic.Uint64
	blockThreshold atomic.Uint64
}

func NewCascade(config CascadeConfig, heuristic ports.IngressLayer, classifier ports.PromptClassifier, judge ports.PromptJudge) (*Cascade, error) {
	if heuristic == nil {
		return nil, fmt.Errorf("%w: heuristic layer is required", ErrInvalidCascadeConfig)
	}
	if !validThresholds(config.JudgeThreshold, config.BlockThreshold) {
		return nil, fmt.Errorf("%w: thresholds must satisfy 0 <= judge <= block <= 1", ErrInvalidCascadeConfig)
	}
	c := &Cascade{config: config, heuristic: heuristic, classifier: classifier, judge: judge}
	c.judgeThreshold.Store(math.Float64bits(config.JudgeThreshold))
	c.blockThreshold.Store(math.Float64bits(config.BlockThreshold))
	return c, nil
}

func validThresholds(judge, block float64) bool {
	return judge >= 0 && judge <= 1 && block >= 0 && block <= 1 && judge <= block
}

// Thresholds returns the current live judge/block thresholds.
func (c *Cascade) Thresholds() (judgeThreshold, blockThreshold float64) {
	return math.Float64frombits(c.judgeThreshold.Load()), math.Float64frombits(c.blockThreshold.Load())
}

// SetThresholds atomically swaps the live judge/block thresholds after applying
// the same validation NewCascade does. It returns ErrInvalidCascadeConfig
// without mutating anything when the new values are out of range.
func (c *Cascade) SetThresholds(judgeThreshold, blockThreshold float64) error {
	if !validThresholds(judgeThreshold, blockThreshold) {
		return fmt.Errorf("%w: thresholds must satisfy 0 <= judge <= block <= 1", ErrInvalidCascadeConfig)
	}
	c.judgeThreshold.Store(math.Float64bits(judgeThreshold))
	c.blockThreshold.Store(math.Float64bits(blockThreshold))
	return nil
}

func (c *Cascade) Name() string { return "ingress_cascade" }

func (c *Cascade) Evaluate(ctx context.Context, prompt core.Prompt) (core.Verdict, error) {
	started := time.Now()

	verdict, err := evaluateWithTimeout(ctx, c.config.HeuristicTimeout, func(stageCtx context.Context) (core.Verdict, error) {
		return c.heuristic.Evaluate(stageCtx, prompt)
	})
	if err != nil {
		return c.stageFailure("heuristic", started, err)
	}
	if verdict.Action == core.ActionBlock {
		verdict.Duration = time.Since(started)
		return verdict, nil
	}
	// A lexical heuristic hit is evidence, not a verdict: carry it forward so the
	// judge can weigh it, and remember that it fired so an ambiguous-but-flagged
	// prompt still reaches the judge even when the classifier scores it low.
	heuristicEvidence := []core.Finding(nil)
	if verdict.Action == core.ActionEscalate {
		heuristicEvidence = verdict.Findings
	}
	if c.classifier == nil {
		// No classifier to corroborate with. Without a judge there is nothing left
		// that can read intent, so fail safe on the evidence we have.
		if len(heuristicEvidence) > 0 {
			resolved, err := c.adjudicate(ctx, prompt, heuristicEvidence, started)
			return resolved, err
		}
		verdict.Duration = time.Since(started)
		return verdict, nil
	}

	classification, err := classifyWithTimeout(ctx, c.config.ClassifierTimeout, func(stageCtx context.Context) (core.Classification, error) {
		return c.classifier.Classify(stageCtx, prompt)
	})
	if err != nil {
		return c.stageFailure(c.classifier.Name(), started, err)
	}
	probability := classification.MaliciousProbability
	if probability < 0 || probability > 1 {
		return c.stageFailure(c.classifier.Name(), started, fmt.Errorf("malicious probability %f is outside [0,1]", probability))
	}

	finding := core.Finding{
		Layer: c.classifier.Name(), Code: "semantic_prompt_injection",
		Message: "semantic classifier detected malicious intent", Confidence: probability,
	}
	judgeThreshold, blockThreshold := c.Thresholds()
	if probability >= blockThreshold {
		// Certain enough to act alone, or no judge available to ask: block here.
		certain := c.config.CertainBlockThreshold > 0 && probability >= c.config.CertainBlockThreshold
		if certain || c.judge == nil {
			blocked := core.Block(append(heuristicEvidence, finding)...)
			blocked.Duration = time.Since(started)
			return blocked, nil
		}
		// Otherwise the classifier proposes and the judge disposes, exactly as a
		// lexical heuristic hit does. A high score is strong evidence of intent,
		// not proof of it.
		return c.adjudicate(ctx, prompt, append(heuristicEvidence, finding), started)
	}
	if probability < judgeThreshold && len(heuristicEvidence) == 0 {
		allowed := core.Allow()
		allowed.Duration = time.Since(started)
		return allowed, nil
	}
	// Either the classifier is uncertain, or the heuristic flagged something the
	// classifier did not corroborate. Both are exactly the "needs intent" case.
	evidence := heuristicEvidence
	if probability >= judgeThreshold {
		evidence = append(evidence, finding)
	}
	return c.adjudicate(ctx, prompt, evidence, started)
}

// adjudicate hands the accumulated evidence to the LLM judge, which is the only
// layer that can read intent. The judge's own verdict decides; the evidence that
// got us here is preserved on a block so telemetry still shows which layer first
// flagged the prompt. When no judge is configured this fails per the pipeline's
// fail-closed setting rather than silently allowing flagged text through.
func (c *Cascade) adjudicate(ctx context.Context, prompt core.Prompt, evidence []core.Finding, started time.Time) (core.Verdict, error) {
	if c.judge == nil {
		return c.stageFailure("llm_judge", started, errors.New("ambiguous classification requires an unavailable judge"))
	}
	verdict, err := evaluateWithTimeout(ctx, c.config.JudgeTimeout, func(stageCtx context.Context) (core.Verdict, error) {
		return c.judge.Judge(stageCtx, prompt)
	})
	if err != nil {
		return c.stageFailure(c.judge.Name(), started, err)
	}
	if verdict.Action == core.ActionBlock {
		verdict.Findings = append(append([]core.Finding(nil), evidence...), verdict.Findings...)
	}
	verdict.Duration = time.Since(started)
	return verdict, nil
}

func (c *Cascade) stageFailure(layer string, started time.Time, err error) (core.Verdict, error) {
	if !c.config.FailClosed {
		allowed := core.Allow()
		allowed.Duration = time.Since(started)
		return allowed, fmt.Errorf("%s: %w", layer, err)
	}
	blocked := core.Block(core.Finding{
		Layer: layer, Code: "security_layer_unavailable",
		Message: "security evaluation could not be completed",
	})
	blocked.Duration = time.Since(started)
	return blocked, fmt.Errorf("%s: %w", layer, err)
}

func evaluateWithTimeout(ctx context.Context, timeout time.Duration, fn func(context.Context) (core.Verdict, error)) (core.Verdict, error) {
	stageCtx, cancel := stageContext(ctx, timeout)
	defer cancel()
	return fn(stageCtx)
}

func classifyWithTimeout(ctx context.Context, timeout time.Duration, fn func(context.Context) (core.Classification, error)) (core.Classification, error) {
	stageCtx, cancel := stageContext(ctx, timeout)
	defer cancel()
	return fn(stageCtx)
}

func stageContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}
