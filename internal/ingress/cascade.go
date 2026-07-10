// Package ingress implements the gated prompt-security cascade.
package ingress

import (
	"context"
	"errors"
	"fmt"
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
	FailClosed        bool
}

type Cascade struct {
	config     CascadeConfig
	heuristic  ports.IngressLayer
	classifier ports.PromptClassifier
	judge      ports.PromptJudge
}

func NewCascade(config CascadeConfig, heuristic ports.IngressLayer, classifier ports.PromptClassifier, judge ports.PromptJudge) (*Cascade, error) {
	if heuristic == nil {
		return nil, fmt.Errorf("%w: heuristic layer is required", ErrInvalidCascadeConfig)
	}
	if config.JudgeThreshold < 0 || config.JudgeThreshold > 1 ||
		config.BlockThreshold < 0 || config.BlockThreshold > 1 ||
		config.JudgeThreshold > config.BlockThreshold {
		return nil, fmt.Errorf("%w: thresholds must satisfy 0 <= judge <= block <= 1", ErrInvalidCascadeConfig)
	}
	return &Cascade{config: config, heuristic: heuristic, classifier: classifier, judge: judge}, nil
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
	if c.classifier == nil {
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
	if probability >= c.config.BlockThreshold {
		blocked := core.Block(finding)
		blocked.Duration = time.Since(started)
		return blocked, nil
	}
	if probability < c.config.JudgeThreshold {
		allowed := core.Allow()
		allowed.Duration = time.Since(started)
		return allowed, nil
	}
	if c.judge == nil {
		return c.stageFailure("llm_judge", started, errors.New("ambiguous classification requires an unavailable judge"))
	}

	verdict, err = evaluateWithTimeout(ctx, c.config.JudgeTimeout, func(stageCtx context.Context) (core.Verdict, error) {
		return c.judge.Judge(stageCtx, prompt)
	})
	if err != nil {
		return c.stageFailure(c.judge.Name(), started, err)
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
