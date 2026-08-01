package egress

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jscyril/echelon/internal/core"
)

var ErrInvalidMLCascadeConfig = errors.New("invalid egress ML cascade configuration")

// responseClassifier/responseJudge are the egress-side analogs of
// ports.PromptClassifier/ports.PromptJudge, operating on core.ModelResponse
// instead of core.Prompt.
type responseClassifier interface {
	Name() string
	Classify(ctx context.Context, response core.ModelResponse) (core.Classification, error)
}

type responseJudge interface {
	Name() string
	Judge(ctx context.Context, response core.ModelResponse) (core.Verdict, error)
}

type MLCascadeConfig struct {
	ClassifierTimeout time.Duration
	JudgeTimeout      time.Duration
	JudgeThreshold    float64
	BlockThreshold    float64
}

// MLCascade is a ports.EgressScanner: classifier -> (allow | escalate to judge |
// block), the same three-band gating ingress.Cascade uses, reused here because
// the response-relevant categories (toxicity_harm, malicious_code) need the same
// judge-adjudicates-the-ambiguous-band treatment ingress already relies on. Never
// redacts — only allows or blocks, so it never mutates response.Body.
type MLCascade struct {
	config     MLCascadeConfig
	classifier responseClassifier
	judge      responseJudge
}

func NewMLCascade(config MLCascadeConfig, classifier responseClassifier, judge responseJudge) (*MLCascade, error) {
	if classifier == nil {
		return nil, fmt.Errorf("%w: classifier is required", ErrInvalidMLCascadeConfig)
	}
	if config.JudgeThreshold < 0 || config.JudgeThreshold > 1 ||
		config.BlockThreshold < 0 || config.BlockThreshold > 1 ||
		config.JudgeThreshold > config.BlockThreshold {
		return nil, fmt.Errorf("%w: thresholds must satisfy 0 <= judge <= block <= 1", ErrInvalidMLCascadeConfig)
	}
	return &MLCascade{config: config, classifier: classifier, judge: judge}, nil
}

func (c *MLCascade) Name() string { return "response_classifier" }

func (c *MLCascade) Scan(ctx context.Context, response core.ModelResponse) (core.ModelResponse, core.Verdict, error) {
	started := time.Now()

	classification, err := classifyWithTimeout(ctx, c.config.ClassifierTimeout, func(stageCtx context.Context) (core.Classification, error) {
		return c.classifier.Classify(stageCtx, response)
	})
	if err != nil {
		return response, core.Verdict{}, fmt.Errorf("%s: %w", c.classifier.Name(), err)
	}
	probability := classification.MaliciousProbability
	if probability < 0 || probability > 1 {
		return response, core.Verdict{}, fmt.Errorf("%s: malicious probability %f is outside [0,1]", c.classifier.Name(), probability)
	}

	topCategory, topScore := "malicious_code", 0.0
	for category, score := range classification.Labels {
		if score > topScore {
			topCategory, topScore = category, score
		}
	}
	finding := core.Finding{
		Layer: c.classifier.Name(), Code: topCategory,
		Message: "response classifier detected policy-relevant content", Confidence: probability,
	}
	if probability >= c.config.BlockThreshold {
		blocked := core.Block(finding)
		blocked.Duration = time.Since(started)
		return response, blocked, nil
	}
	if probability < c.config.JudgeThreshold {
		allowed := core.Allow()
		allowed.Duration = time.Since(started)
		return response, allowed, nil
	}
	if c.judge == nil {
		return response, core.Verdict{}, fmt.Errorf("response_judge: ambiguous classification requires an unavailable judge")
	}

	verdict, err := judgeWithTimeout(ctx, c.config.JudgeTimeout, func(stageCtx context.Context) (core.Verdict, error) {
		return c.judge.Judge(stageCtx, response)
	})
	if err != nil {
		return response, core.Verdict{}, fmt.Errorf("%s: %w", c.judge.Name(), err)
	}
	verdict.Duration = time.Since(started)
	return response, verdict, nil
}

func classifyWithTimeout(ctx context.Context, timeout time.Duration, fn func(context.Context) (core.Classification, error)) (core.Classification, error) {
	stageCtx, cancel := scannerContext(ctx, timeout)
	defer cancel()
	return fn(stageCtx)
}

func judgeWithTimeout(ctx context.Context, timeout time.Duration, fn func(context.Context) (core.Verdict, error)) (core.Verdict, error) {
	stageCtx, cancel := scannerContext(ctx, timeout)
	defer cancel()
	return fn(stageCtx)
}
