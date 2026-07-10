package ingress

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jscyril/echelon/internal/core"
)

type rule struct {
	code       string
	expression *regexp.Regexp
}

// Heuristic is the first, local-only ingress layer. All expressions are
// compiled at construction time; Evaluate performs no compilation or I/O.
type Heuristic struct {
	rules []rule
}

func NewHeuristic() *Heuristic {
	return &Heuristic{rules: []rule{
		{code: "instruction_override", expression: regexp.MustCompile(`\b(ignore|forget|disregard|override)\b.{0,96}\b(previous|prior|above|system|developer)\b.{0,96}\b(instruction|prompt|message|rule)s?\b`)},
		{code: "system_prompt_exfiltration", expression: regexp.MustCompile(`\b(reveal|print|show|dump|repeat|exfiltrate)\b.{0,96}\b(system|developer|hidden)\b.{0,96}\b(prompt|message|instruction|policy)s?\b`)},
		{code: "jailbreak_persona", expression: regexp.MustCompile(`\b(do anything now|developer mode|jailbreak|unrestricted mode)\b`)},
		{code: "role_delimiter_injection", expression: regexp.MustCompile(`(?m)(^|\n)\s*(system|developer)\s*:\s*`)},
		{code: "prompt_markup_injection", expression: regexp.MustCompile(`(?i)<\/?(system|developer|instructions?|prompt)>|\[\/?(system|developer|instructions?)\]`)},
	}}
}

func (h *Heuristic) Name() string { return "heuristic" }

func (h *Heuristic) Evaluate(ctx context.Context, prompt core.Prompt) (core.Verdict, error) {
	started := time.Now()
	text := normalize(prompt.Text)
	if text == "" {
		verdict := core.Allow()
		verdict.Duration = time.Since(started)
		return verdict, nil
	}

	for i := range h.rules {
		if err := ctx.Err(); err != nil {
			return core.Verdict{}, err
		}
		if h.rules[i].expression.MatchString(text) {
			verdict := core.Block(core.Finding{
				Layer:      h.Name(),
				Code:       h.rules[i].code,
				Message:    "prompt matched a known injection structure",
				Confidence: 1,
			})
			verdict.Duration = time.Since(started)
			return verdict, nil
		}
	}

	verdict := core.Allow()
	verdict.Duration = time.Since(started)
	return verdict, nil
}

func normalize(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	pendingSpace := false
	for _, char := range text {
		if unicode.IsSpace(char) {
			pendingSpace = builder.Len() > 0
			continue
		}
		if pendingSpace {
			builder.WriteByte(' ')
			pendingSpace = false
		}
		builder.WriteRune(unicode.ToLower(char))
	}
	return builder.String()
}
