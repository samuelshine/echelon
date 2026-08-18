package ingress

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jscyril/echelon/internal/core"
)

// confidence describes how much weight a matched rule's verdict carries.
//
// The distinction exists because regexes cannot read intent. A structural
// marker (an injected `system:` turn, a `<system>` tag) is an artifact of the
// prompt's *form*: legitimate user text essentially never contains one, so
// matching it is near-conclusive and blocking immediately is both safe and
// free. A lexical pattern matches *vocabulary* -- and the exact words an
// attacker uses to override instructions are also the words a security analyst,
// policy author, or support agent uses to discuss doing so ("our policy says to
// disregard previous instructions from unverified senders -- how do we handle
// that?"). Blocking those outright is how a firewall ends up rejecting the
// legitimate security work it exists to protect.
type confidence int

const (
	// structural: form-based evidence, conclusive on its own -> block here.
	structural confidence = iota
	// lexical: vocabulary-based evidence, ambiguous without intent -> escalate
	// to the LLM judge, which sees this finding plus the classifier's scores
	// and can weigh them against what the text is actually asking for.
	lexical
)

type rule struct {
	code       string
	confidence confidence
	expression *regexp.Regexp
}

// Heuristic is the first, local-only ingress layer. All expressions are
// compiled at construction time; Evaluate performs no compilation or I/O.
type Heuristic struct {
	rules []rule
}

func NewHeuristic() *Heuristic {
	return &Heuristic{rules: []rule{
		{code: "instruction_override", confidence: lexical, expression: regexp.MustCompile(`\b(ignore|forget|disregard|override)\b.{0,96}\b(previous|prior|above|system|developer)\b.{0,96}\b(instruction|prompt|message|rule)s?\b`)},
		{code: "system_prompt_exfiltration", confidence: lexical, expression: regexp.MustCompile(`\b(reveal|print|show|dump|repeat|exfiltrate)\b.{0,96}\b(system|developer|hidden)\b.{0,96}\b(prompt|message|instruction|policy)s?\b`)},
		{code: "jailbreak_persona", confidence: lexical, expression: regexp.MustCompile(`\b(do anything now|developer mode|jailbreak|unrestricted mode)\b`)},
		{code: "role_delimiter_injection", confidence: structural, expression: regexp.MustCompile(`(?m)(^|\n)\s*(system|developer)\s*:\s*`)},
		{code: "prompt_markup_injection", confidence: structural, expression: regexp.MustCompile(`(?i)<\/?(system|developer|instructions?|prompt)>|\[\/?(system|developer|instructions?)\]`)},
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
			finding := core.Finding{
				Layer:      h.Name(),
				Code:       h.rules[i].code,
				Message:    "prompt matched a known injection structure",
				Confidence: 1,
			}
			var verdict core.Verdict
			if h.rules[i].confidence == structural {
				verdict = core.Block(finding)
			} else {
				// Escalate rather than decide: the cascade routes an ActionEscalate
				// verdict to the LLM judge, carrying this finding as evidence.
				finding.Message = "prompt matched a context-dependent injection pattern"
				finding.Confidence = 0.5
				verdict = core.Escalate(finding)
			}
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
