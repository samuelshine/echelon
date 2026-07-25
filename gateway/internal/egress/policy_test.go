package egress

import (
	"context"
	"testing"

	"github.com/jscyril/echelon/internal/core"
)

func TestPolicyScannerBlocksCanary(t *testing.T) {
	scanner := NewPolicyScanner("[SYSTEM_CANARY]")
	_, verdict, err := scanner.Scan(context.Background(), core.ModelResponse{Body: []byte(`{"content":"[SYSTEM_CANARY]"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionBlock || verdict.Findings[0].Code != "system_prompt_leakage" {
		t.Fatalf("unexpected verdict: %#v", verdict)
	}
}
