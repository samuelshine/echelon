package core

import "testing"

func TestUsageTotalTokens(t *testing.T) {
	usage := Usage{InputTokens: 13, OutputTokens: 21}
	if got := usage.TotalTokens(); got != 34 {
		t.Fatalf("TotalTokens() = %d, want 34", got)
	}
}

func TestBlockRetainsFindings(t *testing.T) {
	finding := Finding{Layer: "heuristic", Code: "instruction_override", Confidence: 1}
	verdict := Block(finding)
	if verdict.Action != ActionBlock || len(verdict.Findings) != 1 {
		t.Fatalf("unexpected verdict: %#v", verdict)
	}
}
