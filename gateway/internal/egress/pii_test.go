package egress

import (
	"context"
	"strings"
	"testing"

	"github.com/jscyril/echelon/internal/core"
)

func TestPIIScannerMasksSupportedEntities(t *testing.T) {
	scanner := NewPIIScanner(PIIMask)
	response := core.ModelResponse{Body: []byte(`{"email":"user@example.com","ssn":"123-45-6789","card":"4111 1111 1111 1111"}`)}
	output, verdict, err := scanner.Scan(context.Background(), response)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionRedact || len(verdict.Findings) != 3 {
		t.Fatalf("unexpected verdict: %#v", verdict)
	}
	for _, sensitive := range []string{"user@example.com", "123-45-6789", "4111 1111 1111 1111"} {
		if strings.Contains(string(output.Body), sensitive) {
			t.Fatalf("output retained %q: %s", sensitive, output.Body)
		}
	}
	if string(response.Body) == string(output.Body) {
		t.Fatal("expected replacement response body")
	}
}

func TestPIIScannerIgnoresInvalidPaymentCardCandidate(t *testing.T) {
	scanner := NewPIIScanner(PIIMask)
	response := core.ModelResponse{Body: []byte(`{"number":"1234 5678 9012 3456"}`)}
	output, verdict, err := scanner.Scan(context.Background(), response)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionAllow || string(output.Body) != string(response.Body) {
		t.Fatalf("unexpected invalid-card result: output=%s verdict=%#v", output.Body, verdict)
	}
}

func TestPIIScannerBlockModeDoesNotMutateResponse(t *testing.T) {
	scanner := NewPIIScanner(PIIBlock)
	response := core.ModelResponse{Body: []byte(`{"email":"user@example.com"}`)}
	output, verdict, err := scanner.Scan(context.Background(), response)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionBlock || string(output.Body) != string(response.Body) {
		t.Fatalf("unexpected block result: output=%s verdict=%#v", output.Body, verdict)
	}
}

// TestPIIFindingsRecordRedactNotBlock pins a console-accuracy bug: the egress
// pipeline accumulates findings from several scanners and returns ONE verdict,
// so telemetry used to label every finding with the request's final outcome.
// A response where PII was masked and a later scanner blocked showed up as
// "PII . block" -- claiming the PII scanner rejected a response it had actually
// cleaned and passed on. Findings now carry what their own layer decided.
func TestPIIFindingsRecordRedactNotBlock(t *testing.T) {
	scanner := NewPIIScanner(PIIMask)
	response := core.ModelResponse{Body: []byte(`{"email":"user@example.com"}`)}
	_, verdict, err := scanner.Scan(context.Background(), response)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionRedact {
		t.Fatalf("verdict action = %v, want redact", verdict.Action)
	}
	if len(verdict.Findings) == 0 {
		t.Fatal("no findings recorded")
	}
	for _, f := range verdict.Findings {
		if f.Action != core.ActionRedact {
			t.Errorf("finding %q action = %v, want redact: mask mode cleans the "+
				"response and lets it through, it does not block", f.Code, f.Action)
		}
	}
}

func TestPIIFindingsRecordBlockInBlockMode(t *testing.T) {
	scanner := NewPIIScanner(PIIBlock)
	response := core.ModelResponse{Body: []byte(`{"email":"user@example.com"}`)}
	_, verdict, err := scanner.Scan(context.Background(), response)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != core.ActionBlock {
		t.Fatalf("verdict action = %v, want block", verdict.Action)
	}
	for _, f := range verdict.Findings {
		if f.Action != core.ActionBlock {
			t.Errorf("finding %q action = %v, want block", f.Code, f.Action)
		}
	}
}
