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
