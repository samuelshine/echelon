package upstream

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// buildResponse constructs a raw http.Response from a status code and body.
// The upstream package uses this to return normalised OpenAI responses to the
// gateway handler.
func buildResponse(statusCode int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// wrapProviderError formats a provider's native error response into an
// OpenAI-compatible error shape.
func wrapProviderError(provider string, statusCode int, rawBody []byte) []byte {
	// Attempt to see if it's already an OpenAI error or JSON.
	var parsed any
	if err := json.Unmarshal(rawBody, &parsed); err == nil {
		if asMap, ok := parsed.(map[string]any); ok {
			if _, hasError := asMap["error"]; hasError {
				return rawBody // Already wrapped
			}
		}
	}

	// Not OpenAI shaped, wrap it.
	wrapped := map[string]any{
		"error": map[string]any{
			"message": string(rawBody),
			"type":    provider + "_error",
			"code":    statusCode,
		},
	}
	out, _ := json.Marshal(wrapped)
	return out
}
