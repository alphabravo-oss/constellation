package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Discovery documents and token responses are small JSON documents. Bound the
// decoded HTTP body, including error responses, before accepting any identity.
const maxOIDCResponseBytes = 1 << 20

func readOIDCResponse(response *http.Response, phase string) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, oidcResponseError(phase, "response missing", nil)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, oidcResponseError(phase, "response read failed", readErr)
	}
	if closeErr != nil {
		return nil, oidcResponseError(phase, "response close failed", closeErr)
	}
	if len(body) > maxOIDCResponseBytes {
		return nil, oidcResponseError(phase, "response too large", nil)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: %s status %d", phase, response.StatusCode)
	}
	return body, nil
}

// Never wrap provider response bytes, request URLs, or arbitrary transport
// errors: they can carry credentials. Preserve only standard cancellation
// identity for callers that distinguish cancellation from provider failure.
func oidcResponseError(phase, category string, cause error) error {
	if errors.Is(cause, context.Canceled) {
		return fmt.Errorf("oidc: %s %s: %w", phase, category, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return fmt.Errorf("oidc: %s %s: %w", phase, category, context.DeadlineExceeded)
	}
	return fmt.Errorf("oidc: %s %s", phase, category)
}
