package notify

import (
	"context"
	"errors"
	"testing"
)

func TestEndpointValidationRespectsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, target := range []string{"https://8.8.8.8/hook", "https://receiver.invalid/hook"} {
		if err := PublicURLAllowedContext(ctx, target); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled endpoint validation: %v", err)
		}
	}
}
