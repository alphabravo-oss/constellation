package scanner

import (
	"context"
	"errors"
	"testing"
)

func TestArtifactTargetValidationRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, target := range []string{"https://8.8.8.8/artifact.zip", "https://artifact.invalid/bundle.zip"} {
		if err := guardServerlessTarget(ctx, target); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled target validation: %v", err)
		}
	}
}
