package scanner

import (
	"context"
	"errors"
	"testing"
)

func TestArtifactTargetValidationRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, target := range []string{"8.8.8.8", "artifact.invalid"} {
		if _, err := defaultArtifactDialer().addresses(ctx, target); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled target validation: %v", err)
		}
	}
}
