//go:build !linux

package quarantine

import (
	"context"
	"errors"
)

// ReadProcSnapshot returns an unsupported-platform error on non-Linux platforms.
func ReadProcSnapshot(_ context.Context, _ int) (map[string][]byte, error) {
	return nil, errors.New("quarantine: procfs snapshot is Linux-only")
}
