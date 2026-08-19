//go:build !linux || !cgo

package dpi

import (
	"context"
	"errors"
)

// SourceConfig is the platform-independent config for the inline kernel source.
// On non-Linux / no-cgo builds the source returns unsupported-platform errors.
type SourceConfig struct {
	QueueNum     uint16
	MaxPacketLen uint32
}

// Source is the NFQUEUE / pcap inline source. The real Linux implementation lives in
// source_linux.go behind build tags; this fallback returns errors so the package builds
// and tests run on any platform.
type Source struct{}

// NewSource returns an unsupported-platform error when nfqueue support is unavailable.
func NewSource(_ *Engine, _ SourceConfig) (*Source, error) {
	return nil, errors.New("dpi: NFQUEUE source requires linux + cgo")
}

// Run is a no-op.
func (*Source) Run(_ context.Context) error {
	return errors.New("dpi: NFQUEUE source not supported on this platform")
}

// Close is a no-op.
func (*Source) Close() error { return nil }
