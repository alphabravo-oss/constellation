//go:build !linux

package ebpf

import "errors"

// newLoader on non-Linux always returns ErrUnsupported. The Agent treats this as
// degraded mode rather than a fatal error.
func newLoader(_ Options) (loader, error) {
	return nil, errors.New("ebpf: not supported on non-linux")
}
