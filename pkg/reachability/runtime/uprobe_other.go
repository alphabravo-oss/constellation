//go:build !linux

package runtime

func attachUprobe(_, _ string, _ func()) (Detacher, error) {
	return nil, ErrUnsupported
}
