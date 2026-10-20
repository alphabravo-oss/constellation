//go:build linux

package ebpf

import (
	"math"
	"os"
	"strings"
	"testing"
)

func TestRingBufferSizeBoundsAndDefault(t *testing.T) {
	t.Parallel()
	for _, value := range []int{0, os.Getpagesize(), 256 << 10, 1 << 30} {
		size, err := validatedRingBufferSize(value)
		expected := value
		if value == 0 {
			expected = 256 << 10
		}
		if err != nil || int64(size) != int64(expected) {
			t.Fatalf("size=%d -> %d err=%v", value, size, err)
		}
	}
	invalid := []int{-1, 1, os.Getpagesize() + 1, 3 * os.Getpagesize(), math.MaxInt}
	if int64(math.MaxInt) > math.MaxUint32 {
		overflow := int64(math.MaxUint32) + 1
		invalid = append(invalid, int(overflow))
	}
	for _, value := range invalid {
		if size, err := validatedRingBufferSize(value); err == nil || size != 0 {
			t.Fatalf("invalid size=%d -> %d err=%v", value, size, err)
		}
		if _, err := newLoader(Options{RingBufferSize: value}); err == nil || !strings.Contains(err.Error(), "ring buffer size") {
			t.Fatalf("invalid size=%d reached kernel/object setup: %v", value, err)
		}
	}
}
