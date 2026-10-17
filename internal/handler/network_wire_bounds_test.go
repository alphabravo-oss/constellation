package handler

import (
	"math"
	"testing"
)

func TestNetworkApplicationIDNativeRange(t *testing.T) {
	for _, value := range []uint32{0, 1, 1001, 2028, math.MaxUint16} {
		got, ok := NetworkApplicationID(value)
		if !ok || int64(got) != int64(value) {
			t.Errorf("application %d became %d, valid=%v", value, got, ok)
		}
	}
	for _, value := range []uint32{math.MaxUint16 + 1, math.MaxInt32, math.MaxInt32 + 1, math.MaxUint32} {
		if got, ok := NetworkApplicationID(value); ok || got != 0 {
			t.Errorf("unsupported application %d accepted as %d", value, got)
		}
	}
}
