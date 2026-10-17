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

func TestNetworkThreatIDUnsignedRange(t *testing.T) {
	for _, value := range []int64{0, 1, math.MaxInt32, math.MaxInt32 + 1, math.MaxUint32} {
		got, ok := NetworkThreatID(value)
		if !ok || int64(got) != value {
			t.Fatalf("ID %d => %d/%v", value, got, ok)
		}
	}
	for _, value := range []int64{-1, math.MinInt32, math.MaxUint32 + 1} {
		if _, ok := NetworkThreatID(value); ok {
			t.Fatalf("invalid ID %d", value)
		}
	}
}
