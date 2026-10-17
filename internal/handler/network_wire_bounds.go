package handler

import "math"

// NetworkApplicationID validates the native DP application field before it is
// persisted in PostgreSQL INTEGER. Connection and threat records both carry a
// uint16 application, even though legacy HTTP DTOs use uint32. Zero is unknown.
func NetworkApplicationID(value uint32) (int32, bool) {
	if value > math.MaxUint16 {
		return 0, false
	}
	return int32(value), true
}
