package handler

import (
	"fmt"
	"math"
)

// NetworkApplicationID validates the native DP application field before it is
// persisted in PostgreSQL INTEGER. Connection and threat records both carry a
// uint16 application, even though legacy HTTP DTOs use uint32. Zero is unknown.
func NetworkApplicationID(value uint32) (int32, bool) {
	if value > math.MaxUint16 {
		return 0, false
	}
	return int32(value), true
}

// NetworkThreatID checks the canonical unsigned wire range before name lookup.
// Stored IDs use int64 so the full uint32 range survives PostgreSQL and JSON.
func NetworkThreatID(value int64) (uint32, bool) {
	if value < 0 || value > math.MaxUint32 {
		return 0, false
	}
	return uint32(value), true
}

// NetworkThreatName preserves unknown IDs instead of aliasing a signed cast.
func NetworkThreatName(value int64) string {
	if id, ok := NetworkThreatID(value); ok {
		if name := NeuVectorThreatName(id); name != "" {
			return name
		}
	}
	return fmt.Sprintf("signature %d", value)
}
