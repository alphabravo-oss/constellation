package main

import (
	"math"
	"syscall"
	"testing"
)

func TestScannerCacheFreeBytesRejectsUnrepresentableCapacity(t *testing.T) {
	for _, tc := range []struct {
		name      string
		blocks    uint64
		blockSize int64
		want      int64
		valid     bool
	}{
		{"empty", 0, 4096, 0, true},
		{"ordinary", 12, 4096, 49152, true},
		{"maximum", math.MaxInt64, 1, math.MaxInt64, true},
		{"signed block overflow", math.MaxUint64, 1, 0, false},
		{"product overflow", math.MaxInt64/4096 + 1, 4096, 0, false},
		{"zero block size", 1, 0, 0, false},
		{"negative block size", 1, -1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, valid := scannerCacheFreeBytes(syscall.Statfs_t{Bavail: tc.blocks, Bsize: tc.blockSize})
			if got != tc.want || valid != tc.valid {
				t.Fatalf("capacity = (%d, %v), want (%d, %v)", got, valid, tc.want, tc.valid)
			}
		})
	}
}
