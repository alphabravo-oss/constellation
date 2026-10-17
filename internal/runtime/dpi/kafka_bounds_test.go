package dpi

import (
	"encoding/binary"
	"testing"
)

func TestKafkaFrameBoundaries(t *testing.T) {
	frame := []byte{0, 0, 0, 14, 0, 18, 0, 3, 255, 255, 255, 254, 0, 4, 't', 'e', 's', 't'}
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
		valid  bool
	}{
		{"valid", func(p []byte) []byte { return p }, true},
		{"truncated", func(p []byte) []byte { return p[:16] }, false},
		{"short declared header", func(p []byte) []byte { p[3] = 9; return p }, false},
		{"client crosses declared frame", func(p []byte) []byte { p[3] = 10; return p }, false},
		{"invalid negative client length", func(p []byte) []byte { p[12] = 255; p[13] = 254; return p }, false},
		{"null client", func(p []byte) []byte { p[12] = 255; p[13] = 255; return p }, true},
		{"negative API key", func(p []byte) []byte { p[4] = 255; p[5] = 255; return p }, false},
		{"invalid UTF8 client", func(p []byte) []byte { p[14] = 255; return p }, false},
		{"coalesced frames", func(p []byte) []byte { return append(p, frame...) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := parseKafka(Flow{}, DirRequest, tc.change(append([]byte(nil), frame...)))
			if (event != nil) != tc.valid {
				t.Fatalf("valid=%v, event=%+v", tc.valid, event)
			}
			if event != nil && event.Kafka.Correlation != -2 {
				t.Fatal("signed correlation changed")
			}
		})
	}
	for _, tc := range []struct {
		wire uint32
		want int32
	}{{0x80000000, -2147483648}, {0x7fffffff, 2147483647}} {
		binary.BigEndian.PutUint32(frame[8:12], tc.wire)
		event := parseKafka(Flow{}, DirRequest, frame)
		if event == nil || event.Kafka.Correlation != tc.want {
			t.Fatalf("signed correlation %x not preserved", tc.wire)
		}
	}
}
