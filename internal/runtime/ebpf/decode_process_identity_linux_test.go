//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestDecodeProcessStartIdentityIsAdditive(t *testing.T) {
	t.Parallel()
	for _, tail := range []int{0, 4, 8} {
		header := int(unsafe.Sizeof(recordHeader{}))
		body := make([]byte, 16+256+256+tail)
		copy(body, "nginx\x00")
		copy(body[16:], "/usr/sbin/nginx\x00")
		if tail == 8 {
			binary.LittleEndian.PutUint64(body[16+256+256:], 12349999999)
		}
		record := make([]byte, header+len(body))
		record[0] = recKindExec
		binary.LittleEndian.PutUint32(record[4:8], 4242)
		copy(record[header:], body)
		event, ok := decodeRecord(record)
		if !ok || event.Process == nil || event.Process.PID != 4242 || event.Process.Comm != "nginx" {
			t.Fatalf("legacy capture broken for tail%d: %+v", tail, event)
		}
		expected := uint64(0)
		if tail == 8 {
			expected = 12349999999
		}
		if event.Process.StartBootNS != expected {
			t.Fatalf("source identity tail%d=%d want%d", tail, event.Process.StartBootNS, expected)
		}
	}
}

func TestDecodeRecordFullCHeaderLayout(t *testing.T) {
	t.Parallel()
	for _, kind := range []byte{recKindExec, recKindFile} {
		record := make([]byte, 40+528)
		record[0] = kind
		binary.LittleEndian.PutUint32(record[4:8], 4242)
		binary.LittleEndian.PutUint32(record[8:12], 123)
		binary.LittleEndian.PutUint32(record[12:16], 1001)
		binary.LittleEndian.PutUint32(record[16:20], 1002)
		// Nonzero padding also ensures the decoder does not treat it as data.
		binary.LittleEndian.PutUint32(record[20:24], 0xdeadbeef)
		binary.LittleEndian.PutUint64(record[24:32], 0x1122334455667788)
		binary.LittleEndian.PutUint64(record[32:40], 0x99aabbccddeeff00)
		var header recordHeader
		if err := binary.Read(bytes.NewReader(record[:40]), binary.LittleEndian, &header); err != nil {
			t.Fatal(err)
		}
		if binary.Size(header) != 40 || header.TS != 0x99aabbccddeeff00 || header.CgroupID != 0x1122334455667788 || header.UID != 1001 || header.GID != 1002 || header.PPID != 123 {
			t.Fatalf("C header misdecoded: %+v", header)
		}
		event, ok := decodeRecord(record)
		if !ok {
			t.Fatal("nonzero C header rejected")
		}
		if kind == recKindExec {
			if event.Process.PID != 4242 || event.Process.UID != 1001 || event.Process.GID != 1002 || event.Process.CgroupID != header.CgroupID {
				t.Fatalf("process identity misdecoded: %+v", event.Process)
			}
		} else if event.File.PID != 4242 || event.File.CgroupID != header.CgroupID {
			t.Fatalf("file identity misdecoded: %+v", event.File)
		}
	}
}
