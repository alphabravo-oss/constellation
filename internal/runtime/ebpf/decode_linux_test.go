//go:build linux

package ebpf

import (
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"
)

// TestDecodeRecordFileAbsolutePath guards the RT-1 fix: the BPF file_open hook
// now emits an absolute (leading-slash) path via bpf_d_path, and the userspace
// decoder must surface it intact into FileEvent.Path. The FIM / file-profile
// matchers reject anything without a leading slash, so a regression that
// truncated to the dentry leaf (basename) would silently disable detection.
func TestDecodeRecordFileAbsolutePath(t *testing.T) {
	const path = "/etc/shadow"

	hdrSz := int(unsafe.Sizeof(recordHeader{})) // matches the wire header layout
	body := make([]byte, 4+4+16+256)            // flags, mode, comm[16], path[256]
	binary.LittleEndian.PutUint32(body[0:4], 0x8000)
	binary.LittleEndian.PutUint32(body[4:8], 0x1)
	copy(body[8:24], "cat\x00")
	copy(body[24:24+256], path+"\x00")

	rec := make([]byte, hdrSz+len(body))
	rec[0] = recKindFile
	binary.LittleEndian.PutUint32(rec[4:8], 4242) // pid
	copy(rec[hdrSz:], body)

	evt, ok := decodeRecord(rec)
	if !ok {
		t.Fatal("decodeRecord returned ok=false for a file record")
	}
	if evt.Kind != EventKindFile || evt.File == nil {
		t.Fatalf("decoded wrong event kind: %+v", evt)
	}
	if !strings.HasPrefix(evt.File.Path, "/") {
		t.Fatalf("file path %q is not absolute; FIM matchers require a leading slash", evt.File.Path)
	}
	if evt.File.Path != path {
		t.Fatalf("file path = %q, want %q", evt.File.Path, path)
	}
	if evt.File.PID != 4242 {
		t.Fatalf("file pid = %d, want 4242", evt.File.PID)
	}
}
