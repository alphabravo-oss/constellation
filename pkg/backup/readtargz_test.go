package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// makeTarGz builds a gzipped tar containing the given (name -> content) members.
func makeTarGz(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range members {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     0o600,
			Size:     int64(len(body)),
		}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz.Close: %v", err)
	}
	return buf.Bytes()
}

// TestReadTarGzEnforcesDecompressedCeiling confirms readTarGz rejects an archive whose
// decompressed members exceed maxArchiveBytes (M4) — including the case where the total is
// spread across multiple members — while accepting one that stays under the ceiling.
func TestReadTarGzEnforcesDecompressedCeiling(t *testing.T) {
	orig := maxArchiveBytes
	maxArchiveBytes = 1024
	defer func() { maxArchiveBytes = orig }()

	// Under the ceiling: two small members, total < 1024. Must succeed and round-trip.
	ok := makeTarGz(t, map[string][]byte{
		"tables/a.jsonl": bytes.Repeat([]byte("a"), 300),
		"tables/b.jsonl": bytes.Repeat([]byte("b"), 300),
	})
	files, err := readTarGz(bytes.NewReader(ok))
	if err != nil {
		t.Fatalf("under-ceiling archive rejected: %v", err)
	}
	if len(files["tables/a.jsonl"]) != 300 || len(files["tables/b.jsonl"]) != 300 {
		t.Fatalf("round-trip mismatch: %d %d", len(files["tables/a.jsonl"]), len(files["tables/b.jsonl"]))
	}

	// Over the ceiling: members total 1200 > 1024. Must be rejected with a clear error.
	over := makeTarGz(t, map[string][]byte{
		"tables/a.jsonl": bytes.Repeat([]byte("a"), 700),
		"tables/b.jsonl": bytes.Repeat([]byte("b"), 500),
	})
	if _, err := readTarGz(bytes.NewReader(over)); err == nil {
		t.Fatal("expected over-ceiling archive to be rejected, got nil")
	} else if !strings.Contains(err.Error(), "decompressed limit") {
		t.Fatalf("unexpected error: %v", err)
	}

	// A single member larger than the ceiling is likewise rejected.
	big := makeTarGz(t, map[string][]byte{
		"tables/a.jsonl": bytes.Repeat([]byte("a"), 2048),
	})
	if _, err := readTarGz(bytes.NewReader(big)); err == nil {
		t.Fatal("expected oversized single member to be rejected, got nil")
	}
}
