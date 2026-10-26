package k8sauditarchive

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func archiveKeys(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	if err := backup.GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	return private, public
}
func archiveFixture() (Window, []Record) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	w := Window{OrgID: uuid.New(), ClusterID: uuid.New(), From: start, Through: start.Add(time.Hour)}
	row := Record{ID: uuid.New(), OrgID: w.OrgID, ClusterID: w.ClusterID, Verb: "get", At: start.Add(time.Minute), Raw: json.RawMessage(`{"private":"event"}`)}
	return w, []Record{row}
}

func TestArtifactTrustScopeAndTampering(t *testing.T) {
	t.Parallel()
	private, public := archiveKeys(t)
	w, records := archiveFixture()
	data, report, err := encode(t.Context(), w, records, false, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if report.Manifest.Count != 1 || report.Manifest.Last.ID != records[0].ID {
		t.Fatal("incorrect report")
	}
	summary, _ := json.Marshal(report)
	if bytes.Contains(summary, []byte("private")) {
		t.Fatal("report leaked event")
	}
	_, wrong := archiveKeys(t)
	if _, err := Verify(t.Context(), bytes.NewReader(data), wrong); err == nil {
		t.Fatal("wrong key accepted")
	}
	for _, part := range []string{"manifest", "signature", "data", "duplicate"} {
		t.Run(part, func(t *testing.T) {
			t.Parallel()
			var e envelope
			if err := json.Unmarshal(data, &e); err != nil {
				t.Fatal(err)
			}
			switch part {
			case "manifest":
				e.Manifest = bytes.Replace(e.Manifest, []byte(formatVersion), []byte("untrusted"), 1)
			case "signature":
				e.Signature[0] ^= 1
			case "data":
				e.Data[len(e.Data)/2] ^= 1
			}
			changed, _ := json.Marshal(e)
			if part == "duplicate" {
				changed = append([]byte(`{"data":"",`), changed[1:]...)
			}
			if _, err := Verify(t.Context(), bytes.NewReader(changed), public); err == nil {
				t.Fatal("tampered/ambiguous artifact accepted")
			}
		})
	}
	records[0].OrgID = uuid.New()
	if _, _, err := encode(t.Context(), w, records, false, private, public); err == nil {
		t.Fatal("signed foreign row accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Verify(ctx, bytes.NewReader(data), public); err == nil {
		t.Fatal("canceled verification succeeded")
	}
}

func TestSignedInvalidBoundariesAndOrder(t *testing.T) {
	t.Parallel()
	private, public := archiveKeys(t)
	for _, kind := range []string{"before", "through", "duplicate", "after", "submicrosecond", "limit"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			w, rows := archiveFixture()
			switch kind {
			case "before":
				rows[0].At = w.From.Add(-time.Second)
			case "through":
				rows[0].At = w.Through
			case "duplicate":
				rows = append(rows, rows[0])
			case "after":
				w.After = Cursor{At: rows[0].At, ID: rows[0].ID}
			case "submicrosecond":
				rows[0].At = rows[0].At.Add(time.Nanosecond)
			case "limit":
				for len(rows) <= MaxRows {
					rows = append(rows, rows[0])
				}
			}
			if _, _, err := encode(t.Context(), w, rows, false, private, public); err == nil {
				t.Fatal("invalid signed page accepted")
			}
		})
	}
}

func TestDecompressedArchiveBound(t *testing.T) {
	t.Parallel()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(bytes.Repeat([]byte(" "), MaxBatchBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRecords(t.Context(), compressed.Bytes(), Manifest{RecordBytes: MaxBatchBytes, RecordsSHA256: "not-a-match"}); err == nil {
		t.Fatal("oversized expansion accepted")
	}
}
