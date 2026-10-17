package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/securefiles"
)

func (f *pcapFilesFixture) report(t *testing.T, id uuid.UUID, status string, count int64) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(AgentStatusUpdate{Status: PcapCaptureStatus(status), ErrorMessage: "late worker notification", PacketCount: count})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(t.Context(), "POST", "/runtime-pcap/"+id.String()+"/status", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(f.d.Pool())(http.HandlerFunc(f.h.UpdateStatus)).ServeHTTP(w, r)
	return w
}
func TestPcapStatusCannotCreateCompletedWithoutUpload(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "running")
	w := f.report(t, id, "completed", 100)
	if w.Code != 409 || f.status(t, id) != "running" {
		t.Fatalf("completion=%d %s", w.Code, w.Body.String())
	}
	requirePcapEntries(t, f.root, 0)
	w = f.operator(t, "GET", "/runtime-pcap/"+id.String()+"/download", f.h.Download)
	if w.Code != 409 {
		t.Fatal("status-only file available")
	}
}

type lostPcapReceipt struct {
	header http.Header
	status int
	writes int
}

func (w *lostPcapReceipt) Header() http.Header       { return w.header }
func (w *lostPcapReceipt) WriteHeader(status int)    { w.status = status }
func (w *lostPcapReceipt) Write([]byte) (int, error) { w.writes++; return 0, io.ErrClosedPipe }
func TestPcapStatusLostUploadACKCannotDowngradeCompleted(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "running")
	body := "authoritative captured bytes"
	r := httptest.NewRequestWithContext(t.Context(), "POST", "/runtime-pcap/"+id.String()+"/upload", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+f.token)
	lost := &lostPcapReceipt{header: make(http.Header)}
	handler.RuntimeAgentTokenMiddleware(f.d.Pool())(http.HandlerFunc(f.h.Upload)).ServeHTTP(lost, r)
	if lost.status != 200 || lost.writes == 0 || f.status(t, id) != "completed" {
		t.Fatal("fixture did not lose an actual committed receipt")
	}
	for _, status := range []string{"failed", "running", "completed"} {
		w := f.report(t, id, status, 1)
		if w.Code != 409 || f.status(t, id) != "completed" {
			t.Fatalf("late %s=%d %s", status, w.Code, w.Body.String())
		}
	}
	w := f.operator(t, "GET", "/runtime-pcap/"+id.String()+"/download", f.h.Download)
	if w.Code != 200 || w.Body.String() != body {
		t.Fatalf("retained artifact=%d %s", w.Code, w.Body.String())
	}
}
func TestPcapStatusFailedAndExpiredStayTerminal(t *testing.T) {
	f := pcapFilesDB(t)
	for _, state := range []string{"failed", "expired"} {
		id := f.capture(t, state)
		w := f.report(t, id, "running", 1)
		if w.Code != 409 || f.status(t, id) != state {
			t.Fatalf("revived %s", state)
		}
		w = f.report(t, id, "failed", 1)
		if w.Code != 200 || f.status(t, id) != state {
			t.Fatalf("changed terminal %s", state)
		}
	}
	id := f.capture(t, "running")
	w := f.report(t, id, "failed", -1)
	if w.Code != 400 || f.status(t, id) != "running" {
		t.Fatal("negative counter accepted")
	}
	w = f.report(t, id, "failed", 4)
	if w.Code != 200 || f.status(t, id) != "failed" {
		t.Fatalf("worker failure=%d %s", w.Code, w.Body.String())
	}
}
func TestPcapStatusDownloadRequiresVerifiedArtifactReceipt(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "completed")
	body := "legacy status-only file"
	if err := securefiles.WriteFile(f.root, pcapFileName(id), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	w := f.operator(t, "GET", "/runtime-pcap/"+id.String()+"/download", f.h.Download)
	if w.Code != 500 || strings.Contains(w.Body.String(), body) {
		t.Fatal("unverified legacy bytes downloaded")
	}
	hash := sha256.Sum256([]byte(body))
	if _, err := f.d.Pool().Exec(t.Context(), `UPDATE runtime_pcap_captures SET sha256=$1,file_size_bytes=$2 WHERE id=$3`, hex.EncodeToString(hash[:]), len(body), id); err != nil {
		t.Fatal(err)
	}
	w = f.operator(t, "GET", "/runtime-pcap/"+id.String()+"/download", f.h.Download)
	if w.Code != 200 || w.Body.String() != body {
		t.Fatalf("valid receipt=%d %s", w.Code, w.Body.String())
	}
	if err := securefiles.WriteFile(f.root, pcapFileName(id), []byte(strings.Repeat("x", len(body))), 0o600); err != nil {
		t.Fatal(err)
	}
	w = f.operator(t, "GET", "/runtime-pcap/"+id.String()+"/download", f.h.Download)
	if w.Code != 500 || strings.Contains(w.Body.String(), strings.Repeat("x", len(body))) {
		t.Fatal("tampered bytes downloaded")
	}
}
