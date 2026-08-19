package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildLambdaZip returns an in-memory zip resembling a Lambda deployment package:
// a handler file plus a bundled-dependency manifest Syft can catalogue.
func buildLambdaZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestFetchServerlessArtifactFromHTTP(t *testing.T) {
	zipBytes := buildLambdaZip(t, map[string]string{
		"index.js": "exports.handler = async () => ({statusCode:200});\n",
		"package.json": `{"name":"payments","version":"1.0.0",` +
			`"dependencies":{"left-pad":"1.3.0"}}`,
		"node_modules/left-pad/package.json": `{"name":"left-pad","version":"1.3.0"}`,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	unpacked, err := FetchServerlessArtifact(context.Background(), ServerlessArtifact{
		Source:              srv.URL + "/payments.zip",
		HTTPClient:          srv.Client(),
		AllowPrivateTargets: true, // httptest listens on loopback
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer unpacked.Close()

	if unpacked.Files != 3 {
		t.Fatalf("files = %d, want 3", unpacked.Files)
	}
	if !strings.HasPrefix(unpacked.Ref(), "dir:") {
		t.Fatalf("ref = %q, want dir: prefix", unpacked.Ref())
	}
	// The handler + manifest must be present on disk.
	for _, rel := range []string{"index.js", "package.json", "node_modules/left-pad/package.json"} {
		if _, err := os.Stat(filepath.Join(unpacked.Dir, rel)); err != nil {
			t.Fatalf("expected extracted file %s: %v", rel, err)
		}
	}
}

// TestFetchServerlessArtifactRejectsSSRFTarget ensures an http(s) source resolving
// to loopback/link-local/private space is refused unless AllowPrivateTargets is set.
func TestFetchServerlessArtifactRejectsSSRFTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("should never be fetched"))
	}))
	defer srv.Close()

	_, err := FetchServerlessArtifact(context.Background(), ServerlessArtifact{
		Source:     srv.URL + "/artifact.zip", // loopback
		HTTPClient: srv.Client(),
	})
	if err == nil {
		t.Fatal("expected SSRF guard to reject loopback target, got nil error")
	}
}

func TestFetchServerlessArtifactFromLocalPath(t *testing.T) {
	zipBytes := buildLambdaZip(t, map[string]string{
		"requirements.txt": "flask==2.0.1\nrequests==2.28.0\n",
		"app.py":           "def handler(event, ctx):\n    return {}\n",
	})
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "func.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}

	unpacked, err := FetchServerlessArtifact(context.Background(), ServerlessArtifact{Source: zipPath})
	if err != nil {
		t.Fatalf("fetch local: %v", err)
	}
	defer unpacked.Close()
	if unpacked.Files != 2 {
		t.Fatalf("files = %d, want 2", unpacked.Files)
	}
	if _, err := os.Stat(filepath.Join(unpacked.Dir, "requirements.txt")); err != nil {
		t.Fatalf("expected requirements.txt: %v", err)
	}
}

// TestFetchServerlessArtifactRejectsZipSlip ensures a malicious entry that escapes the
// extraction root is rejected.
func TestFetchServerlessArtifactRejectsZipSlip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("../../etc/evil")
	_, _ = w.Write([]byte("pwned"))
	_ = zw.Close()

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	_, err := FetchServerlessArtifact(context.Background(), ServerlessArtifact{Source: zipPath})
	if err == nil {
		t.Fatal("expected zip-slip rejection, got nil")
	}
	if !strings.Contains(err.Error(), "illegal path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestFetchServerlessArtifactEnforcesUnpackCap guards against zip bombs by capping the
// total uncompressed bytes.
func TestFetchServerlessArtifactEnforcesUnpackCap(t *testing.T) {
	zipBytes := buildLambdaZip(t, map[string]string{
		"big.bin": strings.Repeat("A", 4096),
	})
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "big.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	_, err := FetchServerlessArtifact(context.Background(), ServerlessArtifact{
		Source:           zipPath,
		MaxUnpackedBytes: 1024, // smaller than the 4096-byte entry
	})
	if err == nil {
		t.Fatal("expected unpack-cap error, got nil")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestServerlessArtifactScannedWithSyft is the acceptance test: a Lambda zip is fetched,
// unpacked, and scanned by Syft with NO deployed agent. Skips when syft is absent.
func TestServerlessArtifactScannedWithSyft(t *testing.T) {
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft not on PATH")
	}
	zipBytes := buildLambdaZip(t, map[string]string{
		"app.py":           "def handler(event, ctx):\n    return {'statusCode': 200}\n",
		"requirements.txt": "flask==2.0.1\nrequests==2.28.0\n",
	})
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "func.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}

	unpacked, err := FetchServerlessArtifact(context.Background(), ServerlessArtifact{Source: zipPath})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer unpacked.Close()

	eng := &SyftEngine{}
	res, err := eng.Scan(context.Background(), unpacked.Ref(), ScanOptions{})
	if err != nil {
		t.Fatalf("syft scan: %v", err)
	}
	found := false
	for _, p := range res.Packages {
		if p.Name == "flask" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected flask package from serverless bundle, got %d packages", len(res.Packages))
	}
}
