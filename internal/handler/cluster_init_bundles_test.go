package handler

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestGenerateBundleTLS validates the in-Go cert chain mints a usable CA and a server
// cert verifiable against that CA. Pure-logic test; no DB.
func TestGenerateBundleTLS(t *testing.T) {
	caPEM, certPEM, keyPEM, err := generateBundleTLS("prod-us-east-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, label := range []struct {
		name, in string
	}{
		{"ca cert", caPEM},
		{"server cert", certPEM},
		{"server key", keyPEM},
	} {
		if !strings.Contains(label.in, "-----BEGIN") {
			t.Fatalf("%s: missing PEM header: %s", label.name, label.in[:min(40, len(label.in))])
		}
	}

	// Parse + verify chain.
	caBlock, _ := pem.Decode([]byte(caPEM))
	if caBlock == nil {
		t.Fatal("cannot decode ca pem")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	srvBlock, _ := pem.Decode([]byte(certPEM))
	if srvBlock == nil {
		t.Fatal("cannot decode server pem")
	}
	srvCert, err := x509.ParseCertificate(srvBlock.Bytes)
	if err != nil {
		t.Fatalf("parse server: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := srvCert.Verify(x509.VerifyOptions{
		Roots:       pool,
		DNSName:     "prod-us-east-1.cluster.constellation.internal",
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestEncryptDecryptRoundtrip exercises the AES-256-GCM helpers used to seal the
// bundle YAML before it's written to cluster_init_bundles.contents_encrypted.
func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plain := []byte("apiVersion: constellation.alphabravo.io/v1alpha1\nkind: ClusterInitBundle\n")
	ct, err := encrypt(key, plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) <= len(plain) {
		t.Fatalf("ciphertext too short: %d", len(ct))
	}
	got, err := decrypt(key, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("roundtrip mismatch")
	}
	// Wrong key fails.
	badKey := make([]byte, 32)
	if _, err := decrypt(badKey, ct); err == nil {
		t.Fatal("expected decrypt with wrong key to fail")
	}
}

// TestParseTTL covers the Go duration + Nd extension parser.
func TestParseTTL(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 720 * time.Hour, true},
		{"24h", 24 * time.Hour, true},
		{"720h", 720 * time.Hour, true},
		{"7d", 7 * 24 * time.Hour, true},
		{"30d", 30 * 24 * time.Hour, true},
		{"90d", 90 * 24 * time.Hour, true},
		{"-1h", 0, false},
		{"banana", 0, false},
	}
	for _, c := range cases {
		got, err := parseTTL(c.in)
		if (err == nil) != c.ok {
			t.Errorf("parseTTL(%q): ok=%v err=%v", c.in, c.ok, err)
			continue
		}
		if c.ok && got != c.want {
			t.Errorf("parseTTL(%q): got %v want %v", c.in, got, c.want)
		}
	}
}

// TestManifestYAMLShape ensures the rendered YAML keeps the documented top-level
// keys (apiVersion/kind/metadata/spec) so downstream tooling can parse the file
// with a fixed schema. Regression guard for accidental field renames.
func TestManifestYAMLShape(t *testing.T) {
	m := ClusterInitBundleManifest{
		APIVersion: "constellation.alphabravo.io/v1alpha1",
		Kind:       "ClusterInitBundle",
		Metadata: ClusterInitBundleMetadata{
			Name:      "test",
			ClusterID: "00000000-0000-0000-0000-000000000000",
			OrgID:     "00000000-0000-0000-0000-000000000001",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
		Spec: ClusterInitBundleSpec{
			ControlPlaneURL:     "https://control.example.com",
			ScannerToken:        "cst_aaa",
			RuntimeAgentToken:   "cra_bbb",
			AdmissionCACert:     "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
			AdmissionServerCert: "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n",
			AdmissionServerKey:  "-----BEGIN PRIVATE KEY-----\nCCC\n-----END PRIVATE KEY-----\n",
			AuditHMACSecret:     "deadbeef",
		},
	}
	out, err := yaml.Marshal(&m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		"apiVersion: constellation.alphabravo.io/v1alpha1",
		"kind: ClusterInitBundle",
		"name: test",
		"cluster_id:",
		"org_id:",
		"expires_at:",
		"control_plane_url: https://control.example.com",
		"scanner_token: cst_aaa",
		"runtime_agent_token: cra_bbb",
		"admission_ca_cert:",
		"admission_server_cert:",
		"admission_server_key:",
		"audit_hmac_secret: deadbeef",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("rendered YAML missing %q\n---\n%s\n---", want, out)
		}
	}
}

func TestStatusOf(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	if got := statusOf(future, nil); got != "active" {
		t.Errorf("active: got %s", got)
	}
	if got := statusOf(past, nil); got != "expired" {
		t.Errorf("expired: got %s", got)
	}
	revoked := now.Add(-30 * time.Minute)
	if got := statusOf(future, &revoked); got != "revoked" {
		t.Errorf("revoked: got %s", got)
	}
}

// TestResolveKEKNoPanic is the D3 regression guard: resolveKEK must return a usable
// 32-byte key (or an error) instead of panicking on the request/startup path.
func TestResolveKEKNoPanic(t *testing.T) {
	kek, err := resolveKEK()
	if err != nil {
		// Acceptable: a crypto-RNG failure now surfaces as an error, never a panic.
		t.Logf("resolveKEK returned error (degraded, non-fatal): %v", err)
		return
	}
	if len(kek) != 32 {
		t.Fatalf("resolveKEK: got %d-byte key, want 32", len(kek))
	}
}

// TestKEKReady503 verifies the request-path guard: a handler with no usable KEK writes a
// 503 (not a panic / 500 / process crash) for routes that seal or unseal bundle contents.
func TestKEKReady503(t *testing.T) {
	h := &ClusterInitBundles{} // nil KEK simulates a resolveKEK failure
	rec := httptest.NewRecorder()
	if h.kekReady(rec) {
		t.Fatal("kekReady: expected false with a nil KEK")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("kekReady: status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	// Healthy KEK path: returns true, writes nothing.
	h2 := &ClusterInitBundles{kek: make([]byte, 32)}
	rec2 := httptest.NewRecorder()
	if !h2.kekReady(rec2) {
		t.Fatal("kekReady: expected true with a 32-byte KEK")
	}
	if rec2.Code != http.StatusOK { // recorder default; nothing written
		t.Fatalf("kekReady: unexpected write, status = %d", rec2.Code)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
