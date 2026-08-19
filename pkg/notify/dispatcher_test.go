package notify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// TestSignAndVerifyHMAC exercises the signer + verifier so receivers (or downstream tests)
// can validate the X-Constellation-Signature header using the receiver's secret_key.
func TestSignAndVerifyHMAC(t *testing.T) {
	key := "supersecretkey"
	body := []byte(`{"hello":"world"}`)
	now := time.Unix(1700000000, 0)
	header, _ := signHMAC(key, body, now)
	if !strings.HasPrefix(header, "t=1700000000,v1=") {
		t.Fatalf("unexpected header shape: %q", header)
	}
	if !VerifyHMAC(key, header, body) {
		t.Fatal("verify failed for the freshly-signed body")
	}
	if VerifyHMAC("wrongkey", header, body) {
		t.Fatal("verify accepted with wrong key")
	}
	if VerifyHMAC(key, header, []byte(`tampered`)) {
		t.Fatal("verify accepted with tampered body")
	}
}

// TestRenderBody_WebhookKindIncludesHeadersAndPayload checks the generic webhook
// template emits the structured JSON envelope the docs promise.
func TestRenderBody_WebhookKind(t *testing.T) {
	rec := receiverRow{Kind: "webhook", TemplateID: "default"}
	ev := Event{
		Kind: "finding.triage", OrgID: uuid.New(), Severity: "high",
		Title: "Critical CVE", Cluster: "prod-1", Workload: "api",
		URL: "https://app/findings/x", IdempotencyKey: uuid.New(),
		FiredAt: time.Now().UTC(), Labels: map[string]string{"sev": "high"},
	}
	body, ct, err := renderBody(rec, ev)
	if err != nil {
		t.Fatal(err)
	}
	if ct != "application/json" {
		t.Fatalf("content-type: %s", ct)
	}
	s := string(body)
	for _, want := range []string{`"kind": "finding.triage"`, `"severity": "high"`, `prod-1`, `"sev"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in body:\n%s", want, s)
		}
	}
}

func TestRenderBody_SlackKind(t *testing.T) {
	rec := receiverRow{Kind: "slack", TemplateID: "default"}
	ev := Event{Kind: "runtime.alert.exec", Severity: "critical", Title: `shell "spawn"`, Cluster: "c", Workload: "w", URL: "https://x", IdempotencyKey: uuid.New(), FiredAt: time.Now().UTC()}
	body, _, err := renderBody(rec, ev)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, "CRITICAL") {
		t.Fatalf("missing severity prefix: %s", s)
	}
	// jsonString-escaped quote
	if !strings.Contains(s, `shell \"spawn\"`) {
		t.Fatalf("title not json-escaped: %s", s)
	}
}

// TestRateLimit_ExhaustsBucket ensures the per-receiver token bucket throttles after
// the configured cap.
func TestRateLimit_ExhaustsBucket(t *testing.T) {
	d := &Dispatcher{cfg: DispatcherConfig{Now: func() time.Time { return time.Unix(0, 0) }}, buckets: map[uuid.UUID]*tokenBucket{}}
	rec := receiverRow{ID: uuid.New(), RatePerMin: 2}
	if !d.tryConsume(rec) {
		t.Fatal("first call should consume")
	}
	if !d.tryConsume(rec) {
		t.Fatal("second call should consume")
	}
	if d.tryConsume(rec) {
		t.Fatal("third call should be throttled")
	}
}

// TestRequestHeadersOnSuccessfulDispatch spins a tiny HTTP server and exercises the
// outbound request shape via a synthetic worker invocation (no DB).
func TestOutboundRequestShape(t *testing.T) {
	var capturedHeaders http.Header
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rec := receiverRow{
		ID: uuid.New(), Kind: "webhook", Endpoint: srv.URL,
		SecretKey: "abc", TemplateID: "default", RatePerMin: 60,
	}
	ev := Event{
		Kind: "finding.bulk", Severity: "high", OrgID: uuid.New(),
		Title: "demo", URL: "https://x", IdempotencyKey: uuid.New(),
		FiredAt: time.Now().UTC(),
	}
	body, ct, err := renderBody(rec, ev)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := signHMAC(rec.SecretKey, body, time.Now().UTC())
	req, _ := http.NewRequest("POST", rec.Endpoint, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Constellation-Signature", sig)
	req.Header.Set("X-Constellation-Idempotency", ev.IdempotencyKey.String())
	req.Header.Set("X-Constellation-Event", ev.Kind)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if capturedHeaders.Get("X-Constellation-Signature") == "" {
		t.Fatal("missing X-Constellation-Signature")
	}
	if capturedHeaders.Get("X-Constellation-Idempotency") != ev.IdempotencyKey.String() {
		t.Fatalf("idempotency mismatch: %s", capturedHeaders.Get("X-Constellation-Idempotency"))
	}
	if !strings.Contains(string(capturedBody), `"finding.bulk"`) {
		t.Fatalf("body shape: %s", capturedBody)
	}
	// Verify the signature against the captured body — i.e. nothing tampered in transit.
	if !VerifyHMAC(rec.SecretKey, capturedHeaders.Get("X-Constellation-Signature"), capturedBody) {
		t.Fatal("captured signature should verify")
	}
}

func TestGenerateSecretKey(t *testing.T) {
	k, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(k))
	}
	k2, _ := GenerateSecretKey()
	if k == k2 {
		t.Fatal("two generated keys collide")
	}
}

func TestTruncate_RuneBoundary(t *testing.T) {
	// "é" is 2 bytes (0xC3 0xA9); truncating at a byte that splits it must not
	// produce invalid UTF-8, otherwise Postgres rejects the Exec and degraded
	// status is never recorded.
	s := strings.Repeat("é", 200) // 400 bytes
	got := truncate(s, 241)       // 241 would split the 121st rune mid-sequence
	if !utf8.ValidString(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if len(got) > 241 {
		t.Fatalf("truncate exceeded limit: got %d bytes", len(got))
	}
	// Under the limit, the string is returned unchanged.
	if truncate("hello", 240) != "hello" {
		t.Fatal("short string should be returned unchanged")
	}
	// ASCII truncation still lands exactly on the byte limit.
	if got := truncate(strings.Repeat("a", 300), 240); len(got) != 240 {
		t.Fatalf("ascii truncate: got %d bytes, want 240", len(got))
	}
}
