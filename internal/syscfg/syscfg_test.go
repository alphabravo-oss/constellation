package syscfg

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// --- fakeStore: an in-memory store implementing the syscfg store interface so the
// Provider hot-reload, Seed, Save, and Load paths can be exercised without a DB. ---

type fakeStore struct {
	mu   sync.Mutex
	rows map[uuid.UUID]struct {
		blob []byte
		rev  int64
	}
}

func newFakeStore() *fakeStore {
	return &fakeStore{rows: map[uuid.UUID]struct {
		blob []byte
		rev  int64
	}{}}
}

type fakeRow struct {
	blob []byte
	rev  int64
	err  error
}

func (r fakeRow) Scan(dst ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dst[0].(*json.RawMessage)) = json.RawMessage(r.blob)
	*(dst[1].(*int64)) = r.rev
	return nil
}

func (s *fakeStore) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := args[0].(uuid.UUID)
	row, ok := s.rows[id]
	if !ok {
		return fakeRow{err: pgx.ErrNoRows}
	}
	return fakeRow{blob: row.blob, rev: row.rev}
}

// Exec handles both the INSERT...ON CONFLICT DO NOTHING (Seed) shape, distinguished by
// the absence of a RETURNING (Save uses QueryRow). Only Seed's INSERT reaches here.
func (s *fakeStore) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := args[0].(uuid.UUID)
	if _, ok := s.rows[id]; ok {
		return pgconn.NewCommandTag("INSERT 0 0"), nil // ON CONFLICT DO NOTHING
	}
	blob := toBytes(args[1])
	s.rows[id] = struct {
		blob []byte
		rev  int64
	}{blob: blob, rev: 1}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (s *fakeStore) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, nil
}

// save mimics the Save SQL (used by tests directly to bump revisions) since Save uses
// QueryRow with RETURNING which our fakeRow doesn't model for the upsert path.
func (s *fakeStore) save(id uuid.UUID, cfg Config) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	blob, _ := json.Marshal(cfg)
	row := s.rows[id]
	row.blob = blob
	row.rev++
	if row.rev == 0 {
		row.rev = 1
	}
	s.rows[id] = row
	return row.rev
}

func toBytes(v any) []byte {
	switch t := v.(type) {
	case []byte:
		return t
	case json.RawMessage:
		return []byte(t)
	case string:
		return []byte(t)
	default:
		b, _ := json.Marshal(v)
		return b
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		c    Config
		ok   bool
	}{
		{"default ok", Default(), true},
		{"bad proxy", Config{EgressProxy: EgressProxy{HTTPSProxy: "://nope"}}, false},
		{"good proxy", Config{EgressProxy: EgressProxy{HTTPSProxy: "http://proxy:3128"}, TLSVerify: true}, true},
		{"bad syslog port", Config{SyslogSIEM: SyslogTarget{Host: "h", Port: 0}}, false},
		{"bad syslog proto", Config{SyslogSIEM: SyslogTarget{Host: "h", Port: 514, Protocol: "sctp"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if tc.ok && err != nil {
				t.Fatalf("want valid, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("want invalid, got nil")
			}
		})
	}
}

// TestRedacted: GET must mask the CA bundle secret but preserve set-vs-unset.
func TestRedacted(t *testing.T) {
	c := Default()
	if c.Redacted().CABundlePEM != "" {
		t.Fatalf("unset bundle should stay empty")
	}
	c.CABundlePEM = testCACert(t)
	red := c.Redacted()
	if red.CABundlePEM != redactedMarker {
		t.Fatalf("set bundle = %q, want redaction marker", red.CABundlePEM)
	}
	if c.CABundlePEM == redactedMarker {
		t.Fatalf("Redacted mutated the original")
	}
}

// TestRedacted_ProxyCredentials: an egress proxy URL with embedded credentials must be
// masked on GET/audit (no cleartext password leaks), and echoing the redacted value back
// through a PATCH must preserve the originally stored credentialed URL.
func TestRedacted_ProxyCredentials(t *testing.T) {
	// Credential-free proxy URLs are returned unchanged and not flagged as redacted.
	for _, s := range []string{"", "http://egress.test:3128", "http://proxy:3128/"} {
		if got := redactProxyUserinfo(s); got != s {
			t.Errorf("redactProxyUserinfo(%q) = %q, want unchanged", s, got)
		}
		if proxyUserinfoIsRedacted(s) {
			t.Errorf("proxyUserinfoIsRedacted(%q) = true, want false", s)
		}
	}

	const cred = "https://user:s3cr3t@proxy:3128"
	c := Default()
	c.EgressProxy.HTTPSProxy = cred

	red := c.Redacted().EgressProxy.HTTPSProxy
	if strings.Contains(red, "s3cr3t") || strings.Contains(red, "user") {
		t.Fatalf("Config.Redacted leaked proxy credentials: %q", red)
	}
	if red == cred {
		t.Fatalf("credentialed proxy not redacted: %q", red)
	}
	if !proxyUserinfoIsRedacted(red) {
		t.Fatalf("redacted proxy %q not detected as redacted (round-trip would wipe secret)", red)
	}
	if c.CABundlePEM != "" || c.EgressProxy.HTTPSProxy != cred {
		t.Fatalf("Redacted mutated the original config")
	}

	// PATCH echoing the redacted proxy back preserves the stored credentialed URL.
	patched, err := c.ApplyPatch(json.RawMessage(`{"egress_proxy":{"https_proxy":"` + red + `"}}`))
	if err != nil {
		t.Fatalf("ApplyPatch redacted echo: %v", err)
	}
	if patched.EgressProxy.HTTPSProxy != cred {
		t.Fatalf("redacted proxy echo wiped/corrupted secret: got %q want %q", patched.EgressProxy.HTTPSProxy, cred)
	}
}

// TestApplyPatch_PartialAndSecretPreserve: a partial patch only touches named keys, and
// a redaction-marker echo for the secret preserves the stored value.
func TestApplyPatch_PartialAndSecretPreserve(t *testing.T) {
	base := Default()
	base.CABundlePEM = testCACert(t)

	// Partial patch: only flip tls_verify; everything else preserved including the secret.
	patched, err := base.ApplyPatch(json.RawMessage(`{"tls_verify": false}`))
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if patched.TLSVerify {
		t.Fatalf("tls_verify not applied")
	}
	if patched.CABundlePEM != base.CABundlePEM {
		t.Fatalf("ca bundle should be preserved on partial patch")
	}

	// Echoing the redaction marker leaves the stored secret intact.
	echoed, err := base.ApplyPatch(json.RawMessage(`{"ca_bundle_pem": "` + redactedMarker + `"}`))
	if err != nil {
		t.Fatalf("patch echo: %v", err)
	}
	if echoed.CABundlePEM != base.CABundlePEM {
		t.Fatalf("redacted echo wiped the secret")
	}

	// Unknown keys are rejected.
	if _, err := base.ApplyPatch(json.RawMessage(`{"nope": 1}`)); err == nil {
		t.Fatalf("unknown key should be rejected")
	}
	// Invalid value rejected by Validate.
	if _, err := base.ApplyPatch(json.RawMessage(`{"egress_proxy": {"https_proxy": "://nope"}}`)); err == nil {
		t.Fatalf("invalid value should be rejected")
	}
}

// TestProvider_HotReloadWithoutRestart: the core B1 acceptance — after the row changes
// (simulating a PATCH on another replica), Refresh swaps the cached value the accessor
// returns, all without recreating the Provider.
func TestProvider_HotReloadWithoutRestart(t *testing.T) {
	ctx := context.Background()
	s := newFakeStore()
	org := uuid.New()

	// Seed first boot from env defaults (TLS verify on, proxy empty).
	if _, _, err := Seed(ctx, s, org, Default()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	p := NewProvider(s)

	// Warm the cache; initial proxy is empty.
	if got := p.Get(ctx, org).EgressProxy.HTTPSProxy; got != "" {
		t.Fatalf("initial proxy = %q, want empty", got)
	}

	// Simulate a PATCH landing in the DB (revision bumps).
	newCfg := Default()
	newCfg.EgressProxy.HTTPSProxy = "http://egress:3128"
	s.save(org, newCfg)

	// Before Refresh the accessor still returns the cached (old) value.
	if got := p.Get(ctx, org).EgressProxy.HTTPSProxy; got != "" {
		t.Fatalf("pre-refresh proxy = %q, want still empty (cached)", got)
	}

	// The reloader tick picks up the new revision and hot-swaps the cache.
	if n := p.Refresh(ctx); n != 1 {
		t.Fatalf("Refresh changed = %d, want 1", n)
	}
	if got := p.Get(ctx, org).EgressProxy.HTTPSProxy; got != "http://egress:3128" {
		t.Fatalf("post-refresh proxy = %q, want updated WITHOUT restart", got)
	}
}

// TestProvider_UpdateAfterPatch: the writing replica sees its own change immediately.
func TestProvider_UpdateAfterPatch(t *testing.T) {
	ctx := context.Background()
	s := newFakeStore()
	org := uuid.New()
	_, _, _ = Seed(ctx, s, org, Default())
	p := NewProvider(s)
	_ = p.Get(ctx, org) // warm

	c := Default()
	c.SyslogSIEM = SyslogTarget{Host: "siem.local", Port: 514, Protocol: "tcp"}
	p.UpdateAfterPatch(org, c, 2)

	got := p.Get(ctx, org)
	if got.SyslogSIEM.Addr() != "siem.local:514" {
		t.Fatalf("syslog addr = %q, want siem.local:514", got.SyslogSIEM.Addr())
	}
}

// TestSeed_FirstBootIdempotent: env seeds on first boot, then the DB row wins — a second
// Seed with different defaults is a no-op.
func TestSeed_FirstBootIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newFakeStore()
	org := uuid.New()

	envDefaults := Default()
	envDefaults.EgressProxy.HTTPSProxy = "http://boot-proxy:8080"
	cfg, rev, err := Seed(ctx, s, org, envDefaults)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if cfg.EgressProxy.HTTPSProxy != "http://boot-proxy:8080" || rev != 1 {
		t.Fatalf("first boot didn't seed env defaults: %+v rev=%d", cfg, rev)
	}

	// Second boot with different env must NOT overwrite the now-authoritative DB row.
	other := Default()
	other.EgressProxy.HTTPSProxy = "http://changed:9999"
	cfg2, _, err := Seed(ctx, s, org, other)
	if err != nil {
		t.Fatalf("seed2: %v", err)
	}
	if cfg2.EgressProxy.HTTPSProxy != "http://boot-proxy:8080" {
		t.Fatalf("second seed overwrote DB row: %q", cfg2.EgressProxy.HTTPSProxy)
	}
}

// TestDefaultsFromEnv: env vars map to the bootstrap Config.
func TestDefaultsFromEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://envproxy:3128")
	t.Setenv("NO_PROXY", "localhost,.internal")
	t.Setenv("CONSTELLATION_TLS_VERIFY", "false")
	t.Setenv("CONSTELLATION_SYSLOG_HOST", "siem")
	t.Setenv("CONSTELLATION_SYSLOG_PORT", "6514")
	t.Setenv("CONSTELLATION_SYSLOG_PROTOCOL", "tcp")

	c := DefaultsFromEnv()
	if c.EgressProxy.HTTPSProxy != "http://envproxy:3128" || c.EgressProxy.NoProxy != "localhost,.internal" {
		t.Fatalf("proxy env not honored: %+v", c.EgressProxy)
	}
	if c.TLSVerify {
		t.Fatalf("tls_verify env not honored")
	}
	if c.SyslogSIEM.Addr() != "siem:6514" || c.SyslogSIEM.Protocol != "tcp" {
		t.Fatalf("syslog env not honored: %+v", c.SyslogSIEM)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("env config invalid: %v", err)
	}
}

// TestHTTPClient_ProxyAndTLS: the shared outbound client honors the live proxy + TLS knobs.
func TestHTTPClient_ProxyAndTLS(t *testing.T) {
	// TLS-verify off -> transport skips verification.
	c := Default()
	c.TLSVerify = false
	cl := c.HTTPClient(0)
	tr := cl.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("tls_verify=false should set InsecureSkipVerify")
	}

	// Proxy honored, with NoProxy bypass.
	c = Default()
	c.EgressProxy = EgressProxy{HTTPSProxy: "http://egress:3128", NoProxy: "internal.svc"}
	cl = c.HTTPClient(0)
	tr = cl.Transport.(*http.Transport)
	reqProxied, _ := http.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
	u, _ := tr.Proxy(reqProxied)
	if u == nil || u.Host != "egress:3128" {
		t.Fatalf("proxied request should route via egress, got %v", u)
	}
	reqBypass, _ := http.NewRequest(http.MethodGet, "https://internal.svc/x", nil)
	if u, _ := tr.Proxy(reqBypass); u != nil {
		t.Fatalf("no_proxy host should bypass proxy, got %v", u)
	}

	// Verify the proxy actually carries traffic end-to-end (smoke).
	hit := false
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	c = Default()
	c.EgressProxy = EgressProxy{HTTPSProxy: proxy.URL}
	cl = c.HTTPClient(2 * time.Second)
	resp, err := cl.Get("http://example.invalid/whatever")
	if err == nil {
		_ = resp.Body.Close()
	}
	if !hit {
		t.Fatalf("request did not flow through the configured proxy")
	}
}

// TestSyslogSenderAccessor: the audit/notifier consumer reads the live target.
func TestSyslogSenderAccessor(t *testing.T) {
	ctx := context.Background()
	s := newFakeStore()
	org := uuid.New()
	_, _, _ = Seed(ctx, s, org, Default())
	p := NewProvider(s)

	if _, ok := p.SyslogSender(ctx, org); ok {
		t.Fatalf("no target configured -> sender should be absent")
	}
	c := Default()
	c.SyslogSIEM = SyslogTarget{Host: "siem.local", Port: 514, Protocol: "udp"}
	p.UpdateAfterPatch(org, c, 2)
	sender, ok := p.SyslogSender(ctx, org)
	if !ok || sender == nil {
		t.Fatalf("configured target -> sender should be present")
	}
	if sender.Addr != "siem.local:514" || sender.Network != "udp" {
		t.Fatalf("sender target = %s/%s, want siem.local:514/udp", sender.Network, sender.Addr)
	}
}

// testCACert returns a valid self-signed CA cert PEM for the CA-bundle validation tests.
func testCACert(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
