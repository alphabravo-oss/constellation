//go:build integration

package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	columncrypto "github.com/alphabravocompany/constellation/internal/crypto"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

func TestMain(m *testing.M) { pgtest.Main(m) }
func testLocalService(t testing.TB) (*Service, authctx.Subject, LocalConfig) {
	t.Helper()
	pool := pgtest.Pool(t)
	ctx := context.Background()
	c := LocalConfig{Enabled: true, OrgName: "demo", BootstrapEmail: "owner@example.test", BootstrapPassword: "test-owner-Long-Unique-741!", BootstrapTOTP: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}
	c.defaults()
	s, err := New(ctx, Store{Pool: pool}, nil, BreakGlassConfig{}, c, audit.New(pool), prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	var actor authctx.Subject
	if err = pool.QueryRow(ctx, `SELECT id,org_id,email FROM users WHERE email=$1`, c.BootstrapEmail).Scan(&actor.UserID, &actor.OrgID, &actor.Email); err != nil {
		t.Fatal(err)
	}
	return s, actor, c
}
func testCode(secret string, delta int64) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(time.Now().Unix()/30+delta))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(raw[:])
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(h[offset:offset+4])&0x7fffffff)%1000000)
}
func TestLocalLifecycleAndRevocation(t *testing.T) {
	t.Parallel()
	s, admin, c := testLocalService(t)
	ctx := t.Context()
	raw, _, kind, err := s.loginLocal(ctx, c.BootstrapEmail, c.BootstrapPassword, testCode(c.BootstrapTOTP, 0), false)
	if err != nil || kind != "break-glass" {
		t.Fatalf("bootstrap login %s %v", kind, err)
	}
	if _, err = s.Authenticate(ctx, raw); err != nil {
		t.Fatal(err)
	}
	out, err := s.createUser(ctx, admin, "analyst@example.test", "Analyst", "different-local-password-741!", rbac.RoleAnalyst)
	if err != nil {
		t.Fatal(err)
	}
	var sealed columncrypto.Sealed
	if err = s.store.Pool.QueryRow(ctx, `SELECT totp_secret,key_id,algorithm FROM local_users WHERE user_id=$1`, out.ID).Scan(&sealed.Ciphertext, &sealed.KeyID, &sealed.Algorithm); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed.Ciphertext), out.TOTPSecret) || sealed.KeyID == "" {
		t.Fatal("TOTP not encrypted")
	}
	plain, err := s.enc.Decrypt(sealed)
	if err != nil || string(plain) != out.TOTPSecret {
		t.Fatal("TOTP triple cannot be opened", err)
	}
	loginCode := testCode(out.TOTPSecret, 0)
	analyst, _, _, err := s.loginLocal(ctx, "analyst@example.test", out.Password, loginCode, false)
	if err != nil {
		t.Fatal(err)
	}
	subj, err := s.Authenticate(ctx, analyst)
	if err != nil {
		t.Fatal(err)
	}
	if err = rbac.Authorize(subj.Assignments, rbac.VerbReadFindings, rbac.Resource{OrgID: subj.OrgID}); err != nil {
		t.Fatal(err)
	}
	if err = rbac.Authorize(subj.Assignments, rbac.VerbManageUsers, rbac.Resource{OrgID: subj.OrgID}); err == nil {
		t.Fatal("analyst acquired administrator access")
	}
	if _, _, _, err = s.loginLocal(ctx, "analyst@example.test", out.Password, loginCode, false); err == nil {
		t.Fatal("TOTP replay accepted")
	}
	if _, err = s.mutateUser(ctx, admin, out.ID, "disable", ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate(ctx, analyst); err == nil {
		t.Fatal("disabled session accepted")
	}
	if _, _, _, err = s.loginLocal(ctx, "analyst@example.test", out.Password, testCode(out.TOTPSecret, 1), false); err == nil {
		t.Fatal("disabled account accepted")
	}
	if _, err = s.mutateUser(ctx, admin, admin.UserID, "disable", ""); err == nil {
		t.Fatal("recovery/self disable accepted")
	}
}
func TestLocalPolicyAndBackoff(t *testing.T) {
	t.Parallel()
	s, admin, _ := testLocalService(t)
	ctx := t.Context()
	out, err := s.createUser(ctx, admin, "limits@example.test", "Limits", "another-good-password-747!", rbac.RoleAnalyst)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := s.store.readSettings(ctx, s.enc)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Local.TOTPPolicy = "admins"
	cfg.Local.Enabled = false
	if err = s.store.writeSettings(ctx, cfg, columncrypto.Sealed{}, &admin, s.audit); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = s.loginLocal(ctx, "limits@example.test", out.Password, "", false); err == nil {
		t.Fatal("local disabled bypass")
	}
	cfg, err = s.store.readSettings(ctx, s.enc)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Local.Enabled = true
	if err = s.store.writeSettings(ctx, cfg, columncrypto.Sealed{}, &admin, s.audit); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = s.loginLocal(ctx, "limits@example.test", out.Password, "", false); err != nil {
		t.Fatal("analyst TOTP optional policy", err)
	}
	for range cfg.Local.AccountRate {
		_, _, _, _ = s.loginLocal(ctx, "limits@example.test", "wrong", "", false)
	}
	if _, _, _, err = s.loginLocal(ctx, "limits@example.test", out.Password, "", false); !errors.Is(err, errLoginBlocked) {
		t.Fatal("backoff absent", err)
	}
	for i := 0; i < cfg.Local.IPRate; i++ {
		if ok, err := s.store.reserveIP(ctx, "192.0.2.5", cfg.Local.IPRate); !ok || err != nil {
			t.Fatal("premature IP limit", err)
		}
	}
	if ok, err := s.store.reserveIP(ctx, "192.0.2.5", cfg.Local.IPRate); ok || err != nil {
		t.Fatal("IP limit missing", err)
	}
	if _, err = s.createUser(ctx, admin, "breached@example.test", "Breached", "password", rbac.RoleAnalyst); err == nil || !strings.Contains(err.Error(), "breached") {
		t.Fatal("breached password not rejected", err)
	}
}
func TestMigrationPreservesRecoveryAndBootstrapIsIdempotent(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	ctx := t.Context()
	enc, err := columncrypto.Default()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword("original-recovery-password-741!")
	if err != nil {
		t.Fatal(err)
	}
	e := BreakGlassConfig{Enabled: true, OrgName: "demo", PasswordHash: hash, TOTPSecret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}
	c := LocalConfig{Enabled: true, OrgName: "demo", BootstrapEmail: "bootstrap@example.test", BootstrapPassword: "bootstrap-local-password-741!", BootstrapTOTP: e.TOTPSecret}
	s, err := New(ctx, Store{Pool: pool}, nil, e, c, audit.New(pool), prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	raw, _, kind, err := s.loginLocal(ctx, "break-glass@constellation.local", "original-recovery-password-741!", testCode(e.TOTPSecret, 0), true)
	if err != nil || kind != "break-glass" {
		t.Fatal("migration lost credentials", err)
	}
	if _, err = s.Authenticate(ctx, raw); err != nil {
		t.Fatal(err)
	}
	// A second startup cannot overwrite rotated or disabled local credentials.
	c.BootstrapPassword = "changed-deployment-password-741!"
	if err = s.bootstrap(ctx, c); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM local_users`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("idempotence: %d %v", n, err)
	}
	var secret columncrypto.Sealed
	if err = pool.QueryRow(ctx, `SELECT totp_secret,key_id,algorithm FROM local_users WHERE break_glass`).Scan(&secret.Ciphertext, &secret.KeyID, &secret.Algorithm); err != nil {
		t.Fatal(err)
	}
	if p, err := enc.Decrypt(secret); err != nil || string(p) != e.TOTPSecret {
		t.Fatal("recovery seed changed", err)
	}
	cfg, err := s.store.readSettings(ctx, enc)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Local.Enabled = false
	actor := authctx.Subject{UserID: uuid.New()}
	if err = pool.QueryRow(ctx, `SELECT id,org_id FROM users WHERE email=$1`, c.BootstrapEmail).Scan(&actor.UserID, &actor.OrgID); err != nil {
		t.Fatal(err)
	}
	if err = s.store.writeSettings(ctx, cfg, columncrypto.Sealed{}, &actor, s.audit); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = s.loginLocal(ctx, "break-glass@constellation.local", "original-recovery-password-741!", testCode(e.TOTPSecret, 1), true); err != nil {
		t.Fatal("recovery unavailable with local disabled", err)
	}
	if _, err = pool.Exec(ctx, `UPDATE users SET disabled=true WHERE oidc_issuer='break-glass'`); err == nil {
		t.Fatal("legacy endpoint could disable recovery administrator")
	}
}
func TestSessionSnapshotsObserveOtherReplicaRevocations(t *testing.T) {
	t.Parallel()
	s, actor, _ := testLocalService(t)
	ctx := t.Context()
	q := &Service{store: s.store}
	if err := q.RefreshSessions(ctx); err != nil {
		t.Fatal(err)
	}
	go q.runSessions(ctx)
	out, err := s.createUser(ctx, actor, "snapshot@example.test", "Snapshot", "snapshot-password-Long-197!", rbac.RoleAnalyst)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, _, err := s.loginLocal(ctx, "snapshot@example.test", out.Password, testCode(out.TOTPSecret, 0), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.session(raw); err != nil {
		t.Fatal("new cookie was returned before it was usable on the second replica", err)
	}
	if _, err = s.mutateUser(ctx, actor, out.ID, "disable", ""); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err = q.session(raw); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked session survived on second replica")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func TestFreshSSOOnlyInstallStillBootstrapsRecovery(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	c := LocalConfig{Enabled: false, OrgName: "fresh", BootstrapEmail: "recovery@example.test", BootstrapPassword: "fresh-recovery-password-191!", BootstrapTOTP: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}
	s, err := New(t.Context(), Store{Pool: pool}, nil, BreakGlassConfig{}, c, audit.New(pool), prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	raw, _, kind, err := s.loginLocal(t.Context(), c.BootstrapEmail, c.BootstrapPassword, testCode(c.BootstrapTOTP, 0), true)
	if err != nil || kind != "break-glass" {
		t.Fatalf("SSO-only bootstrap recovery %s %v", kind, err)
	}
	if _, err = s.Authenticate(t.Context(), raw); err != nil {
		t.Fatal(err)
	}
}
func BenchmarkLocalSessionCheck(b *testing.B) {
	s, admin, _ := testLocalService(b)
	ctx := context.Background()
	admin.Assignments = []rbac.RoleAssignment{{Role: rbac.RoleGlobalAdmin, Scope: rbac.Scope{OrgID: admin.OrgID}}}
	var epoch int64
	if err := s.store.Pool.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id=$1`, admin.UserID).Scan(&epoch); err != nil {
		b.Fatal(err)
	}
	raw, err := s.store.startSession(ctx, admin, epoch, []string{rbac.RoleGlobalAdmin}, "local", time.Now().Add(time.Hour), s.audit)
	if err != nil {
		b.Fatal(err)
	}
	if err = s.RefreshSessions(ctx); err != nil {
		b.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_ = s.RefreshSessions(ctx)
			}
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := s.Authenticate(ctx, raw); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(0, "request_network_calls")
	if per := b.Elapsed() / time.Duration(b.N); per > 50*time.Microsecond {
		b.Fatalf("session check %s exceeds 50 µs", per)
	}
}
