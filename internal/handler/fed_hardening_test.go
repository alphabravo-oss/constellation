package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

// kickMemberByCluster ejects the member for clusterID via the KickMember handler (status
// 'kicked' + kicked_at tombstone + credential revocation), as a master operator would.
func kickMemberByCluster(t *testing.T, h *Federation, orgID, userID uuid.UUID, clusterID string) {
	t.Helper()
	var mid uuid.UUID
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT id FROM fed_members WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&mid); err != nil {
		t.Fatalf("lookup member id: %v", err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/federation/members/"+mid.String(), nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: orgID, UserID: userID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", mid.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.KickMember(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("kick member = %d body=%s", rec.Code, rec.Body.String())
	}
}

// mintViaEndpoint mints a signed join token through MintJoinToken (so its jti is persisted
// for single-use), as an operator would, and returns the token.
func mintViaEndpoint(t *testing.T, h *Federation, orgID, userID uuid.UUID) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/federation/join-tokens", strings.NewReader(`{}`))
	req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: orgID, UserID: userID}))
	rec := httptest.NewRecorder()
	h.MintJoinToken(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint join token = %d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	tok, _ := out["join_token"].(string)
	if tok == "" {
		t.Fatal("mint returned no join_token")
	}
	return tok
}

// TestFedHardening_KickIsDurable (D1-1) proves a kicked cluster cannot re-admit itself by
// replaying a still-valid join credential: a fixed/GitOps token re-join is refused after a
// kick, and only a FRESH signed token minted AFTER the kick re-admits it.
func TestFedHardening_KickIsDurable(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, userID := fedTrustPreflight(t, ctx, pool)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM fed_join_tokens WHERE org_id=$1`, orgID) })
	signer := fedTestSigner(t, ctx, pool)

	const fixed = "gitops-preshared-join-secret-d1h"
	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{FixedToken: fixed, SecretTTL: time.Hour})

	// Join with the fixed (reusable) token, then the master kicks the joint.
	if code, _ := doJoin(t, h, fedJoinRequest{JoinToken: fixed, ClusterID: "d1-hk-1", ClusterName: "hk-1"}); code != http.StatusOK {
		t.Fatalf("initial join = %d", code)
	}
	kickMemberByCluster(t, h, orgID, userID, "d1-hk-1")

	// Replay the fixed token the kicked joint still holds: it must NOT silently un-kick.
	if code, out := doJoin(t, h, fedJoinRequest{JoinToken: fixed, ClusterID: "d1-hk-1", ClusterName: "hk-1"}); code != http.StatusForbidden {
		t.Fatalf("kicked-cluster re-join with fixed token = %d body=%v, want 403", code, out)
	}
	// The member is still kicked, and the credential is still revoked (no un-kick happened).
	var status string
	var revokedAt *time.Time
	_ = pool.QueryRow(ctx, `SELECT status FROM fed_members WHERE org_id=$1 AND cluster_id=$2`, orgID, "d1-hk-1").Scan(&status)
	_ = pool.QueryRow(ctx, `SELECT revoked_at FROM fed_credentials WHERE org_id=$1 AND cluster_id=$2`, orgID, "d1-hk-1").Scan(&revokedAt)
	if status != "kicked" {
		t.Fatalf("member status after refused re-join = %q, want kicked", status)
	}
	if revokedAt == nil {
		t.Fatal("credential revoked_at was cleared by a refused re-join (kick not durable)")
	}

	// An operator mints a FRESH token after the kick: re-admission is now allowed.
	fresh := mintViaEndpoint(t, h, orgID, userID)
	if code, out := doJoin(t, h, fedJoinRequest{JoinToken: fresh, ClusterID: "d1-hk-1", ClusterName: "hk-1"}); code != http.StatusOK {
		t.Fatalf("re-admit with fresh post-kick token = %d body=%v, want 200", code, out)
	}
	_ = pool.QueryRow(ctx, `SELECT status FROM fed_members WHERE org_id=$1 AND cluster_id=$2`, orgID, "d1-hk-1").Scan(&status)
	if status != "pending" {
		t.Fatalf("member status after re-admit = %q, want pending", status)
	}
}

// TestFedHardening_JoinTokenSingleUse (D1-2) proves a master-minted join token is consumed on
// first exchange: a replay (here, to hijack a DIFFERENT cluster id within the TTL) is rejected.
func TestFedHardening_JoinTokenSingleUse(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, userID := fedTrustPreflight(t, ctx, pool)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM fed_join_tokens WHERE org_id=$1`, orgID) })
	signer := fedTestSigner(t, ctx, pool)
	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{JoinTokenTTL: time.Minute, SecretTTL: time.Hour})

	tok := mintViaEndpoint(t, h, orgID, userID)
	if code, _ := doJoin(t, h, fedJoinRequest{JoinToken: tok, ClusterID: "d1-su-a", ClusterName: "su-a"}); code != http.StatusOK {
		t.Fatalf("first use of minted token = %d, want 200", code)
	}
	// Replay the same token for a different cluster id: single-use must reject it.
	if code, out := doJoin(t, h, fedJoinRequest{JoinToken: tok, ClusterID: "d1-su-b", ClusterName: "su-b"}); code != http.StatusUnauthorized {
		t.Fatalf("replay of consumed token = %d body=%v, want 401", code, out)
	}
	// The replayed cluster never got a credential row.
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM fed_credentials WHERE org_id=$1 AND cluster_id=$2`, orgID, "d1-su-b").Scan(&n)
	if n != 0 {
		t.Fatalf("replay minted a credential for the hijacked cluster id (rows=%d)", n)
	}
	_, _ = pool.Exec(ctx, `DELETE FROM fed_credentials WHERE org_id=$1 AND cluster_id IN ('d1-su-a','d1-su-b')`, orgID)
	_, _ = pool.Exec(ctx, `DELETE FROM fed_members WHERE org_id=$1 AND cluster_id IN ('d1-su-a','d1-su-b')`, orgID)
}

// TestFedHardening_EmptyFingerprintRejectedUnderMTLS (D2-2) proves a credential with no bound
// client cert (cert_fingerprint=”) is rejected — not silently downgraded to bearer-only —
// once mTLS enforcement (a wired CA) is on. Otherwise a credential minted while the CA was off
// would authenticate on the bearer alone forever.
func TestFedHardening_EmptyFingerprintRejectedUnderMTLS(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	ca := fedTestCA(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)

	// Join WITHOUT a CA -> the credential has an empty cert_fingerprint (a pre-/non-mTLS join).
	hNoCA := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{SecretTTL: time.Hour})
	joinTok, _ := signer.IssueJoinToken(orgID, time.Minute)
	_, out := doJoin(t, hNoCA, fedJoinRequest{JoinToken: joinTok, ClusterID: "d2-empty", ClusterName: "empty"})
	secret, _ := out["secret"].(string)
	if secret == "" {
		t.Fatal("join did not issue a secret")
	}
	var fp string
	_ = pool.QueryRow(ctx, `SELECT cert_fingerprint FROM fed_credentials WHERE org_id=$1 AND cluster_id=$2`, orgID, "d2-empty").Scan(&fp)
	if fp != "" {
		t.Fatalf("precondition: expected empty fingerprint, got %q", fp)
	}

	// Now enforce mTLS (CA wired). The empty-fingerprint credential must be rejected even
	// though the bearer ticket itself is valid.
	srv := startFedMTLSServer(t, pool, signer, ca, hNoCA)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/federation/sync?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := fedTestClient(srv, nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("empty-fingerprint credential under mTLS = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "not bound to a client certificate") {
		t.Fatalf("unexpected rejection reason: %s", body)
	}
}

// TestFedHardening_ProxyRejectsTraversal (D3-1) proves the cross-cluster proxy rejects any
// '.'/'..' segment (raw or percent-encoded) before the allowlist check and URL construction,
// so a non-admin cannot escape the read allowlist / the /api/v1 SSRF-path invariant.
func TestFedHardening_ProxyRejectsTraversal(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}
	if !fedMembersPresent(t, ctx, d) {
		t.Skip("skipping: fed_members schema not applied")
	}
	var rec recordingJoint
	ts := newRecordingJoint(t, &rec)
	clusterID := insertMember(t, ctx, d, orgID, ts.URL)
	h := NewFedProxy(d, audit.New(pool))

	for _, sub := range []string{"findings/../../users", "findings/%2e%2e/users", "../admin", "findings/."} {
		before := rec.hits
		// Non-admin reader: an allowlisted first segment must not let traversal through.
		if w := forwardReq(t, h, readerSubject(orgID, userID), http.MethodGet, clusterID, sub, "", ""); w.Code != http.StatusBadRequest {
			t.Fatalf("reader traversal %q = %d, want 400", sub, w.Code)
		}
		// Admin too: traversal must never be forwarded under the master's credential.
		if w := forwardReq(t, h, adminSubject(orgID, userID), http.MethodGet, clusterID, sub, "", ""); w.Code != http.StatusBadRequest {
			t.Fatalf("admin traversal %q = %d, want 400", sub, w.Code)
		}
		if rec.hits != before {
			t.Fatalf("traversal %q was forwarded to the joint", sub)
		}
	}
}

// TestFedHardening_ProxyStripsTrustHeaders (D3-2) proves the proxy strips inbound identity /
// trust headers so a caller cannot smuggle one to the joint under the master's identity.
func TestFedHardening_ProxyStripsTrustHeaders(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}
	if !fedMembersPresent(t, ctx, d) {
		t.Skip("skipping: fed_members schema not applied")
	}

	var seen http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(ts.Close)
	clusterID := insertMember(t, ctx, d, orgID, ts.URL)
	h := NewFedProxy(d, audit.New(pool))

	smuggled := map[string]string{
		"X-Forwarded-For":   "10.9.9.9",
		"X-Real-Ip":         "10.9.9.9",
		"X-Api-Key":         "smuggled-key",
		"X-Forwarded-User":  "admin",
		"X-Forwarded-Proto": "https",
		"Ssl-Client-Cert":   "spoofed-cert",
	}
	url := "/api/v1/federation/clusters/" + clusterID + "/findings"
	r := httptest.NewRequest(http.MethodGet, url, nil)
	for k, v := range smuggled {
		r.Header.Set(k, v)
	}
	r = r.WithContext(WithSubject(r.Context(), adminSubject(orgID, userID)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", clusterID)
	rctx.URLParams.Add("*", "findings")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Forward(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("forward = %d body=%s", w.Code, w.Body.String())
	}
	for k := range smuggled {
		if got := seen.Get(k); got != "" {
			t.Fatalf("smuggled header %s leaked to joint with value %q", k, got)
		}
	}
}
