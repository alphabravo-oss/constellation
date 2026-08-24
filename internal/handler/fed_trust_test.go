package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// fedTrustPreflight skips unless the D1 trust schema (migration 105) is present and
// returns a seeded org+user with that org promoted to the federation master state.
func fedTrustPreflight(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	for _, table := range []string{"fed_credentials", "fed_signing_keys", "fed_members", "federation_state"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s (migration 105) not applied (%v)", table, err)
		}
	}
	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}
	cleanup := func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM fed_credentials WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM fed_members WHERE org_id=$1 AND cluster_id LIKE 'd1-%'`, orgID)
		_, _ = pool.Exec(context.Background(), `UPDATE federation_state SET state='standalone'`)
	}
	cleanup()
	t.Cleanup(cleanup)
	// Promote AFTER the pre-clean so the master state holds for the duration of the test
	// (the fixed-token join path resolves the master org from federation_state).
	if _, err := pool.Exec(ctx, `
INSERT INTO federation_state (org_id, state, revision) VALUES ($1,'master',1)
ON CONFLICT (org_id) DO UPDATE SET state='master'`, orgID); err != nil {
		t.Fatal(err)
	}
	return orgID, userID
}

func fedTestSigner(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *auth.FedSigner {
	t.Helper()
	keys, err := auth.LoadFedSigningKeysPEM(ctx, pool)
	if err != nil {
		t.Fatalf("load fed signing keys: %v", err)
	}
	s, err := auth.NewFedSigner(keys...)
	if err != nil {
		t.Fatalf("new fed signer: %v", err)
	}
	return s
}

// doJoin runs the Join handler with the given body and returns the decoded response +
// status. The handler is wired with the supplied signer/config.
func doJoin(t *testing.T, h *Federation, body fedJoinRequest) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/federation/join", bytes.NewReader(raw))
	// Production joins reach the controller over the ingress-terminated TLS connection; the
	// mTLS-join guard (D2-3) treats X-Forwarded-Proto=https as that TLS evidence.
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	h.Join(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// TestFedTrust_JoinIssuesPerClusterSecretWithTTL covers the D1 acceptance check: a
// join exchange issues a per-cluster secret with a TTL, and the secret is stored only
// hashed (like api_tokens), epoch 0.
func TestFedTrust_JoinIssuesPerClusterSecretWithTTL(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)

	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{
		JoinTokenTTL: time.Minute, SecretTTL: time.Hour,
	})

	joinTok, err := signer.IssueJoinToken(orgID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	code, out := doJoin(t, h, fedJoinRequest{JoinToken: joinTok, ClusterID: "d1-edge-1", ClusterName: "edge-1"})
	if code != http.StatusOK {
		t.Fatalf("join status = %d, body=%v", code, out)
	}
	secret, _ := out["secret"].(string)
	if secret == "" {
		t.Fatal("join did not return a per-cluster secret")
	}
	if out["expires_at"] == nil {
		t.Fatal("join with SecretTTL did not return an expiry")
	}

	// The secret is a valid sync ticket for this cluster.
	claims, err := signer.VerifySyncTicket(secret)
	if err != nil || claims.ClusterID != "d1-edge-1" || claims.OrgID != orgID {
		t.Fatalf("returned secret is not a valid sync ticket: claims=%+v err=%v", claims, err)
	}

	// The DB stores only the hash, never the raw secret, and a live (not-revoked) row.
	var storedHash string
	var epoch int64
	var revokedAt *time.Time
	var expiresAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT secret_hash, epoch, revoked_at, expires_at FROM fed_credentials WHERE org_id=$1 AND cluster_id=$2`,
		orgID, "d1-edge-1").Scan(&storedHash, &epoch, &revokedAt, &expiresAt); err != nil {
		t.Fatalf("read fed_credentials: %v", err)
	}
	sum := sha256.Sum256([]byte(secret))
	if storedHash != hex.EncodeToString(sum[:]) {
		t.Fatal("stored secret_hash does not match sha256(secret)")
	}
	if storedHash == secret {
		t.Fatal("raw secret was stored instead of its hash")
	}
	if epoch != 0 || revokedAt != nil {
		t.Fatalf("fresh credential epoch=%d revoked=%v, want epoch 0 / not revoked", epoch, revokedAt)
	}
	if expiresAt == nil {
		t.Fatal("credential row missing expiry for a TTL'd secret")
	}
}

// TestFedTrust_SyncTicketAuthenticates verifies a freshly issued per-cluster ticket
// passes FedSyncTokenMiddleware and reaches Sync with the authenticated joint identity.
func TestFedTrust_SyncTicketAuthenticates(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)

	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{SecretTTL: time.Hour})
	joinTok, _ := signer.IssueJoinToken(orgID, time.Minute)
	_, out := doJoin(t, h, fedJoinRequest{JoinToken: joinTok, ClusterID: "d1-edge-2", ClusterName: "edge-2"})
	secret := out["secret"].(string)

	srv := httptest.NewServer(FedSyncTokenMiddleware(pool, signer, nil, "")(http.HandlerFunc(h.Sync)))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid ticket sync = %d, want 200", resp.StatusCode)
	}
	// The poll is treated as a heartbeat: the pending member flips to active.
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM fed_members WHERE org_id=$1 AND cluster_id=$2`, orgID, "d1-edge-2").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("member status = %q after sync, want active", status)
	}
}

// TestFedTrust_RevokedJointCantSync covers the D1 acceptance check: after the master
// kicks a joint (bumping the per-cluster epoch), the joint's already-issued ticket is
// rejected on its next poll.
func TestFedTrust_RevokedJointCantSync(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)

	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{SecretTTL: time.Hour})
	joinTok, _ := signer.IssueJoinToken(orgID, time.Minute)
	_, out := doJoin(t, h, fedJoinRequest{JoinToken: joinTok, ClusterID: "d1-edge-3", ClusterName: "edge-3"})
	secret := out["secret"].(string)

	srv := httptest.NewServer(FedSyncTokenMiddleware(pool, signer, nil, "")(http.HandlerFunc(h.Sync)))
	defer srv.Close()
	poll := func() int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"?since=0", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := poll(); got != http.StatusOK {
		t.Fatalf("pre-revoke poll = %d, want 200", got)
	}

	// Master kicks the joint: status->kicked + epoch bump (the revocation primitive).
	if err := RevokeFedCredential(ctx, pool, orgID, "d1-edge-3"); err != nil {
		t.Fatal(err)
	}
	if got := poll(); got != http.StatusForbidden {
		t.Fatalf("post-revoke poll = %d, want 403", got)
	}
}

// TestFedTrust_ReadFindingsJWTRejectedOnSync covers the headline D1 acceptance check:
// a generic read-findings user JWT can no longer pull /sync. The fed middleware only
// accepts a ticket signed by the dedicated fed key; a session-signed JWT fails.
func TestFedTrust_ReadFindingsJWTRejectedOnSync(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, userID := fedTrustPreflight(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)

	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{})
	srv := httptest.NewServer(FedSyncTokenMiddleware(pool, signer, nil, "")(http.HandlerFunc(h.Sync)))
	defer srv.Close()

	// A real user session JWT carrying read-findings, signed by a SEPARATE session key.
	sessKey := genRSAPEM(t)
	sessSigner, err := auth.NewSigner("constellation", "constellation", time.Hour, sessKey)
	if err != nil {
		t.Fatal(err)
	}
	userJWT, _, err := sessSigner.Issue(userID, orgID, "u@example.com", []string{"read-findings"}, 0)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("read-findings JWT on /sync = %d, want 401", resp.StatusCode)
	}
}

// TestFedTrust_FixedTokenJoinWorks covers the D1 GitOps path: a pre-shared fixed join
// token (config/env) is accepted at the exchange endpoint.
func TestFedTrust_FixedTokenJoinWorks(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	fedTrustPreflight(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)

	const fixed = "gitops-preshared-join-secret"
	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{FixedToken: fixed, SecretTTL: time.Hour})

	code, out := doJoin(t, h, fedJoinRequest{JoinToken: fixed, ClusterID: "d1-edge-4", ClusterName: "edge-4"})
	if code != http.StatusOK {
		t.Fatalf("fixed-token join = %d, body=%v", code, out)
	}
	if out["secret"] == nil || out["secret"] == "" {
		t.Fatal("fixed-token join did not issue a secret")
	}
	// A wrong fixed token is rejected.
	bad, _ := doJoin(t, h, fedJoinRequest{JoinToken: "not-the-token", ClusterID: "d1-edge-5", ClusterName: "edge-5"})
	if bad != http.StatusUnauthorized {
		t.Fatalf("bad join token = %d, want 401", bad)
	}
}

// TestFedTrust_RejoinRotatesSecret verifies a re-join bumps the epoch and rotates the
// stored secret so the previous ticket no longer validates (stale-ticket rejection).
func TestFedTrust_RejoinRotatesSecret(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)

	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{SecretTTL: time.Hour})
	joinTok, _ := signer.IssueJoinToken(orgID, time.Minute)
	_, out1 := doJoin(t, h, fedJoinRequest{JoinToken: joinTok, ClusterID: "d1-edge-6", ClusterName: "edge-6"})
	oldSecret := out1["secret"].(string)
	_, out2 := doJoin(t, h, fedJoinRequest{JoinToken: joinTok, ClusterID: "d1-edge-6", ClusterName: "edge-6"})
	newSecret := out2["secret"].(string)
	if oldSecret == newSecret {
		t.Fatal("re-join did not rotate the secret")
	}

	srv := httptest.NewServer(FedSyncTokenMiddleware(pool, signer, nil, "")(http.HandlerFunc(h.Sync)))
	defer srv.Close()
	poll := func(secret string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"?since=0", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, _ := srv.Client().Do(req)
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := poll(newSecret); got != http.StatusOK {
		t.Fatalf("new secret poll = %d, want 200", got)
	}
	// The old secret carries the pre-bump epoch -> revoked.
	if got := poll(oldSecret); got != http.StatusForbidden {
		t.Fatalf("old secret poll = %d, want 403 (stale epoch)", got)
	}
}

// TestFedTrust_MintJoinTokenMasterOnly verifies a master mints a signed join token but a
// standalone org cannot (409), and that the minted token round-trips end-to-end into a
// successful join.
func TestFedTrust_MintJoinTokenMasterOnly(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, userID := fedTrustPreflight(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)
	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{JoinTokenTTL: time.Minute, SecretTTL: time.Hour})

	mint := func() (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/federation/join-tokens", bytes.NewReader([]byte(`{}`)))
		req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: orgID, UserID: userID}))
		rec := httptest.NewRecorder()
		h.MintJoinToken(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, out := mint()
	if code != http.StatusCreated {
		t.Fatalf("master mint = %d, body=%v", code, out)
	}
	joinTok, _ := out["join_token"].(string)
	if joinTok == "" {
		t.Fatal("mint returned no join_token")
	}
	if c, _ := doJoin(t, h, fedJoinRequest{JoinToken: joinTok, ClusterID: "d1-edge-7", ClusterName: "edge-7"}); c != http.StatusOK {
		t.Fatalf("join with minted token = %d, want 200", c)
	}

	// Demote to standalone: minting is now refused.
	if _, err := pool.Exec(ctx, `UPDATE federation_state SET state='standalone' WHERE org_id=$1`, orgID); err != nil {
		t.Fatal(err)
	}
	if code, _ := mint(); code != http.StatusConflict {
		t.Fatalf("standalone mint = %d, want 409", code)
	}
}

// genRSAPEM returns a fresh PKCS1 RSA private key PEM for building a session signer.
func genRSAPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
}
