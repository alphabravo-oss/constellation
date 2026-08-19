package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
	regsecrets "github.com/alphabravocompany/constellation/pkg/registry/secrets"
)

// testFedSealer returns a real AES-256-GCM cipher under a fixed key so the fed-CA at-rest
// encryption round-trips deterministically across the D2 tests (Seal at generate, Open at
// load must use the same key).
func testFedSealer(t *testing.T) auth.Sealer {
	t.Helper()
	c, err := regsecrets.New(make([]byte, 32))
	if err != nil {
		t.Fatalf("build test cipher: %v", err)
	}
	return c
}

// fedTestCA skips unless migration 106 (fed_ca) is present and returns a freshly generated
// federation CA. fed_ca is cleared first so the CA is generated under this test's cipher
// (a CA persisted by an earlier run under a different key could not be decrypted).
func fedTestCA(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *auth.FedCA {
	t.Helper()
	var rc string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.fed_ca')::text,'')`).Scan(&rc); err != nil || rc == "" {
		t.Skipf("skipping: fed_ca (migration 106) not applied (%v)", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM fed_ca`); err != nil {
		t.Fatalf("clear fed_ca: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM fed_ca`) })
	ca, err := auth.LoadFedCA(ctx, pool, testFedSealer(t))
	if err != nil {
		t.Fatalf("load fed CA: %v", err)
	}
	if ca == nil {
		t.Fatal("LoadFedCA returned nil with a sealer")
	}
	return ca
}

// startFedMTLSServer mounts the /sync middleware (with the CA) over a TLS server that
// requests + verifies any presented client cert against the fed CA, so r.TLS.PeerCertificates
// is populated exactly as a directly-terminated mTLS controller would see it.
func startFedMTLSServer(t *testing.T, pool *pgxpool.Pool, signer *auth.FedSigner, ca *auth.FedCA, h *Federation) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/api/v1/federation/sync", FedSyncTokenMiddleware(pool, signer, ca, "")(http.HandlerFunc(h.Sync)))
	srv := httptest.NewUnstartedServer(mux)
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("append CA cert to pool")
	}
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: caPool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// fedTestClient builds an INDEPENDENT http.Client that trusts the test server's cert and
// optionally presents the given client certificate. Independent (not srv.Client(), which is
// a shared singleton) so presenting a cert on one request never leaks into another.
func fedTestClient(srv *httptest.Server, cert *tls.Certificate) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	tlsCfg := &tls.Config{RootCAs: roots}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}

func pollSync(t *testing.T, client *http.Client, srv *httptest.Server, bearer string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/federation/sync?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// joinWithCA runs Join (CA wired) and returns the bearer secret plus the per-joint client
// cert material from the response.
func joinWithCA(t *testing.T, h *Federation, signer *auth.FedSigner, orgID uuid.UUID, clusterID string) (secret, certPEM, keyPEM, caPEM string) {
	t.Helper()
	joinTok, err := signer.IssueJoinToken(orgID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	code, out := doJoin(t, h, fedJoinRequest{JoinToken: joinTok, ClusterID: clusterID, ClusterName: clusterID})
	if code != http.StatusOK {
		t.Fatalf("join status=%d body=%v", code, out)
	}
	secret, _ = out["secret"].(string)
	certPEM, _ = out["client_cert"].(string)
	keyPEM, _ = out["client_key"].(string)
	caPEM, _ = out["ca_cert"].(string)
	return
}

// TestFedMTLS_CAEncryptedAtRest verifies the CA private key is stored encrypted (never as a
// plaintext PEM) and that LoadFedCA round-trips it back to a usable signer.
func TestFedMTLS_CAEncryptedAtRest(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	ca := fedTestCA(t, ctx, pool)

	var keyEnc []byte
	if err := pool.QueryRow(ctx, `SELECT key_enc FROM fed_ca WHERE active=TRUE ORDER BY created_at DESC LIMIT 1`).Scan(&keyEnc); err != nil {
		t.Fatalf("read fed_ca: %v", err)
	}
	if bytes.Contains(keyEnc, []byte("PRIVATE KEY")) {
		t.Fatal("fed CA private key is stored in plaintext PEM (must be encrypted at rest)")
	}
	// Re-load under the same cipher yields a CA that can still issue a cert.
	reloaded, err := auth.LoadFedCA(ctx, pool, testFedSealer(t))
	if err != nil {
		t.Fatalf("reload fed CA: %v", err)
	}
	if c, _, err := reloaded.IssueClientCert("rt-1", time.Hour); err != nil || len(c) == 0 {
		t.Fatalf("reloaded CA cannot issue: %v", err)
	}
	_ = ca
}

// TestFedMTLS_JoinIssuesClientCertBoundToCluster covers the D2 acceptance check: a join
// (CA wired) issues a per-joint client cert tied to the cluster id, signed by the CA, and
// records its fingerprint on the per-cluster credential.
func TestFedMTLS_JoinIssuesClientCertBoundToCluster(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	ca := fedTestCA(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)
	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{SecretTTL: time.Hour}).WithFedCA(ca)

	_, certPEM, keyPEM, caPEM := joinWithCA(t, h, signer, orgID, "d2-edge-1")
	if certPEM == "" || keyPEM == "" || caPEM == "" {
		t.Fatal("join did not return client cert material")
	}
	// The cert is a usable keypair, CN = cluster id, and chains to the fed CA with client EKU.
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		t.Fatalf("returned cert/key is not a valid keypair: %v", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "d2-edge-1" {
		t.Fatalf("client cert CN = %q, want d2-edge-1 (cert not tied to cluster id)", leaf.Subject.CommonName)
	}
	if err := ca.VerifyClientCert(leaf); err != nil {
		t.Fatalf("client cert does not verify against fed CA: %v", err)
	}
	// The credential row records exactly this cert's fingerprint (the binding).
	var fp string
	if err := pool.QueryRow(ctx,
		`SELECT cert_fingerprint FROM fed_credentials WHERE org_id=$1 AND cluster_id=$2`, orgID, "d2-edge-1").Scan(&fp); err != nil {
		t.Fatalf("read fed_credentials: %v", err)
	}
	if fp == "" || fp != auth.FedCertFingerprint(leaf) {
		t.Fatalf("stored fingerprint %q does not match issued cert", fp)
	}
}

// TestFedMTLS_SyncRequiresClientCert is the headline D2 acceptance check: with the cert
// bound, a poll that presents the matching client cert succeeds, while the SAME valid bearer
// WITHOUT the client cert (a leaked bearer) is rejected.
func TestFedMTLS_SyncRequiresClientCert(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	ca := fedTestCA(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)
	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{SecretTTL: time.Hour}).WithFedCA(ca)

	secret, certPEM, keyPEM, _ := joinWithCA(t, h, signer, orgID, "d2-edge-2")
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	srv := startFedMTLSServer(t, pool, signer, ca, h)

	// With the bound client cert: authenticated.
	if got := pollSync(t, fedTestClient(srv, &cert), srv, secret); got != http.StatusOK {
		t.Fatalf("poll WITH client cert = %d, want 200", got)
	}
	// Leaked bearer, NO client cert: rejected (this is the whole point of D2).
	if got := pollSync(t, fedTestClient(srv, nil), srv, secret); got != http.StatusForbidden {
		t.Fatalf("poll with bearer but NO client cert = %d, want 403", got)
	}
}

// TestFedMTLS_WrongJointCertRejected verifies one joint's client cert cannot authenticate
// another joint's bearer ticket: the cert must match the credential it is bound to.
func TestFedMTLS_WrongJointCertRejected(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	ca := fedTestCA(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)
	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{SecretTTL: time.Hour}).WithFedCA(ca)

	secretA, _, _, _ := joinWithCA(t, h, signer, orgID, "d2-edge-3a")
	_, certPEMB, keyPEMB, _ := joinWithCA(t, h, signer, orgID, "d2-edge-3b")
	certB, err := tls.X509KeyPair([]byte(certPEMB), []byte(keyPEMB))
	if err != nil {
		t.Fatal(err)
	}
	srv := startFedMTLSServer(t, pool, signer, ca, h)

	// Cluster A's bearer + cluster B's (validly CA-signed) client cert: the fingerprint /
	// CN bound to A's credential does not match B's cert -> rejected.
	if got := pollSync(t, fedTestClient(srv, &certB), srv, secretA); got != http.StatusForbidden {
		t.Fatalf("A's bearer + B's cert = %d, want 403", got)
	}
}

// TestFedMTLS_JointPollerPresentsCert exercises the joint half end to end: PersistJointJoin
// stores the cert material (key encrypted at rest), and reconcileFedSyncOrg then presents
// the per-joint client cert on its poll against the mTLS-enforcing master.
func TestFedMTLS_JointPollerPresentsCert(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	ca := fedTestCA(t, ctx, pool)
	signer := fedTestSigner(t, ctx, pool)
	sealer := testFedSealer(t)
	h := NewFederation(d, audit.New(pool)).WithFedTrust(signer, FedJoinConfig{SecretTTL: time.Hour}).WithFedCA(ca)

	secret, certPEM, keyPEM, _ := joinWithCA(t, h, signer, orgID, "d2-edge-4")
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM fed_joint_secret WHERE org_id=$1`, orgID) })

	srv := startFedMTLSServer(t, pool, signer, ca, h)
	// The joint pins the master's SERVER cert. In production that cert chains to the CA the
	// master hands out at join; here the httptest server uses its own self-signed cert, so we
	// pin that. (The client-cert presentation — the D2 behaviour under test — is unaffected.)
	masterCAPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err := PersistJointJoin(ctx, pool, sealer, orgID, "d2-edge-4", secret, certPEM, keyPEM, masterCAPEM); err != nil {
		t.Fatalf("PersistJointJoin: %v", err)
	}
	// The joint persisted the key ENCRYPTED, not as a plaintext PEM.
	var keyEnc []byte
	if err := pool.QueryRow(ctx, `SELECT client_key_enc FROM fed_joint_secret WHERE org_id=$1`, orgID).Scan(&keyEnc); err != nil {
		t.Fatalf("read fed_joint_secret: %v", err)
	}
	if bytes.Contains(keyEnc, []byte("PRIVATE KEY")) {
		t.Fatal("joint client key stored in plaintext (must be encrypted at rest)")
	}

	// The poller builds its mTLS client from the stored material and authenticates; an empty
	// revision log is a successful no-op (the auth is what we're proving here). The base
	// client (used only if no cert material) trusts the test server.
	base := fedTestClient(srv, nil)
	if err := reconcileFedSyncOrg(ctx, pool, sealer, base, srv.URL, "", orgID, nil); err != nil {
		t.Fatalf("reconcileFedSyncOrg with mTLS: %v", err)
	}
	// The poll counted as a heartbeat -> the member is active, proving auth succeeded.
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM fed_members WHERE org_id=$1 AND cluster_id=$2`, orgID, "d2-edge-4").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("member status = %q after mTLS poll, want active", status)
	}

	// Sanity: without the cert material the same poll would be rejected by the master. Drop
	// the cert from the joint row and confirm the poller now fails the mTLS gate.
	if _, err := pool.Exec(ctx, `UPDATE fed_joint_secret SET client_cert_pem='', client_key_enc=NULL WHERE org_id=$1`, orgID); err != nil {
		t.Fatal(err)
	}
	if err := reconcileFedSyncOrg(ctx, pool, sealer, base, srv.URL, "", orgID, nil); err == nil {
		t.Fatal("poll WITHOUT the client cert should fail the master's mTLS gate, got nil error")
	}
}
