package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/federation"
)

// TestPerformRemoteJoin_PersistsAndFlipsState mocks the master's POST /federation/join with
// an httptest server and verifies the joint half (FED-JOIN-25): performRemoteJoin calls the
// master, persists the issued secret + per-joint client cert (key sealed at rest) via
// PersistJointJoin, and flips federation_state to joint. This is the request/persist flow the
// JoinRemote handler drives.
func TestPerformRemoteJoin_PersistsAndFlipsState(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	sealer := testFedSealer(t)

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM fed_joint_secret WHERE org_id=$1`, orgID)
	})

	const (
		wantSecret = "ticket-abc"
		wantCert   = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
		wantKey    = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----"
		wantCA     = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"
	)

	// Mock master: assert the joint sent a well-formed join request, then return the
	// issued credential exactly like fed_trust.go Join does with the D2 CA wired.
	var gotReq fedJoinRequest
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/federation/join" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		_ = json.NewEncoder(w).Encode(fedMasterJoinResponse{
			ClusterID:  gotReq.ClusterID,
			Secret:     wantSecret,
			ClientCert: wantCert,
			ClientKey:  wantKey,
			CACert:     wantCA,
		})
	}))
	defer master.Close()

	res, err := performRemoteJoin(ctx, pool, sealer, master.Client(),
		orgID, master.URL, "join-token-xyz", "joint-edge-1", "edge-1")
	if err != nil {
		t.Fatalf("performRemoteJoin: %v", err)
	}

	// The joint identified itself with its cluster id/name and passed the join token through.
	if gotReq.JoinToken != "join-token-xyz" {
		t.Fatalf("master saw join_token=%q, want join-token-xyz", gotReq.JoinToken)
	}
	if gotReq.ClusterID != "joint-edge-1" || gotReq.ClusterName != "edge-1" {
		t.Fatalf("master saw cluster id/name = %q/%q, want joint-edge-1/edge-1", gotReq.ClusterID, gotReq.ClusterName)
	}
	if res.State != string(federation.StateJoint) || !res.MTLS || res.ClusterID != "joint-edge-1" {
		t.Fatalf("unexpected result: %+v", res)
	}

	// The credential landed in fed_joint_secret with the secret + cert, and the key SEALED
	// (never plaintext PEM) — the whole point of persisting through the at-rest cipher.
	var (
		secret, certPEM, caPEM string
		keyEnc                 []byte
	)
	if err := pool.QueryRow(ctx, `
SELECT secret, client_cert_pem, master_ca_pem, client_key_enc
  FROM fed_joint_secret WHERE org_id=$1`, orgID).
		Scan(&secret, &certPEM, &caPEM, &keyEnc); err != nil {
		t.Fatalf("read fed_joint_secret: %v", err)
	}
	if secret != wantSecret || certPEM != wantCert || caPEM != wantCA {
		t.Fatalf("persisted material mismatch: secret=%q cert=%q ca=%q", secret, certPEM, caPEM)
	}
	if len(keyEnc) == 0 {
		t.Fatal("client key was not persisted")
	}
	// It must be the SEALED blob, not the plaintext key.
	if string(keyEnc) == wantKey {
		t.Fatal("client key stored in plaintext (must be encrypted at rest)")
	}
	if opened, err := sealer.Open(keyEnc); err != nil || string(opened) != wantKey {
		t.Fatalf("sealed key did not round-trip: opened=%q err=%v", opened, err)
	}

	// federation_state flipped to joint, master_id = master URL.
	var state, masterID, clusterName string
	if err := pool.QueryRow(ctx,
		`SELECT state, master_id, cluster_name FROM federation_state WHERE org_id=$1`, orgID).
		Scan(&state, &masterID, &clusterName); err != nil {
		t.Fatalf("read federation_state: %v", err)
	}
	if state != string(federation.StateJoint) || masterID != master.URL || clusterName != "joint-edge-1" {
		t.Fatalf("federation_state = state:%q master_id:%q cluster_name:%q", state, masterID, clusterName)
	}
}

// TestPerformRemoteJoin_MasterError surfaces a non-200 from the master as an error and does
// NOT flip local state (a failed join must leave the joint standalone).
func TestPerformRemoteJoin_MasterError(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, ctx, pool)
	// fedTrustPreflight promotes the org to master; reset to standalone so we can assert the
	// failed join leaves it untouched.
	if _, err := pool.Exec(ctx, `UPDATE federation_state SET state='standalone' WHERE org_id=$1`, orgID); err != nil {
		t.Fatal(err)
	}

	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid or expired join token"}`, http.StatusUnauthorized)
	}))
	defer master.Close()

	if _, err := performRemoteJoin(ctx, pool, testFedSealer(t), master.Client(),
		orgID, master.URL, "bad-token", "joint-edge-2", "edge-2"); err == nil {
		t.Fatal("expected error from a 401 master, got nil")
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM federation_state WHERE org_id=$1`, orgID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "standalone" {
		t.Fatalf("federation_state = %q after a failed join, want standalone (unchanged)", state)
	}
}
