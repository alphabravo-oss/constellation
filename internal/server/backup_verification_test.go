package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestBackupVerificationEnforcesTrustScopeAndRBAC(t *testing.T) {
	t.Setenv("CONSTELLATION_BACKUP_ALLOW_UNVERIFIED", "false")
	t.Setenv("CONSTELLATION_BACKUP_DIR", t.TempDir())
	directory := t.TempDir()
	privateKey, publicKey := filepath.Join(directory, "private.pem"), filepath.Join(directory, "public.pem")
	if err := backup.GenerateEd25519Keypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTELLATION_BACKUP_VERIFY_KEY", publicKey)
	_, server, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	var signed, unsigned bytes.Buffer
	for _, artifact := range []struct {
		output *bytes.Buffer
		mode   backup.SignMode
	}{{&signed, backup.SignModeStaticKey}, {&unsigned, backup.SignModeNone}} {
		if _, err := backup.Export(context.Background(), pool, backup.ExportOptions{
			OrgID: orgID.String(), Out: artifact.output,
			Sign: backup.SignerOptions{Mode: artifact.mode, KeyPath: privateKey},
		}); err != nil {
			t.Fatal(err)
		}
	}
	post := func(path, token string, archive []byte) (int, map[string]any) {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(archive))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/gzip")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	for _, endpoint := range []string{"/api/v1/backups/verify", "/api/v1/backups/restore"} {
		if status, body := post(endpoint, auditor, signed.Bytes()); status != http.StatusForbidden {
			t.Fatalf("auditor accessed %s: %d %+v", endpoint, status, body)
		}
		if status, body := post(endpoint+"?allow_unverified=true", admin, unsigned.Bytes()); status != http.StatusBadRequest {
			t.Fatalf("request bypassed operator trust on %s: %d %+v", endpoint, status, body)
		}
	}
	status, body := post("/api/v1/backups/verify", admin, signed.Bytes())
	if status != http.StatusOK || body["verified"] != true || body["signer_identity"] == "" {
		t.Fatalf("signed preview: %d %+v", status, body)
	}
	var audits int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='backup.verify' AND after->>'verified'='true'`, orgID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("verified preview audit: count=%d err=%v", audits, err)
	}
	_, otherServer, _, otherSigner, otherAdminID, _, otherOrgID := newSysConfigTestServer(t)
	foreignToken := issueFor(t, otherSigner, otherAdminID, otherOrgID, 0)
	request, _ := http.NewRequest(http.MethodPost, otherServer.URL+"/api/v1/backups/verify", bytes.NewReader(signed.Bytes()))
	request.Header.Set("Authorization", "Bearer "+foreignToken)
	response, err := otherServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("foreign archive accepted: %d %s", response.StatusCode, payload)
	}
	t.Setenv("CONSTELLATION_BACKUP_ALLOW_UNVERIFIED", "true")
	status, body = post("/api/v1/backups/verify", admin, unsigned.Bytes())
	if status != http.StatusOK || body["verified"] != false || body["signer_identity"] != nil {
		t.Fatalf("unsigned preview acquired trusted identity: %d %+v", status, body)
	}
}
