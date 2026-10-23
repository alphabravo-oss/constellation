//go:build integration

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

// Exercise the real HTTP authorization and archive exporter together. An operator's
// unsigned-backup opt-in must not relax tenant or manage-users authorization.
func TestBackupRestorePinsTenantAndIdentityScope(t *testing.T) {
	t.Setenv("CONSTELLATION_BACKUP_ALLOW_UNVERIFIED", "true")
	t.Setenv("CONSTELLATION_BACKUP_DIR", t.TempDir())
	_, server, pool, signer, adminID, _, orgID := newSysConfigTestServer(t)
	_, otherServer, _, otherSigner, otherAdminID, _, otherOrgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	otherAdmin := issueFor(t, otherSigner, otherAdminID, otherOrgID, 0)
	raw, hash := mintTestPAT(t)
	if _, err := pool.Exec(t.Context(), `INSERT INTO api_tokens(id,user_id,name,token_hash,scopes,status)
 VALUES($1,$2,'restore scope',$3,'["manage-org"]','active')`, uuid.New(), adminID, hash); err != nil {
		t.Fatal(err)
	}
	for _, org := range []uuid.UUID{orgID, otherOrgID} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO policies(org_id,name,engine,category,spec_yaml)
  VALUES($1,'restore-proof','opa-rego','admission','package archived')`, org); err != nil {
			t.Fatal(err)
		}
	}
	var archive bytes.Buffer
	if _, err := backup.Export(t.Context(), pool, backup.ExportOptions{OrgID: orgID.String(), Out: &archive, Sign: backup.SignerOptions{Mode: backup.SignModeNone}}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE policies SET spec_yaml='package current' WHERE name='restore-proof'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE users SET display_name='Current admin' WHERE id=$1`, adminID); err != nil {
		t.Fatal(err)
	}

	restore := func(target *httptest.Server, token string) (int, backup.RestoreResult) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target.URL+"/api/v1/backups/restore?on_conflict=overwrite&allow_unverified=true", bytes.NewReader(archive.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/gzip")
		response, err := target.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result backup.RestoreResult
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, result
	}
	assertState := func(wantPolicy, wantAdmin string) {
		t.Helper()
		var policy, otherPolicy, display string
		var policies, users int
		if err := pool.QueryRow(t.Context(), `SELECT
   (SELECT spec_yaml FROM policies WHERE org_id=$1 AND name='restore-proof'),
   (SELECT spec_yaml FROM policies WHERE org_id=$2 AND name='restore-proof'),
   (SELECT display_name FROM users WHERE id=$3),
   (SELECT count(*) FROM policies WHERE org_id IN ($1,$2)),
   (SELECT count(*) FROM users WHERE org_id IN ($1,$2))`, orgID, otherOrgID, adminID).Scan(&policy, &otherPolicy, &display, &policies, &users); err != nil {
			t.Fatal(err)
		}
		if policy != wantPolicy || otherPolicy != "package current" || display != wantAdmin || policies != 2 || users != 4 {
			t.Fatalf("restore escaped its scope: policy=%q other=%q admin=%q policies=%d users=%d", policy, otherPolicy, display, policies, users)
		}
	}
	if status, _ := restore(otherServer, otherAdmin); status != http.StatusBadRequest {
		t.Fatalf("foreign restore status=%d, want 400", status)
	}
	assertState("package current", "Current admin")
	for range 2 {
		status, result := restore(server, raw)
		if status != http.StatusOK {
			t.Fatalf("manage-org restore status=%d, want 200", status)
		}
		if result.Verified {
			t.Fatal("unsigned restore reported verified")
		}
		var skippedUsers int64
		for _, table := range result.Tables {
			if table.Name == "users" {
				skippedUsers = table.Skipped
			}
		}
		if skippedUsers != 2 {
			t.Fatalf("manage-org restore skipped %d users, want 2", skippedUsers)
		}
		assertState("package archived", "Current admin")
	}
	if status, _ := restore(server, admin); status != http.StatusOK {
		t.Fatalf("manage-users restore status=%d, want 200", status)
	}
	assertState("package archived", "GlobalAdmin")
}
