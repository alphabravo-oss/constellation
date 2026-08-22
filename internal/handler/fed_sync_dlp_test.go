package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

// TestFedSync_RuntimeDLPReplicates covers NET-45: a master runtime_dlp mutation
// writes a fed_rule_revisions row (kind=runtime_dlp); a joint poll advances
// `since` and replicates the rule read-only into fed_runtime_profiles
// (cfg_type='fed'), whence the DLP agent-bundle serving path merges it. Mirrors
// TestFedSync_MasterMutationWritesRevisionAndJointApplies but for the P2-3
// generic-table runtime kind rather than the policies path.
func TestFedSync_RuntimeDLPReplicates(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"fed_runtime_profiles", "federation_state", "fed_rule_revisions", "fed_sync_state"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}

	ruleID := uuid.New()
	_, _ = pool.Exec(ctx, `DELETE FROM fed_runtime_profiles WHERE org_id=$1 AND rule_kind IN ('runtime_dlp')`, orgID)
	_, _ = pool.Exec(ctx, `DELETE FROM fed_rule_revisions WHERE org_id=$1`, orgID)
	_, _ = pool.Exec(ctx, `DELETE FROM fed_sync_state WHERE org_id=$1`, orgID)

	if _, err := pool.Exec(ctx, `
INSERT INTO federation_state (org_id, state, revision) VALUES ($1,'master',1)
ON CONFLICT (org_id) DO UPDATE SET state='master'`, orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM fed_runtime_profiles WHERE org_id=$1 AND rule_kind IN ('runtime_dlp')`, orgID)
		_, _ = pool.Exec(bg, `DELETE FROM fed_rule_revisions WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(bg, `DELETE FROM fed_sync_state WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(bg, `UPDATE federation_state SET state='standalone' WHERE org_id=$1`, orgID)
	})

	// Master side: a DLP rule mutation records a fed revision under kind=runtime_dlp,
	// carrying the agent-bundle row shape the joint's DLP bundle serves. This is the
	// exact call the runtime store's Insert/Update/SetMode hooks make via
	// recordFedDLPRule → LogFedRevision.
	payload := map[string]any{
		"id": ruleID.String(), "org_id": orgID.String(), "name": "fedsync-test-dlp",
		"category": "waf", "apply_dir": 2, "severity": 5, "mode": "enforce",
		"patterns": json.RawMessage(`["(?i)union\\s+select"]`),
	}
	logFedRevision(ctx, pool, orgID, FedKindRuntimeDLP, ruleID.String(), payload)

	var revCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM fed_rule_revisions WHERE org_id=$1 AND rule_kind=$2`, orgID, FedKindRuntimeDLP).Scan(&revCount); err != nil {
		t.Fatal(err)
	}
	if revCount != 1 {
		t.Fatalf("expected 1 runtime_dlp fed revision row, got %d", revCount)
	}

	// Master-side Sync endpoint served over httptest so the joint poller can GET it.
	fedH := NewFederation(d, audit.New(pool))
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/federation/sync", func(sw http.ResponseWriter, sr *http.Request) {
		sr = sr.WithContext(WithSubject(sr.Context(), Subject{UserID: userID, OrgID: orgID}))
		fedH.Sync(sw, sr)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var env syncResponse
	resp, err := http.Get(srv.URL + "/api/v1/federation/sync?since=0")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&env)
	resp.Body.Close()
	if len(env.Revisions) != 1 || env.Revisions[0].Kind != FedKindRuntimeDLP {
		t.Fatalf("unexpected sync envelope: %+v", env)
	}

	// Joint side: poll for the same org. The poller applies the revision into
	// fed_runtime_profiles as a read-only fed row and advances `since`.
	if err := reconcileFedSyncOrg(ctx, pool, nil, srv.Client(), srv.URL, "", orgID, nil); err != nil {
		t.Fatalf("reconcileFedSyncOrg: %v", err)
	}

	var since int64
	if err := pool.QueryRow(ctx, `SELECT last_synced_revision FROM fed_sync_state WHERE org_id=$1`, orgID).Scan(&since); err != nil {
		t.Fatalf("read last_synced_revision: %v", err)
	}
	if since != env.Revisions[0].Revision {
		t.Fatalf("last_synced_revision = %d, want %d", since, env.Revisions[0].Revision)
	}

	var cfgType, gotKey string
	if err := pool.QueryRow(ctx,
		`SELECT cfg_type, rule_key FROM fed_runtime_profiles WHERE org_id=$1 AND rule_kind=$2`,
		orgID, FedKindRuntimeDLP).Scan(&cfgType, &gotKey); err != nil {
		t.Fatalf("read fed runtime_dlp row: %v", err)
	}
	if cfgType != "fed" {
		t.Fatalf("fed runtime_dlp cfg_type = %q, want fed", cfgType)
	}
	if gotKey != ruleID.String() {
		t.Fatalf("fed runtime_dlp rule_key = %q, want %q", gotKey, ruleID.String())
	}

	// Re-polling at the advanced `since` is an idempotent no-op.
	if err := reconcileFedSyncOrg(ctx, pool, nil, srv.Client(), srv.URL, "", orgID, nil); err != nil {
		t.Fatalf("re-poll: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM fed_runtime_profiles WHERE org_id=$1 AND rule_kind=$2`, orgID, FedKindRuntimeDLP).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 fed runtime_dlp row after re-poll, got %d", n)
	}

	// Tombstone: a master delete drops the joint's fed copy.
	logFedRevision(ctx, pool, orgID, FedKindRuntimeDLP+"_delete", ruleID.String(), map[string]string{"id": ruleID.String()})
	if err := reconcileFedSyncOrg(ctx, pool, nil, srv.Client(), srv.URL, "", orgID, nil); err != nil {
		t.Fatalf("reconcile after tombstone: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM fed_runtime_profiles WHERE org_id=$1 AND rule_kind=$2`, orgID, FedKindRuntimeDLP).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected fed runtime_dlp row removed after tombstone, got %d", n)
	}
}
