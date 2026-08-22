package runtime

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// TestRuntimeDLPStore_InsertRecordsFedRevision covers NET-45's master-side hook:
// on a master org, creating a runtime_dlp rule records a fed_rule_revisions row
// (kind=runtime_dlp) carrying the rule so joints can replicate it. On a
// non-master org the hook no-ops (LogFedRevision guards on federation state).
func TestRuntimeDLPStore_InsertRecordsFedRevision(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"runtime_dlp_rules", "federation_state", "fed_rule_revisions"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'DLP Fed Test')`, orgID, "dlp-fed-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, 'dlp-fed-cluster', 'k3s', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO federation_state (org_id, state, revision) VALUES ($1,'master',1)`, orgID); err != nil {
		t.Fatalf("federation_state: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM fed_rule_revisions WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(bg, `DELETE FROM runtime_dlp_rules WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(bg, `DELETE FROM federation_state WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(bg, `DELETE FROM clusters WHERE id=$1`, clusterID)
		_, _ = pool.Exec(bg, `DELETE FROM orgs WHERE id=$1`, orgID)
	})

	store := NewRuntimeDLPStore(d, nil)
	rule := &DLPRule{
		OrgID: orgID, ClusterID: clusterID, Name: "fed-dlp-hook",
		Category: CategoryWAF, Severity: 5, Mode: DLPModeMonitor,
		Patterns: json.RawMessage(`["(?i)union\\s+select"]`),
	}
	id, err := store.Insert(ctx, rule, "req-1")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	var kind, ruleKey string
	if err := pool.QueryRow(ctx,
		`SELECT rule_kind, rule_id FROM fed_rule_revisions WHERE org_id=$1 ORDER BY revision DESC LIMIT 1`,
		orgID).Scan(&kind, &ruleKey); err != nil {
		t.Fatalf("read fed revision: %v", err)
	}
	if kind != "runtime_dlp" {
		t.Fatalf("fed revision kind = %q, want runtime_dlp", kind)
	}
	if ruleKey != id.String() {
		t.Fatalf("fed revision rule_id = %q, want %q", ruleKey, id.String())
	}
}
