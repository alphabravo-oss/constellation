package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/federation"
)

func fedGroupTestOrg(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	orgID, clusterID := uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO orgs (id,name,display_name) VALUES ($1,$2,'Fed group guard')`, orgID, "fed-guard-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID) })
	if _, err := pool.Exec(context.Background(), `INSERT INTO clusters (id,org_id,name,state) VALUES ($1,$2,$3,'connected')`, clusterID, orgID, "fed-guard-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	return orgID, clusterID
}

func fedGroupTestRevision(t *testing.T, kind string, payload fedSyncPayload) federation.RuleRevision {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return federation.RuleRevision{Kind: kind, RuleID: payload.Name, Payload: raw}
}

func TestFedGroupRevisionRejectsReferencesAndPreservesLocalGroups(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ctx := context.Background()
	orgID, clusterID := fedGroupTestOrg(t, pool)
	for _, family := range []string{"network", "dpi", "response", "admission"} {
		t.Run(family, func(t *testing.T) {
			name := "fed-" + family
			original := fedSyncPayload{Name: name, Comment: "before", Criteria: json.RawMessage(`[{"key":"namespace","op":"eq","value":"before"}]`)}
			if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group", original)); err != nil {
				t.Fatal(err)
			}
			var groupID uuid.UUID
			if err := pool.QueryRow(ctx, `SELECT id FROM groups WHERE org_id=$1 AND name=$2`, orgID, name).Scan(&groupID); err != nil {
				t.Fatal(err)
			}
			var remove string
			switch family {
			case "network":
				_, err := pool.Exec(ctx, `INSERT INTO group_rule_edges (org_id,cluster_id,from_group,to_group) VALUES ($1,$2,$3,'external')`, orgID, clusterID, name)
				if err != nil {
					t.Fatal(err)
				}
				remove = `DELETE FROM group_rule_edges WHERE org_id=$1`
			case "dpi":
				sensorID := uuid.New()
				if _, err := pool.Exec(ctx, `INSERT INTO dlp_sensors (id,org_id,name,cfg_type) VALUES ($1,$2,$3,'user')`, sensorID, orgID, name); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(ctx, `INSERT INTO group_dpi_sensor_bindings (org_id,group_id,sensor_kind,sensor_id) VALUES ($1,$2,'dlp',$3)`, orgID, groupID, sensorID); err != nil {
					t.Fatal(err)
				}
				remove = `DELETE FROM group_dpi_sensor_bindings WHERE org_id=$1`
			case "response":
				if _, err := pool.Exec(ctx, `INSERT INTO response_rules_v2 (org_id,name,event_type,workload_match) VALUES ($1,$2,'runtime',$3::jsonb)`, orgID, name, `{"group":"`+groupID.String()+`"}`); err != nil {
					t.Fatal(err)
				}
				remove = `DELETE FROM response_rules_v2 WHERE org_id=$1`
			case "admission":
				if _, err := pool.Exec(ctx, `INSERT INTO policies (org_id,name,engine,category,spec_yaml) VALUES ($1,$2,'constellation-admission','admission',$3)`, orgID, name, fedAdmissionSpec(name)); err != nil {
					t.Fatal(err)
				}
				remove = `DELETE FROM policies WHERE org_id=$1`
			}
			commentOnly := original
			commentOnly.Comment = "safe comment"
			if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group", commentOnly)); err != nil {
				t.Fatalf("comment update: %v", err)
			}
			changed := commentOnly
			changed.Criteria = json.RawMessage(`[{"key":"namespace","op":"eq","value":"after"}]`)
			if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group", changed)); err == nil || !strings.Contains(err.Error(), "policy references") {
				t.Fatalf("referenced criteria update: %v", err)
			}
			if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group_delete", original)); err == nil || !strings.Contains(err.Error(), "policy references") {
				t.Fatalf("referenced delete: %v", err)
			}
			var criteria []byte
			if err := pool.QueryRow(ctx, `SELECT criteria FROM groups WHERE id=$1`, groupID).Scan(&criteria); err != nil || !strings.Contains(string(criteria), "before") {
				t.Fatalf("group changed: criteria=%s err=%v", criteria, err)
			}
			if _, err := pool.Exec(ctx, remove, orgID); err != nil {
				t.Fatal(err)
			}
			if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group_delete", original)); err != nil {
				t.Fatalf("unreferenced delete: %v", err)
			}
		})
	}
	local := fedSyncPayload{Name: "local-collision"}
	if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id,name,kind,comment,cfg_type) VALUES ($1,$2,'ground','local','user')`, orgID, local.Name); err != nil {
		t.Fatal(err)
	}
	if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group", local)); err == nil {
		t.Fatal("federated upsert overwrote local group")
	}
	if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group_delete", local)); err != nil {
		t.Fatal(err)
	}
	var cfgType string
	if err := pool.QueryRow(ctx, `SELECT cfg_type FROM groups WHERE org_id=$1 AND name=$2`, orgID, local.Name).Scan(&cfgType); err != nil || cfgType != "user" {
		t.Fatalf("local group lost: cfg=%q err=%v", cfgType, err)
	}
}

func fedAdmissionSpec(selector string) string {
	return "kind: AdmissionRule\nspec:\n  match:\n    groups: [\"" + selector + "\"]\n  action: deny\n"
}

func TestFedAdmissionRevisionValidatesGroupSelectors(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ctx := context.Background()
	orgID, clusterID := fedGroupTestOrg(t, pool)
	otherOrgID, _ := fedGroupTestOrg(t, pool)
	group := fedSyncPayload{Name: "fed-valid"}
	if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group", group)); err != nil {
		t.Fatal(err)
	}
	var groupID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM groups WHERE org_id=$1 AND name=$2`, orgID, group.Name).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id,cluster_id,name,kind) VALUES ($1,$2,'fed-cluster-only','ground')`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id,name,kind) VALUES ($1,'fed-foreign','ground')`, otherOrgID); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"missing", "fed-cluster-only", "fed-foreign"} {
		payload := fedSyncPayload{Name: "fed-policy-" + selector, Engine: "constellation-admission", Category: "admission", SpecYAML: fedAdmissionSpec(selector), Mode: "monitor"}
		if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "admission_policy", payload)); err == nil {
			t.Fatalf("accepted selector %q", selector)
		}
	}
	for _, kind := range []string{"policy", "admission_policy"} {
		payload := fedSyncPayload{Name: "fed-policy-" + kind, Engine: "constellation-admission", Category: "admission", SpecYAML: fedAdmissionSpec(groupID.String()), Mode: "monitor"}
		if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, kind, payload)); err != nil {
			t.Fatalf("valid %s: %v", kind, err)
		}
	}
	if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group_delete", group)); err == nil {
		t.Fatal("federated admission selectors did not block delete")
	}
}

func TestFedGroupRevisionWaitsForReferenceWriter(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ctx := context.Background()
	orgID, clusterID := fedGroupTestOrg(t, pool)
	group := fedSyncPayload{Name: "fed-race"}
	if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group", group)); err != nil {
		t.Fatal(err)
	}
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	if _, err := writer.Exec(ctx, `INSERT INTO group_rule_edges (org_id,cluster_id,from_group,to_group) VALUES ($1,$2,$3,'external')`, orgID, clusterID, group.Name); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	deleteRevision := fedGroupTestRevision(t, "group_delete", group)
	go func() { result <- applyFedRevision(ctx, pool, orgID, deleteRevision) }()
	select {
	case err := <-result:
		t.Fatalf("deleted before reference committed: %v", err)
	case <-time.After(120 * time.Millisecond):
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "policy references") {
			t.Fatalf("delete after commit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("federated delete did not finish")
	}
}

func TestFedAdmissionRevisionRejectsGroupRenamedDuringWrite(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ctx := context.Background()
	orgID, _ := fedGroupTestOrg(t, pool)
	group := fedSyncPayload{Name: "fed-selector-race"}
	if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group", group)); err != nil {
		t.Fatal(err)
	}
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	if _, err := writer.Exec(ctx, `UPDATE groups SET name='fed-selector-renamed' WHERE org_id=$1 AND name=$2`, orgID, group.Name); err != nil {
		t.Fatal(err)
	}
	payload := fedSyncPayload{Name: "fed-admission-race", Engine: "constellation-admission", Category: "admission", SpecYAML: fedAdmissionSpec(group.Name), Mode: "monitor"}
	revision := fedGroupTestRevision(t, "admission_policy", payload)
	result := make(chan error, 1)
	go func() { result <- applyFedRevision(ctx, pool, orgID, revision) }()
	select {
	case err := <-result:
		t.Fatalf("admission write finished before group rename committed: %v", err)
	case <-time.After(120 * time.Millisecond):
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("replicated admission policy retained a stale group selector")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admission writer did not finish")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM policies WHERE org_id=$1 AND name=$2`, orgID, payload.Name).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale admission policy saved: count=%d err=%v", count, err)
	}
}

func TestFedPurgeRollsBackWhenAnyGroupIsReferenced(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ctx := context.Background()
	orgID, _ := fedGroupTestOrg(t, pool)
	for _, name := range []string{"fed-purge-one", "fed-purge-two"} {
		if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group", fedSyncPayload{Name: name})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO policies (org_id,name,engine,category,spec_yaml,cfg_type) VALUES ($1,'local-reference','constellation-admission','admission',$2,'user')`, orgID, fedAdmissionSpec("fed-purge-two")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO policies (org_id,name,engine,category,spec_yaml,cfg_type) VALUES ($1,'fed-purge-policy','kyverno','admission','{}','fed')`, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fed_sync_state (org_id,last_synced_revision) VALUES ($1,7)`, orgID); err != nil {
		t.Fatal(err)
	}
	if err := purgeFedRows(ctx, pool, orgID); err == nil || !strings.Contains(err.Error(), "policy references") {
		t.Fatalf("purge should roll back: %v", err)
	}
	var groups, policies, cursor int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM groups WHERE org_id=$1 AND cfg_type='fed'`, orgID).Scan(&groups); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM policies WHERE org_id=$1 AND cfg_type='fed'`, orgID).Scan(&policies); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM fed_sync_state WHERE org_id=$1`, orgID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if groups != 2 || policies != 1 || cursor != 1 {
		t.Fatalf("partial purge: groups=%d policies=%d cursor=%d", groups, policies, cursor)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM policies WHERE org_id=$1 AND name='local-reference'`, orgID); err != nil {
		t.Fatal(err)
	}
	if err := purgeFedRows(ctx, pool, orgID); err != nil {
		t.Fatalf("unreferenced purge: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM groups WHERE org_id=$1 AND cfg_type='fed'`, orgID).Scan(&groups); err != nil || groups != 0 {
		t.Fatalf("groups remain: %d %v", groups, err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM policies WHERE org_id=$1 AND cfg_type='fed'`, orgID).Scan(&policies); err != nil || policies != 0 {
		t.Fatalf("policies remain: %d %v", policies, err)
	}
}

func TestFedConcurrentPurgesDoNotDeadlock(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	orgID, _ := fedGroupTestOrg(t, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := applyFedRevision(ctx, pool, orgID, fedGroupTestRevision(t, "group", fedSyncPayload{Name: "fed-concurrent-purge"})); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for attempt := 0; attempt < 2; attempt++ {
		go func() {
			<-start
			results <- purgeFedRows(ctx, pool, orgID)
		}()
	}
	close(start)
	for attempt := 0; attempt < 2; attempt++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent purge: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent purge timed out")
		}
	}
}
