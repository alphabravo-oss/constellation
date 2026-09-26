package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

type migrationGroupGuardFixture struct {
	*migrationRemainingFixture
	cluster uuid.UUID
}

func newMigrationGroupGuardFixture(t *testing.T) *migrationGroupGuardFixture {
	t.Helper()
	base := newMigrationRemainingFixture(t)
	clusterID := uuid.New()
	if _, err := base.d.Pool().Exec(context.Background(), `INSERT INTO clusters (id, org_id, name, state) VALUES ($1,$2,'migration-group-guard','connected')`, clusterID, base.org); err != nil {
		t.Fatal(err)
	}
	return &migrationGroupGuardFixture{migrationRemainingFixture: base, cluster: clusterID}
}

func (fixture *migrationGroupGuardFixture) seedGroup(name string, clusterID uuid.UUID) uuid.UUID {
	fixture.t.Helper()
	groupID := uuid.New()
	if _, err := fixture.d.Pool().Exec(context.Background(), `
INSERT INTO groups (id, org_id, cluster_id, name, kind, criteria, members, cfg_type)
VALUES ($1,$2,$3,$4,'ground','[]'::jsonb,'[]'::jsonb,'user')`, groupID, fixture.org, clusterID, name); err != nil {
		fixture.t.Fatal(err)
	}
	return groupID
}

func (fixture *migrationGroupGuardFixture) seedEdge(fromGroup, toGroup string) {
	fixture.t.Helper()
	if _, err := fixture.d.Pool().Exec(context.Background(), `
INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group)
VALUES ($1,$2,$3,$4)`, fixture.org, fixture.cluster, fromGroup, toGroup); err != nil {
		fixture.t.Fatal(err)
	}
}

func TestMigrationApplyGroupReferenceConflictKeepsPreview(t *testing.T) {
	fixture := newMigrationGroupGuardFixture(t)
	ensureMigrationImportsTestTable(t, fixture.d)
	fixture.seedGroup("guard-api", fixture.cluster)
	fixture.seedEdge("guard-api", "external")
	preview := migrationPreviewDTO{Groups: []migrationPreviewGroupDTO{{
		Name: "guard-api", ClusterID: fixture.cluster.String(), Kind: "ground",
		Criteria: []portableGroupCriterion{{Key: "namespace", Op: "eq", Value: "prod"}},
	}}}
	previewRaw, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	importID := uuid.New()
	if _, err := fixture.d.Pool().Exec(context.Background(), `
INSERT INTO migration_imports (id, org_id, source, source_hash, preview_json, created_by)
VALUES ($1,$2,'neuvector',$3,$4::jsonb,$5)`, importID, fixture.org, importID.String(), previewRaw, fixture.user); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	fixture.h.MigrationApply(response, migrationActionRequest(http.MethodPost, "/migration/apply", importID.String(), fixture.org, fixture.user))
	if response.Code != http.StatusConflict {
		t.Fatalf("referenced group changed: status=%d body=%s", response.Code, response.Body.String())
	}
	var status, criteria string
	if err := fixture.d.Pool().QueryRow(context.Background(), `
SELECT (SELECT status FROM migration_imports WHERE id=$1), (SELECT criteria::text FROM groups WHERE org_id=$2 AND name='guard-api')`, importID, fixture.org).Scan(&status, &criteria); err != nil {
		t.Fatal(err)
	}
	if status != "previewed" || criteria != "[]" {
		t.Fatalf("conflict changed import/group: status=%s criteria=%s", status, criteria)
	}
}

func TestMigrationNetworkEdgeReferentsAreScopedAndLocked(t *testing.T) {
	fixture := newMigrationGroupGuardFixture(t)
	fixture.seedGroup("guard-api", fixture.cluster)
	otherCluster := uuid.New()
	if _, err := fixture.d.Pool().Exec(context.Background(), `INSERT INTO clusters (id, org_id, name, state) VALUES ($1,$2,'other','connected')`, otherCluster, fixture.org); err != nil {
		t.Fatal(err)
	}
	fixture.seedGroup("other-cluster", otherCluster)
	foreignOrg := uuid.New()
	foreignCluster := uuid.New()
	if _, err := fixture.d.Pool().Exec(context.Background(), `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'foreign migration group')`, foreignOrg, "migration-foreign-"+foreignOrg.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = fixture.d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, foreignOrg)
	})
	if _, err := fixture.d.Pool().Exec(context.Background(), `INSERT INTO clusters (id, org_id, name, state) VALUES ($1,$2,'foreign','connected')`, foreignCluster, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.d.Pool().Exec(context.Background(), `INSERT INTO groups (org_id, cluster_id, name, kind) VALUES ($1,$2,'foreign-only','ground')`, foreignOrg, foreignCluster); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/migration/apply", nil)
	for _, destination := range []string{"missing", "other-cluster", "foreign-only"} {
		tx, err := fixture.d.Pool().Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := lockMigrationGroupReferences(request, tx, fixture.org, false, true); err != nil {
			t.Fatal(err)
		}
		_, _, err = fixture.h.applyMigrationNetworkRules(request, tx, Subject{OrgID: fixture.org, UserID: fixture.user}, []migrationPreviewNetworkRuleDTO{{
			Name: "guard-edge", ClusterID: fixture.cluster.String(), FromGroup: "guard-api", ToGroup: destination,
		}})
		if !errors.Is(err, errMigrationGroupConflict) {
			t.Fatalf("destination %s was accepted or not a conflict: %v", destination, err)
		}
		_ = tx.Rollback(context.Background())
	}
	blocker, err := fixture.d.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(context.Background(), `SELECT 1 FROM groups WHERE org_id=$1 AND name='guard-api' FOR UPDATE`, fixture.org); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.d.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := lockMigrationGroupReferences(request, tx, fixture.org, false, true); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = migrationNetworkGroupsExist(request, tx, fixture.org, fixture.cluster, "guard-api", "external")
	if !errors.Is(err, errMigrationGroupConflict) || time.Since(started) > time.Second {
		t.Fatalf("locked referent did not fail promptly: %v", err)
	}
}

func TestMigrationRollbackRejectsExternallyReferencedGroupAndMissingEdgeReferent(t *testing.T) {
	fixture := newMigrationGroupGuardFixture(t)
	groupID := fixture.seedGroup("guard-api", fixture.cluster)
	request := httptest.NewRequest(http.MethodPost, "/migration/rollback", nil)
	fixture.seedEdge("guard-api", "external")
	tx, err := fixture.d.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := lockMigrationGroupReferences(request, tx, fixture.org, true, false); err != nil {
		t.Fatal(err)
	}
	_, _, err = fixture.h.rollbackMigrationGroups(request, tx, fixture.org, []migrationGroupRollbackDTO{{Name: "guard-api", Action: "delete", ID: groupID.String()}})
	if !errors.Is(err, errMigrationGroupConflict) {
		t.Fatalf("referenced group was deleted: %v", err)
	}
	_, _, err = fixture.h.rollbackMigrationGroups(request, tx, fixture.org, []migrationGroupRollbackDTO{{
		Name: "guard-api", Action: "restore", ID: groupID.String(),
		Before: &groupRollbackSnapshot{
			ID: groupID.String(), ClusterID: fixture.cluster.String(), Name: "guard-api", Kind: "ground",
			Criteria: json.RawMessage(`[ {"key":"namespace","op":"eq","value":"prod"} ]`), Members: json.RawMessage(`[]`), CfgType: "user",
		},
	}})
	if !errors.Is(err, errMigrationGroupConflict) {
		t.Fatalf("referenced group selector was restored: %v", err)
	}
	_ = tx.Rollback(context.Background())
	tx, err = fixture.d.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := lockMigrationGroupReferences(request, tx, fixture.org, false, true); err != nil {
		t.Fatal(err)
	}
	_, _, err = fixture.h.rollbackMigrationNetworkRules(request, tx, fixture.org, []migrationNetworkRuleRollbackDTO{{
		Action: "restore", Before: &networkRuleRollbackSnapshot{ID: uuid.New().String(), ClusterID: fixture.cluster.String(), FromGroup: "guard-api", ToGroup: "deleted-group"},
	}})
	if !errors.Is(err, errMigrationGroupConflict) {
		t.Fatalf("edge rollback accepted missing referent: %v", err)
	}
}

func TestMigrationRollbackConflictPreservesAppliedImport(t *testing.T) {
	fixture := newMigrationGroupGuardFixture(t)
	ensureMigrationImportsTestTable(t, fixture.d)
	previewRaw, err := json.Marshal(migrationPreviewDTO{Groups: []migrationPreviewGroupDTO{{
		Name: "guard-created", ClusterID: fixture.cluster.String(), Kind: "ground",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	importID := uuid.New()
	if _, err := fixture.d.Pool().Exec(context.Background(), `
INSERT INTO migration_imports (id, org_id, source, source_hash, preview_json, created_by)
VALUES ($1,$2,'neuvector',$3,$4::jsonb,$5)`, importID, fixture.org, importID.String(), previewRaw, fixture.user); err != nil {
		t.Fatal(err)
	}
	apply := httptest.NewRecorder()
	fixture.h.MigrationApply(apply, migrationActionRequest(http.MethodPost, "/migration/apply", importID.String(), fixture.org, fixture.user))
	if apply.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}
	fixture.seedEdge("guard-created", "external")
	rollback := httptest.NewRecorder()
	fixture.h.MigrationRollback(rollback, migrationActionRequest(http.MethodPost, "/migration/rollback", importID.String(), fixture.org, fixture.user))
	if rollback.Code != http.StatusConflict {
		t.Fatalf("referenced rollback status=%d body=%s", rollback.Code, rollback.Body.String())
	}
	var status string
	var groupCount int
	if err := fixture.d.Pool().QueryRow(context.Background(), `
SELECT (SELECT status FROM migration_imports WHERE id=$1), (SELECT count(*) FROM groups WHERE org_id=$2 AND name='guard-created')`, importID, fixture.org).Scan(&status, &groupCount); err != nil {
		t.Fatal(err)
	}
	if status != "applied" || groupCount != 1 {
		t.Fatalf("failed rollback changed import/group: %s/%d", status, groupCount)
	}
	if _, err := fixture.d.Pool().Exec(context.Background(), `DELETE FROM group_rule_edges WHERE org_id=$1 AND from_group='guard-created'`, fixture.org); err != nil {
		t.Fatal(err)
	}
	rollback = httptest.NewRecorder()
	fixture.h.MigrationRollback(rollback, migrationActionRequest(http.MethodPost, "/migration/rollback", importID.String(), fixture.org, fixture.user))
	if rollback.Code != http.StatusOK {
		t.Fatalf("retry rollback status=%d body=%s", rollback.Code, rollback.Body.String())
	}
}

func TestMigrationGroupReferenceLockWaitsForConcurrentWriter(t *testing.T) {
	fixture := newMigrationGroupGuardFixture(t)
	writer, err := fixture.d.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(context.Background())
	if _, err := writer.Exec(context.Background(), `INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group) VALUES ($1,$2,'pending','external')`, fixture.org, fixture.cluster); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.d.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- lockMigrationGroupReferences(httptest.NewRequest(http.MethodPost, "/migration/apply", nil), tx, fixture.org, true, true)
	}()
	select {
	case err := <-result:
		t.Fatalf("lock completed before writer committed: %v", err)
	case <-time.After(120 * time.Millisecond):
	}
	if err := writer.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("lock did not succeed after writer committed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lock did not finish after writer committed")
	}
}

func TestMigrationGroupReferenceLockRejectsConcurrentOrgDelete(t *testing.T) {
	fixture := newMigrationGroupGuardFixture(t)
	deleting, err := fixture.d.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer deleting.Rollback(context.Background())
	if _, err := deleting.Exec(context.Background(), `SELECT id FROM orgs WHERE id=$1 FOR UPDATE`, fixture.org); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.d.Pool().Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	started := time.Now()
	err = lockMigrationGroupReferences(httptest.NewRequest(http.MethodPost, "/migration/apply", nil), tx, fixture.org, true, false)
	if !errors.Is(err, errMigrationGroupConflict) || time.Since(started) > time.Second {
		t.Fatalf("concurrent organization delete did not yield a prompt conflict: %v", err)
	}
}
