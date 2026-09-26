package runtime

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/group"
)

func learnedGroupFixture(t *testing.T, database *db.DB) (uuid.UUID, uuid.UUID, group.Group) {
	t.Helper()
	ctx := context.Background()
	orgID, clusterID := uuid.New(), uuid.New()
	if _, err := database.Pool().Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "learned-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	if _, err := database.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'learned-test')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	return orgID, clusterID, group.Group{
		Name: "learned-test-service", Kind: group.KindLearned,
		Criteria: []group.Criterion{{Key: "namespace", Value: "default", Op: group.OpEq}},
		Members:  []string{"default/service"}, LearnedFrom: "service", CfgType: "learned",
	}
}

func TestLearnedGroupRefreshIdempotentAndDoesNotClobberAuthoredGroups(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	orgID, clusterID, learned := learnedGroupFixture(t, database)
	ctx := context.Background()
	worker := NewLearnedGroupWorker(database, LearnedGroupWorkerConfig{}, nil)
	if err := worker.upsertLearnedGroup(ctx, orgID, &clusterID, learned); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := database.Pool().QueryRow(ctx, `UPDATE groups SET policy_mode='protect', profile_mode='monitor', updated_at='2000-01-01' WHERE org_id=$1 AND name=$2 RETURNING id`, orgID, learned.Name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := worker.upsertLearnedGroup(ctx, orgID, &clusterID, learned); err != nil {
		t.Fatal(err)
	}
	var actualID uuid.UUID
	var policyMode, profileMode string
	var updatedAt time.Time
	if err := database.Pool().QueryRow(ctx, `SELECT id, policy_mode, profile_mode, updated_at FROM groups WHERE org_id=$1 AND name=$2`, orgID, learned.Name).Scan(&actualID, &policyMode, &profileMode, &updatedAt); err != nil {
		t.Fatal(err)
	}
	if actualID != id || policyMode != "protect" || profileMode != "monitor" || updatedAt.Year() != 2000 {
		t.Fatalf("idempotent refresh changed row: id=%s modes=%s/%s updated=%s", actualID, policyMode, profileMode, updatedAt)
	}
	for _, cfgType := range []string{"user", "fed"} {
		if _, err := database.Pool().Exec(ctx, `UPDATE groups SET cfg_type=$1, kind='ground', members='["authored"]', updated_at='2000-01-01' WHERE id=$2`, cfgType, id); err != nil {
			t.Fatal(err)
		}
		changed := learned
		changed.Members = []string{"replacement"}
		if err := worker.upsertLearnedGroup(ctx, orgID, &clusterID, changed); err != nil {
			t.Fatalf("%s collision: %v", cfgType, err)
		}
		var actualType, kind string
		var members []byte
		if err := database.Pool().QueryRow(ctx, `SELECT cfg_type, kind, members FROM groups WHERE id=$1`, id).Scan(&actualType, &kind, &members); err != nil {
			t.Fatal(err)
		}
		if actualType != cfgType || kind != "ground" || string(members) != `["authored"]` {
			t.Fatalf("%s collision clobbered row: %s %s %s", cfgType, actualType, kind, members)
		}
	}
}

func TestLearnedGroupRefreshRejectsReferencedChanges(t *testing.T) {
	for _, reference := range []string{"network", "dpi", "response-name", "response-id", "admission-name", "admission-id"} {
		t.Run(reference, func(t *testing.T) {
			database := openTestDB(t)
			defer database.Close()
			orgID, clusterID, learned := learnedGroupFixture(t, database)
			ctx := context.Background()
			worker := NewLearnedGroupWorker(database, LearnedGroupWorkerConfig{}, nil)
			if err := worker.upsertLearnedGroup(ctx, orgID, &clusterID, learned); err != nil {
				t.Fatal(err)
			}
			var groupID uuid.UUID
			if err := database.Pool().QueryRow(ctx, `SELECT id FROM groups WHERE org_id=$1 AND name=$2`, orgID, learned.Name).Scan(&groupID); err != nil {
				t.Fatal(err)
			}
			selector := learned.Name
			if strings.HasSuffix(reference, "-id") {
				selector = groupID.String()
			}
			var err error
			switch {
			case reference == "network":
				_, err = database.Pool().Exec(ctx, `INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group) VALUES ($1, $2, $3, 'external')`, orgID, clusterID, learned.Name)
			case reference == "dpi":
				_, err = database.Pool().Exec(ctx, `INSERT INTO group_dpi_sensor_bindings (org_id, group_id, sensor_kind, sensor_id) VALUES ($1, $2, 'dlp', $3)`, orgID, groupID, uuid.New())
			case strings.HasPrefix(reference, "response"):
				match, marshalErr := json.Marshal(map[string]string{"group": selector})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				_, err = database.Pool().Exec(ctx, `INSERT INTO response_rules_v2 (org_id, name, event_type, workload_match) VALUES ($1, $2, 'runtime', $3)`, orgID, reference, match)
			default:
				_, err = database.Pool().Exec(ctx, `INSERT INTO policies (org_id, cluster_id, name, engine, category, spec_yaml) VALUES ($1, $2, $3, 'constellation-admission', 'admission', $4)`, orgID, clusterID, reference, "spec:\n  match:\n    groups:\n      - "+selector+"\n")
			}
			if err != nil {
				t.Fatal(err)
			}
			changed := learned
			changed.Criteria = []group.Criterion{{Key: "namespace", Value: "other", Op: group.OpEq}}
			changed.Members = []string{"other/service"}
			changed.LearnedFrom = "other-service"
			otherClusterID := uuid.New()
			if _, err := database.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'other-learned-test')`, otherClusterID, orgID); err != nil {
				t.Fatal(err)
			}
			if err := worker.upsertLearnedGroup(ctx, orgID, &otherClusterID, changed); err == nil || !strings.Contains(err.Error(), "policy references") {
				t.Fatalf("refresh error = %v, want policy references", err)
			}
			var actualClusterID uuid.UUID
			var unchanged bool
			var learnedFrom string
			wantCriteria, _ := json.Marshal(learned.Criteria)
			wantMembers, _ := json.Marshal(learned.Members)
			if err := database.Pool().QueryRow(ctx, `SELECT cluster_id, criteria=$2::jsonb AND members=$3::jsonb, learned_from FROM groups WHERE id=$1`, groupID, wantCriteria, wantMembers).Scan(&actualClusterID, &unchanged, &learnedFrom); err != nil {
				t.Fatal(err)
			}
			if actualClusterID != clusterID || !unchanged || learnedFrom != learned.LearnedFrom {
				t.Fatalf("referenced group changed: cluster=%s json unchanged=%v source=%s", actualClusterID, unchanged, learnedFrom)
			}
			if err := worker.upsertLearnedGroup(ctx, orgID, &clusterID, learned); err != nil {
				t.Fatalf("unchanged referenced refresh: %v", err)
			}
		})
	}
}

func TestLearnedGroupRefreshOnlyChangesUnreferencedSelectors(t *testing.T) {
	for _, field := range []string{"members", "criteria", "cluster", "learned_from"} {
		t.Run(field, func(t *testing.T) {
			database := openTestDB(t)
			defer database.Close()
			orgID, clusterID, learned := learnedGroupFixture(t, database)
			ctx := context.Background()
			worker := NewLearnedGroupWorker(database, LearnedGroupWorkerConfig{}, nil)
			if err := worker.upsertLearnedGroup(ctx, orgID, &clusterID, learned); err != nil {
				t.Fatal(err)
			}
			next := learned
			nextClusterID := clusterID
			switch field {
			case "members":
				next.Members = []string{"replacement"}
			case "criteria":
				next.Criteria = []group.Criterion{{Key: "namespace", Value: "other", Op: group.OpEq}}
			case "cluster":
				nextClusterID = uuid.New()
				if _, err := database.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'other-learned-test')`, nextClusterID, orgID); err != nil {
					t.Fatal(err)
				}
			case "learned_from":
				next.LearnedFrom = "replacement"
			}
			if _, err := database.Pool().Exec(ctx, `INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group) VALUES ($1, $2, $3, 'external')`, orgID, clusterID, learned.Name); err != nil {
				t.Fatal(err)
			}
			if err := worker.upsertLearnedGroup(ctx, orgID, &nextClusterID, next); err == nil || !strings.Contains(err.Error(), "policy references") {
				t.Fatalf("referenced %s refresh error = %v", field, err)
			}
			if _, err := database.Pool().Exec(ctx, `DELETE FROM group_rule_edges WHERE org_id=$1`, orgID); err != nil {
				t.Fatal(err)
			}
			if err := worker.upsertLearnedGroup(ctx, orgID, &nextClusterID, next); err != nil {
				t.Fatalf("unreferenced %s refresh: %v", field, err)
			}
			wantCriteria, _ := json.Marshal(next.Criteria)
			wantMembers, _ := json.Marshal(next.Members)
			var updated bool
			if err := database.Pool().QueryRow(ctx, `
SELECT cluster_id=$2 AND criteria=$3::jsonb AND members=$4::jsonb AND learned_from=$5
  FROM groups WHERE org_id=$1 AND name=$6`, orgID, nextClusterID, wantCriteria, wantMembers, next.LearnedFrom, next.Name).Scan(&updated); err != nil {
				t.Fatal(err)
			}
			if !updated {
				t.Fatalf("unreferenced %s refresh did not persist", field)
			}
		})
	}
}

func TestLearnedGroupRefreshWaitsForConcurrentReferenceWrite(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	orgID, clusterID, learned := learnedGroupFixture(t, database)
	ctx := context.Background()
	worker := NewLearnedGroupWorker(database, LearnedGroupWorkerConfig{}, nil)
	if err := worker.upsertLearnedGroup(ctx, orgID, &clusterID, learned); err != nil {
		t.Fatal(err)
	}
	writer, err := database.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	if _, err := writer.Exec(ctx, `INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group) VALUES ($1, $2, $3, 'external')`, orgID, clusterID, learned.Name); err != nil {
		t.Fatal(err)
	}
	changed := learned
	changed.Members = []string{"replacement"}
	result := make(chan error, 1)
	go func() { result <- worker.upsertLearnedGroup(ctx, orgID, &clusterID, changed) }()
	select {
	case err := <-result:
		t.Fatalf("refresh finished before reference commit: %v", err)
	case <-time.After(120 * time.Millisecond):
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "policy references") {
			t.Fatalf("refresh error = %v, want policy references", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not finish after reference commit")
	}
	var members []byte
	if err := database.Pool().QueryRow(ctx, `SELECT members FROM groups WHERE org_id=$1 AND name=$2`, orgID, learned.Name).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if string(members) != `["default/service"]` {
		t.Fatalf("referenced members changed: %s", members)
	}
}
