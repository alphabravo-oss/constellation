package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func TestGroupEdgeUpsertValidatesScopedGroups(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, otherOrgID := uuid.New(), uuid.New()
	clusterID, otherClusterID := uuid.New(), uuid.New()
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgID, otherOrgID)
	}()
	for _, org := range []uuid.UUID{orgID, otherOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, org, "edge-upsert-"+org.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, cluster := range []uuid.UUID{clusterID, otherClusterID} {
		if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, $3)`, cluster, orgID, "edge-upsert-"+cluster.String()); err != nil {
			t.Fatal(err)
		}
	}
	groupNames := []struct {
		orgID     uuid.UUID
		clusterID *uuid.UUID
		name      string
	}{
		{orgID, &clusterID, "source"},
		{orgID, nil, "shared"},
		{orgID, &otherClusterID, "other-cluster"},
		{otherOrgID, nil, "other-org"},
	}
	for _, group := range groupNames {
		if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind) VALUES ($1, $2, $3, 'ground')`, group.orgID, group.clusterID, group.name); err != nil {
			t.Fatal(err)
		}
	}
	store := NewGroupEdgeStore(d, nil)
	for _, test := range []struct {
		name    string
		from    string
		to      string
		wantErr bool
	}{
		{"same cluster", "source", "shared", false},
		{"built-in destination", "source", "external", false},
		{"built-in source", "nodes", "source", false},
		{"missing source", "missing", "shared", true},
		{"missing destination", "source", "missing", true},
		{"other org", "source", "other-org", true},
		{"other cluster", "source", "other-cluster", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := store.Upsert(ctx, orgID, clusterID, netpolicy.GroupEdge{FromGroup: test.from, ToGroup: test.to}, nil)
			if (err != nil) != test.wantErr {
				t.Fatalf("Upsert error = %v, want error %v", err, test.wantErr)
			}
			var count int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3 AND to_group=$4`, orgID, clusterID, test.from, test.to).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if test.wantErr && count != 0 || !test.wantErr && count != 1 {
				t.Fatalf("persisted edges = %d, want success=%v", count, !test.wantErr)
			}
		})
	}
	first, err := store.Upsert(ctx, orgID, clusterID, netpolicy.GroupEdge{FromGroup: "source", ToGroup: "shared", Comment: "updated"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Comment != "updated" {
		t.Fatalf("upsert comment = %q", first.Comment)
	}
}

func TestGroupEdgeUpsertWaitsForRenameOrDelete(t *testing.T) {
	for _, mutation := range []string{"rename", "delete"} {
		t.Run(mutation, func(t *testing.T) {
			d := openTestDB(t)
			defer d.Close()
			ctx := context.Background()
			pool := d.Pool()
			orgID, clusterID := uuid.New(), uuid.New()
			defer func() {
				_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
			}()
			if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "edge-race-"+orgID.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'edge-race')`, clusterID, orgID); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind) VALUES ($1, $2, 'source', 'ground')`, orgID, clusterID); err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `LOCK TABLE group_rule_edges IN SHARE MODE`); err != nil {
				t.Fatal(err)
			}
			var references int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1 AND (from_group='source' OR to_group='source')`, orgID).Scan(&references); err != nil || references != 0 {
				t.Fatalf("pre-mutation references = %d, error = %v", references, err)
			}
			query := `UPDATE groups SET name='renamed' WHERE org_id=$1 AND name='source'`
			if mutation == "delete" {
				query = `DELETE FROM groups WHERE org_id=$1 AND name='source'`
			}
			if _, err := tx.Exec(ctx, query, orgID); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				_, err := NewGroupEdgeStore(d, nil).Upsert(ctx, orgID, clusterID, netpolicy.GroupEdge{FromGroup: "source", ToGroup: "external"}, nil)
				result <- err
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				var waiting bool
				err := pool.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM pg_stat_activity
 WHERE query LIKE 'LOCK TABLE group_rule_edges IN ROW EXCLUSIVE MODE%'
   AND datname = current_database()
   AND wait_event_type = 'Lock')`).Scan(&waiting)
				if err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-result:
					t.Fatalf("writer finished before mutation commit: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("writer did not wait for reference table lock")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), `group "source" does not exist`) {
					t.Fatalf("writer error = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("writer did not finish after mutation")
			}
			var edges int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1`, orgID).Scan(&edges); err != nil || edges != 0 {
				t.Fatalf("edges after %s = %d, error = %v", mutation, edges, err)
			}
		})
	}
}

func TestGroupEdgeUpsertWaitsForOrgDeletion(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()
	orgID, clusterID := uuid.New(), uuid.New()
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	}()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "edge-org-race-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'edge-org-race')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind) VALUES ($1, $2, 'source', 'ground')`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	deletion, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer deletion.Rollback(ctx)
	var lockedOrgID uuid.UUID
	if err := deletion.QueryRow(ctx, `SELECT id FROM orgs WHERE id=$1 FOR UPDATE`, orgID).Scan(&lockedOrgID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := NewGroupEdgeStore(d, nil).Upsert(ctx, orgID, clusterID, netpolicy.GroupEdge{FromGroup: "source", ToGroup: "external"}, nil)
		result <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		err := pool.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM pg_stat_activity
 WHERE query LIKE 'SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE%'
   AND datname = current_database()
   AND wait_event_type = 'Lock')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("writer finished before org deletion: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("writer did not wait for org row lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := deletion.Exec(ctx, `LOCK TABLE group_rule_edges IN SHARE MODE NOWAIT`); err != nil {
		t.Fatalf("writer locked reference table before org row: %v", err)
	}
	if _, err := deletion.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, orgID); err != nil {
		t.Fatal(err)
	}
	if err := deletion.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("writer error after org deletion = %v, want no rows", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not finish after org deletion")
	}
	var edges int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1`, orgID).Scan(&edges); err != nil || edges != 0 {
		t.Fatalf("edges after org deletion = %d, error = %v", edges, err)
	}
}
