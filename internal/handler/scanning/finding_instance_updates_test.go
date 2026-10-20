//go:build integration

package scanning

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestScannerFindingUpdatesOnlySelectedRecurrence(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, cluster, asset := uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.Pool().Exec(t.Context(), q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name)VALUES($1::uuid,$1::text,'scanner instances')`, org)
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM findings WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
	})
	exec(`INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'source')`, cluster, org)
	exec(`INSERT INTO assets(id,org_id,cluster_id,kind,name)VALUES($1,$2,$3,'host','node')`, asset, org, cluster)
	first := time.Date(2026, 10, 12, 0, 0, 0, 123456000, time.UTC)
	second := first.Add(time.Microsecond)
	for _, kind := range []string{"vulnerability", "cloud-config"} {
		t.Run(kind, func(t *testing.T) {
			id, targetID := uuid.New(), uuid.New()
			typ, keyName := "host", "scan_finding_key"
			if kind == "cloud-config" {
				typ, keyName = "serverless", "stable_key"
			}
			target := handler.ScanTarget{ID: targetID, OrgID: org, ClusterID: &cluster, Type: typ, Ref: "node-" + targetID.String(), SourceType: "manual"}
			exec(`INSERT INTO scan_targets(id,org_id,cluster_id,type,ref,source_type)VALUES($1,$2,$3,$4,$5,'manual')`, targetID, org, cluster, typ, target.Ref)
			exec(`INSERT INTO findings(id,first_seen_at,last_seen_at,org_id,cluster_id,asset_id,kind,title,severity,scan_target_id,detail_json)VALUES($1,$2,$2,$4,$5,$6,$7,'older recurrence','high',$8,jsonb_build_object($9::text,'same-key')),($1,$3,$3,$4,$5,$6,$7,'selected recurrence','high',$8,jsonb_build_object($9::text,'same-key'))`, id, first, second, org, cluster, asset, kind, targetID, keyName)
			tx, err := d.Pool().Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if kind == "vulnerability" {
				err = upsertTargetFinding(t.Context(), tx, org, &cluster, asset, target, "same-key", scanner.Finding{VulnerabilityID: "CVE-fixture"}, "new observed title", "high", 70, "fixture", []byte("[]"), []byte(`{"scan_finding_key":"same-key"}`), "")
			} else {
				err = upsertServerlessPermissionFinding(t.Context(), tx, org, asset, target, ServerlessPackagesPayload{Provider: "aws", FunctionRef: target.Ref}, &serverlessPermissionAnalysis{Status: "analyzed", Level: "high"}, serverlessPermissionFindingAnalysis{ID: "permission", Title: "new observed title", Severity: "high"}, "same-key")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			rows, err := d.Pool().Query(t.Context(), `SELECT title,revision::text FROM findings WHERE org_id=$1 AND id=$2 ORDER BY first_seen_at`, org, id)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			titles, revisions := []string{}, []string{}
			for rows.Next() {
				var title, revision string
				if err = rows.Scan(&title, &revision); err != nil {
					t.Fatal(err)
				}
				titles = append(titles, title)
				revisions = append(revisions, revision)
			}
			if err = rows.Err(); err != nil {
				t.Fatal(err)
			}
			if len(titles) != 2 || titles[0] != "older recurrence" || titles[1] != "new observed title" || revisions[0] != "1" || revisions[1] != "2" {
				t.Fatalf("recurrences%v revisions%v", titles, revisions)
			}
		})
	}
}
