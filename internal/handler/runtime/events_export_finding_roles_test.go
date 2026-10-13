package runtime

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/google/uuid"
)

func TestEventsExportFindingRolesPreserveExactRecurrencesAndSource(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	p := d.Pool()
	ctx := context.Background()
	org, foreignOrg, cluster, sibling, foreign, asset, repeat := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, o := range []uuid.UUID{org, foreignOrg} {
		if _, err := p.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, o, "finding-export-role-"+o.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = p.Exec(ctx, `DELETE FROM findings WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = p.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg)
	})
	if _, err := p.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'selected'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO assets(id,org_id,cluster_id,kind,name) VALUES($1,$2,$3,'workload','orbit/api')`, asset, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,'orbit','api','Deployment','{"helm.sh/chart":"constellation-1"}'),($1,$3,'orbit','api','Deployment','{}'),($1,$2,'ambiguous','api','Deployment','{"helm.sh/chart":"constellation-1"}'),($1,$2,'ambiguous','api','StatefulSet','{}')`, org, cluster, sibling); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO findings(id,org_id,asset_id,cluster_id,target_type,target_ref,kind,title,severity,first_seen_at) VALUES($1,$2,$3,$4,'workload','orbit/api','runtime','recurrence','high',NOW()-INTERVAL '1 second'),($1,$2,$3,$4,'workload','orbit/api','runtime','recurrence','high',NOW()),(gen_random_uuid(),$2,$3,$5,'workload','orbit/api','runtime','sibling','high',NOW()),(gen_random_uuid(),$2,$3,$4,'workload','ambiguous/api','runtime','ambiguous','high',NOW()),(gen_random_uuid(),$2,$3,$4,'image','orbit/api','runtime','image','high',NOW()),(gen_random_uuid(),$2,$3,$6,'workload','kube-system/api','runtime','unowned-cluster','high',NOW()),(gen_random_uuid(),$7,$3,$6,'workload','orbit/api','runtime','foreign','high',NOW())`, repeat, org, asset, cluster, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/events:export?hours=24", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org}))
	res := httptest.NewRecorder()
	NewEventsExport(p).Export(res, req)
	if res.Code != 200 {
		t.Fatalf("export%d %s", res.Code, res.Body.String())
	}
	decoder := json.NewDecoder(strings.NewReader(res.Body.String()))
	seen := map[string]bool{}
	count := 0
	for decoder.More() {
		var frame struct {
			Event string
			Data  map[string]any
		}
		if err := decoder.Decode(&frame); err != nil {
			t.Fatal(err)
		}
		if frame.Event != "finding" {
			t.Fatalf("unexpected %+v", frame)
		}
		count++
		role, ok := frame.Data["platform_role"].(string)
		if !ok {
			t.Fatal("unknown role omitted")
		}
		if frame.Data["title"] == "recurrence" {
			if role != "core" {
				t.Fatal("core recurrence role omitted")
			}
			key := frame.Data["id"].(string) + frame.Data["first_seen_at"].(string)
			if seen[key] {
				t.Fatal("recurrences collided")
			}
			seen[key] = true
		} else if role != "" {
			t.Fatal("borrowed source/ambiguous/image role", frame.Data)
		}
		if frame.Data["org_id"] != org.String() {
			t.Fatal("foreign export")
		}
	}
	if count != 6 || len(seen) != 2 {
		t.Fatalf("cohort count%d identities%d", count, len(seen))
	}
}
