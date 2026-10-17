package runtime

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestQuarantineCreateRequiresOwnedClusterAndExistingWorkload(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := t.Context()
	org, foreignOrg, cluster, otherCluster, foreignCluster, user := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs (id,name,display_name) VALUES ($1,$2,$2),($3,$4,$4)`, org, "quarantine-"+org.String(), foreignOrg, "quarantine-"+foreignOrg.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM quarantine_entries WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1,$2)`, org, foreignOrg)
	})
	if _, err := d.Pool().Exec(ctx, `INSERT INTO clusters (id,org_id,name) VALUES ($1,$4,'a'),($2,$4,'b'),($3,$5,'foreign')`, cluster, otherCluster, foreignCluster, org, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO deployments (org_id,cluster_id,namespace,name,kind) VALUES ($1,$2,'team','api','Deployment'),($1,$3,'team','other','Deployment')`, org, cluster, otherCluster); err != nil {
		t.Fatal(err)
	}
	h := NewQuarantine(d, nil)
	for _, tc := range []struct {
		cluster uuid.UUID
		target  string
		status  int
	}{{cluster, "team/missing", 404}, {cluster, "team/other", 404}, {foreignCluster, "team/api", 404}, {cluster, "team/api", 201}, {cluster, "team/api", 409}} {
		body := fmt.Sprintf(`{"cluster_id":%q,"scope":"workload","match_key":%q,"reason":"incident","expires_in_hours":24}`, tc.cluster.String(), tc.target)
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/quarantine", strings.NewReader(body))
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org, UserID: user}))
		w := httptest.NewRecorder()
		h.Create(w, r)
		if w.Code != tc.status {
			t.Errorf("%s target=%s status=%d want=%d body=%s", tc.cluster, tc.target, w.Code, tc.status, w.Body.String())
		}
	}
	var count int
	if err := d.Pool().QueryRow(ctx, `SELECT count(*) FROM quarantine_entries WHERE org_id=$1`, org).Scan(&count); err != nil || count != 1 {
		t.Errorf("quarantines=%d err=%v", count, err)
	}
}
