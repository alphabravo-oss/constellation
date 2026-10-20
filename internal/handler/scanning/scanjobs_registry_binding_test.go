package scanning

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestEnqueueRegistryBinding(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool, ctx := d.Pool(), t.Context()
	org, foreignOrg, user, registry, foreignRegistry := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "registry-binding-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=ANY($1)`, []uuid.UUID{org, foreignOrg})
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,org_id,email,display_name) VALUES($1,$2,$3,'Registry scan user')`, user, org, user.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]uuid.UUID{{registry, org}, {foreignRegistry, foreignOrg}} {
		if _, err := pool.Exec(ctx, `INSERT INTO registries(id,org_id,name,kind,endpoint,auth_kind) VALUES($1,$2,'private','ghcr','ghcr.io/team','none')`, pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	h := NewScanJobs(d, audit.New(pool))
	imageRef := "ghcr.io/team/private:latest"
	enqueue := func(source, ref, target string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(EnqueueRequest{TargetType: target, TargetRef: imageRef, SourceType: source, SourceRef: ref})
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/scan-jobs", bytes.NewReader(body))
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org, UserID: user}))
		rec := httptest.NewRecorder()
		h.Enqueue(rec, req)
		return rec
	}
	for _, tc := range []struct {
		name, ref, target string
		status            int
	}{
		{"missing", "", "image", 400}, {"malformed", "not-a-uuid", "image", 400},
		{"foreign", foreignRegistry.String(), "image", 404}, {"absent", uuid.NewString(), "image", 404},
		{"not image", registry.String(), "host", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := enqueue("registry", tc.ref, tc.target)
			if r.Code != tc.status {
				t.Fatalf("status=%d body=%s", r.Code, r.Body.String())
			}
		})
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM scan_targets WHERE org_id=$1`, org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected requests created targets: %d %v", count, err)
	}
	// Reproduce a pre-fix target with provenance but no credential association.
	oldTarget := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO scan_targets(id,org_id,type,ref,source_type,source_ref) VALUES($1,$2,'image','ghcr.io/team/private:latest','registry',$3)`, oldTarget, org, registry.String()); err != nil {
		t.Fatal(err)
	}
	r := enqueue("registry", registry.String(), "image")
	if r.Code != http.StatusAccepted {
		t.Fatalf("enqueue: %d %s", r.Code, r.Body.String())
	}
	var job struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	var bound, target uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT t.registry_id,t.id FROM scan_jobs j JOIN scan_targets t ON t.id=j.target_id WHERE j.id=$1`, job.ID).Scan(&bound, &target); err != nil || bound != registry || target != oldTarget {
		t.Fatalf("binding=%s target=%s err=%v", bound, target, err)
	}
	token, _, err := handler.IssueScannerToken(ctx, pool, org, "registry-binding", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/scan-jobs/claim", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(h.Claim)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("claim %d %s", rec.Code, rec.Body.String())
	}
	var claim struct {
		RegistryID uuid.UUID `json:"registry_id"`
		LeaseID    uuid.UUID `json:"lease_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &claim); err != nil || claim.RegistryID != registry || claim.LeaseID == uuid.Nil {
		t.Fatalf("claim=%+v err=%v", claim, err)
	}
	imageRef = "ghcr.io/team/new-image:latest"
	r = enqueue("registry", registry.String(), "image")
	if r.Code != http.StatusAccepted {
		t.Fatalf("fresh enqueue: %d %s", r.Code, r.Body.String())
	}
	if err := json.Unmarshal(r.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT t.registry_id FROM scan_jobs j JOIN scan_targets t ON t.id=j.target_id WHERE j.id=$1`, job.ID).Scan(&bound); err != nil || bound != registry {
		t.Fatalf("fresh binding=%s err=%v", bound, err)
	}
	// An arbitrary source_ref on a manual job cannot opt into credentials.
	r = enqueue("manual", foreignRegistry.String(), "image")
	if r.Code != http.StatusAccepted {
		t.Fatalf("manual: %d %s", r.Code, r.Body.String())
	}
	if err := json.Unmarshal(r.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	var noRegistry bool
	if err := pool.QueryRow(ctx, `SELECT t.registry_id IS NULL FROM scan_jobs j JOIN scan_targets t ON t.id=j.target_id WHERE j.id=$1`, job.ID).Scan(&noRegistry); err != nil || !noRegistry {
		t.Fatalf("manual unexpectedly bound credentials: %v", err)
	}
}
