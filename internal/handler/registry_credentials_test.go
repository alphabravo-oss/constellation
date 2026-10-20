//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/scanlease"
)

// TestRegistryCredentialsGetIsOrgScoped exercises the credential release boundary
// against a real database, including lease ownership and redacted audit receipts.
func TestRegistryCredentialsGetIsOrgScoped(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	ctx := context.Background()

	orgA := uuid.New()
	orgB := uuid.New()
	for _, id := range []uuid.UUID{orgA, orgB} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Reg Creds Test')`,
			id, "reg-creds-"+id.String()); err != nil {
			t.Fatalf("seed org: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = ANY($1)`, []uuid.UUID{orgA, orgB})
	})

	sealed, _, err := sealCredentials(ctx, pool, "static", map[string]string{"username": "alice", "password": "s3cret"})
	if err != nil {
		t.Fatalf("seal credentials: %v", err)
	}
	regID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO registries (id, org_id, name, kind, endpoint, auth_kind, auth_secret)
VALUES ($1, $2, 'privreg', 'ghcr', 'ghcr.io', 'static', $3)`,
		regID, orgA, sealed); err != nil {
		t.Fatalf("seed registry: %v", err)
	}

	tokenID := uuid.New()
	tok := &ScannerToken{ID: tokenID, OrgID: orgA, Name: "test-scanner"}
	targetID, jobID := uuid.New(), uuid.New()
	workerID := tok.workerID() + ":worker-1"
	if _, err := pool.Exec(ctx, `INSERT INTO scan_targets(id,org_id,type,ref,source_type,registry_id) VALUES($1,$2,'image','ghcr.io/team/app:latest','registry',$3)`, targetID, orgA, regID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs(id,org_id,target_id,status,worker_id,lease_expires_at) VALUES($1,$2,$3,'running',$4,NOW()+INTERVAL '30 minutes')`, jobID, orgA, targetID, workerID); err != nil {
		t.Fatal(err)
	}
	h := NewRegistryCredentials(d, audit.New(pool))

	leaseHeader := ""
	call := func(handler *RegistryCredentials, orgID uuid.UUID, registryID string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scanner/registry-credentials?registry_id="+registryID+"&job_id="+jobID.String(), nil)
		tok := &ScannerToken{ID: tokenID, OrgID: orgID, Name: "test-scanner"}
		req.Header.Set("X-Constellation-Scanner-Instance", "worker-1")
		req.Header.Set(scanlease.Header, leaseHeader)
		req = req.WithContext(context.WithValue(req.Context(), scannerTokenKey{}, tok))
		rr := httptest.NewRecorder()
		handler.Get(rr, req)
		return rr
	}

	// Owning org: 200 with decrypted credentials.
	rr := call(h, orgA, regID.String())
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential response permits caching")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("orgA status=%d body=%s want 200", rr.Code, rr.Body.String())
	}
	var dto RegistryCredentialsDTO
	if err := json.Unmarshal(rr.Body.Bytes(), &dto); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dto.Username != "alice" || dto.Password != "s3cret" {
		t.Fatal("unexpected decrypted credentials")
	}
	if dto.Kind != "ghcr" || dto.AuthKind != "static" {
		t.Fatalf("kind/auth_kind=%q/%q want ghcr/static", dto.Kind, dto.AuthKind)
	}
	var issuedCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE org_id = $1 AND action = 'registry.credentials-issued' AND target_id = $2`, orgA, regID.String()).Scan(&issuedCount); err != nil {
		t.Fatal(err)
	}
	if issuedCount != 1 {
		t.Fatalf("successful credential reads wrote %d audit events, want 1", issuedCount)
	}
	var auditAfter string
	if err := pool.QueryRow(ctx, `SELECT after::text FROM audit_events WHERE org_id = $1 AND action = 'registry.credentials-issued' AND target_id = $2`, orgA, regID.String()).Scan(&auditAfter); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditAfter, dto.Password) || !strings.Contains(auditAfter, `"has_credentials": true`) || !strings.Contains(auditAfter, jobID.String()) || !strings.Contains(auditAfter, workerID) {
		t.Fatalf("credential audit payload is missing the redacted receipt: %s", auditAfter)
	}

	// Different org, same registry id: 404 (org-scoped, no leak).
	if rr := call(h, orgB, regID.String()); rr.Code != http.StatusNotFound {
		t.Fatalf("orgB status=%d body=%s want 404", rr.Code, rr.Body.String())
	}

	// Missing registry_id: 400.
	if rr := call(h, orgA, ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("missing registry_id status=%d want 400", rr.Code)
	}

	// Each invalid ownership edge and lease state must deny without issuing credentials.

	// A new claim requires its exact identity, even for the same scanner instance.
	leaseID := uuid.NewString()
	if _, err := pool.Exec(ctx, `UPDATE scan_jobs SET lease_id=$2 WHERE id=$1`, jobID, leaseID); err != nil {
		t.Fatal(err)
	}
	for _, stale := range []string{"", uuid.NewString()} {
		leaseHeader = stale
		if rec := call(h, orgA, regID.String()); rec.Code != http.StatusNotFound {
			t.Fatalf("stale lease credential status %d", rec.Code)
		}
	}
	leaseHeader = leaseID
	if rec := call(h, orgA, regID.String()); rec.Code != http.StatusOK {
		t.Fatalf("current lease credential status %d", rec.Code)
	}
	var fencedReceipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='registry.credentials-issued' AND after->>'lease_id'=$2`, orgA, leaseID).Scan(&fencedReceipts); err != nil || fencedReceipts != 1 {
		t.Fatalf("fenced receipts %d %v", fencedReceipts, err)
	}
	leaseHeader = ""
	if _, err := pool.Exec(ctx, `UPDATE scan_jobs SET lease_id=NULL WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, query string
		args        []any
	}{
		{"expired lease", `UPDATE scan_jobs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1`, []any{jobID}},
		{"missing lease", `UPDATE scan_jobs SET lease_expires_at=NULL WHERE id=$1`, []any{jobID}},
		{"other instance", `UPDATE scan_jobs SET worker_id=$2 WHERE id=$1`, []any{jobID, tok.workerID() + ":worker-2"}},
		{"other token", `UPDATE scan_jobs SET worker_id=$2 WHERE id=$1`, []any{jobID, "scanner:test-scanner:" + uuid.NewString() + ":worker-1"}},
		{"completed job", `UPDATE scan_jobs SET status='completed' WHERE id=$1`, []any{jobID}},
		{"paused job", `UPDATE scan_jobs SET status='paused' WHERE id=$1`, []any{jobID}},
		{"canceled job", `UPDATE scan_jobs SET status='canceled' WHERE id=$1`, []any{jobID}},
		{"foreign job", `UPDATE scan_jobs SET org_id=$2 WHERE id=$1`, []any{jobID, orgB}},
		{"foreign target", `UPDATE scan_targets SET org_id=$2 WHERE id=$1`, []any{targetID, orgB}},
		{"unrelated registry", `UPDATE scan_targets SET registry_id=NULL WHERE id=$1`, []any{targetID}},
		{"non-image target", `UPDATE scan_targets SET type='host' WHERE id=$1`, []any{targetID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.query, tc.args...); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := pool.Exec(ctx, `UPDATE scan_jobs SET org_id=$2,status='running',worker_id=$3,lease_expires_at=NOW()+INTERVAL '30 minutes' WHERE id=$1`, jobID, orgA, workerID); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(ctx, `UPDATE scan_targets SET org_id=$2,type='image',registry_id=$3 WHERE id=$1`, targetID, orgA, regID); err != nil {
					t.Fatal(err)
				}
			}()
			rr := call(h, orgA, regID.String())
			if rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), dto.Password) {
				t.Fatalf("invalid lease returned status %d or disclosed credentials", rr.Code)
			}
		})
	}
	for _, query := range []string{"registry_id=" + regID.String(), "registry_id=" + regID.String() + "&job_id=invalid", "registry_id=invalid&job_id=" + jobID.String()} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scanner/registry-credentials?"+query, nil)
		req = req.WithContext(context.WithValue(req.Context(), scannerTokenKey{}, tok))
		rr := httptest.NewRecorder()
		h.Get(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid query status=%d", rr.Code)
		}
	}

	closedPool, err := pgxpool.NewWithConfig(ctx, pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	closedPool.Close()
	for _, failedAudit := range []*audit.Logger{nil, audit.New(closedPool)} {
		rr := call(NewRegistryCredentials(d, failedAudit), orgA, regID.String())
		if rr.Code != http.StatusServiceUnavailable || !json.Valid(rr.Body.Bytes()) || strings.Contains(rr.Body.String(), dto.Password) {
			t.Fatalf("audit failure status=%d body=%s", rr.Code, rr.Body.String())
		}
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE org_id = $1 AND action = 'registry.credentials-issued' AND target_id = $2`, orgA, regID.String()).Scan(&issuedCount); err != nil {
			t.Fatal(err)
		}
		if issuedCount != 2 {
			t.Fatalf("failed audit changed issued count to %d", issuedCount)
		}
	}
}
