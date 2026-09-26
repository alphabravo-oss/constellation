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
)

// TestRegistryCredentialsGetIsOrgScoped exercises the REG-PRIVAUTH-11 endpoint
// end-to-end against the test DB: a scanner token in the owning org gets the
// decrypted credentials; a token in a different org gets 404 (no cross-org
// existence oracle); a missing registry_id is 400. Skips when the test DB is
// unreachable (see openTestDB).
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

	sealed, err := sealCredentials(ctx, pool, "static", map[string]string{"username": "alice", "password": "s3cret"})
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

	h := NewRegistryCredentials(d, audit.New(pool))

	call := func(handler *RegistryCredentials, orgID uuid.UUID, registryID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/scanner/registry-credentials?registry_id="+registryID, nil)
		tok := &ScannerToken{ID: uuid.New(), OrgID: orgID, Name: "test-scanner"}
		req = req.WithContext(context.WithValue(req.Context(), scannerTokenKey{}, tok))
		rr := httptest.NewRecorder()
		handler.Get(rr, req)
		return rr
	}

	// Owning org: 200 with decrypted credentials.
	rr := call(h, orgA, regID.String())
	if rr.Code != http.StatusOK {
		t.Fatalf("orgA status=%d body=%s want 200", rr.Code, rr.Body.String())
	}
	var dto RegistryCredentialsDTO
	if err := json.Unmarshal(rr.Body.Bytes(), &dto); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dto.Username != "alice" || dto.Password != "s3cret" {
		t.Fatalf("creds=%q/%q want alice/s3cret", dto.Username, dto.Password)
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
	if strings.Contains(auditAfter, dto.Password) || !strings.Contains(auditAfter, `"has_credentials": true`) {
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
		if issuedCount != 1 {
			t.Fatalf("failed audit changed issued count to %d", issuedCount)
		}
	}
}
