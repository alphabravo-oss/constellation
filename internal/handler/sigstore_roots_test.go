package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// TestSigstoreRoots_CRUDOrgScoping proves SIG-ROOTS-38: roots are created, listed, and
// deleted per-org, and one org can neither see nor delete another org's roots.
func TestSigstoreRoots_CRUDOrgScoping(t *testing.T) {
	d := openTestDB(t)
	pool := d.Pool()
	ctx := context.Background()

	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.sigstore_roots')::text,'')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: 151_sigstore_roots migration not applied (%v)", err)
	}

	orgA, orgB := uuid.New(), uuid.New()
	userA, userB := uuid.New(), uuid.New()
	for _, o := range []struct {
		org, user uuid.UUID
	}{{orgA, userA}, {orgB, userB}} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Sigstore Test')`,
			o.org, "sig-"+o.org.String()); err != nil {
			t.Fatalf("org: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1,$2,$3,'Sig User')`,
			o.user, o.org, "sig-"+o.user.String()+"@example.com"); err != nil {
			t.Fatalf("user: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM sigstore_roots WHERE org_id = ANY($1)`, []uuid.UUID{orgA, orgB})
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = ANY($1)`, []uuid.UUID{orgA, orgB})
	})

	h := NewSigstoreRoots(d, nil)

	// Org A creates a root.
	rootID := createSigstoreRoot(t, h, userA, orgA, `{"name":"airgap","root_pem":"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"}`)

	// Org A lists exactly one; org B lists zero (org isolation).
	if got := listSigstoreRoots(t, h, userA, orgA); len(got) != 1 || got[0]["name"] != "airgap" {
		t.Fatalf("orgA list = %v, want one 'airgap' root", got)
	}
	if got := listSigstoreRoots(t, h, userB, orgB); len(got) != 0 {
		t.Fatalf("orgB list = %v, want empty (isolation)", got)
	}

	// Org B cannot delete org A's root.
	if code := deleteSigstoreRoot(t, h, userB, orgB, rootID); code != http.StatusNotFound {
		t.Fatalf("orgB delete of orgA root = %d, want 404", code)
	}
	// Org A can.
	if code := deleteSigstoreRoot(t, h, userA, orgA, rootID); code != http.StatusOK {
		t.Fatalf("orgA delete = %d, want 200", code)
	}
	if got := listSigstoreRoots(t, h, userA, orgA); len(got) != 0 {
		t.Fatalf("orgA list after delete = %v, want empty", got)
	}

	// RootsForOrg maps rows to sigverify roots.
	_ = createSigstoreRoot(t, h, userA, orgA, `{"name":"r2","root_pem":"pem"}`)
	roots, err := RootsForOrg(ctx, pool, orgA)
	if err != nil {
		t.Fatalf("RootsForOrg: %v", err)
	}
	if len(roots) != 1 || roots[0].Name != "r2" || roots[0].PublicKeyPEM != "pem" || roots[0].Mode != "public-key" {
		t.Fatalf("RootsForOrg = %+v", roots)
	}
}

func createSigstoreRoot(t *testing.T, h *SigstoreRoots, userID, orgID uuid.UUID, body string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sigstore-roots", bytes.NewReader([]byte(body)))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status %d body %s", rec.Code, rec.Body.String())
	}
	var dto map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &dto)
	return dto["id"].(string)
}

func listSigstoreRoots(t *testing.T, h *SigstoreRoots, userID, orgID uuid.UUID) []map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sigstore-roots", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status %d body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Roots []map[string]any `json:"roots"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Roots
}

func deleteSigstoreRoot(t *testing.T, h *SigstoreRoots, userID, orgID uuid.UUID, id string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sigstore-roots/"+id, nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	return rec.Code
}
