package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// usersReqBody drives a Users handler method with a JSON body, a Subject in context, and an
// optional chi {id} route param.
func usersReqBody(t *testing.T, method, path, idParam, body string, h http.HandlerFunc, subj Subject) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rctx := chi.NewRouteContext()
	if idParam != "" {
		rctx.URLParams.Add("id", idParam)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	req = req.WithContext(WithSubject(ctx, subj))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func globalAdmin(userID, orgID uuid.UUID) Subject {
	return Subject{UserID: userID, OrgID: orgID,
		Assignments: []rbac.RoleAssignment{{Role: rbac.RoleGlobalAdmin, Scope: rbac.Scope{OrgID: orgID}}}}
}

// AUTH-USERCRUD-20: creating a local user provisions a password-authenticated account in the
// caller's org with a forced temp password + the requested org-scoped role, and audits it.
func TestUsers_Create(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	adminID := uuid.New()

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id IN (SELECT id FROM users WHERE org_id = $1)`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Create Org')`,
		orgID, "create-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, 'A', 'x')`,
		adminID, orgID, "admin-"+adminID.String()+"@x.test"); err != nil {
		t.Fatalf("insert admin: %v", err)
	}

	h := NewUsers(d, audit.New(pool))
	admin := globalAdmin(adminID, orgID)
	email := "invitee-" + uuid.NewString() + "@x.test"
	body := `{"email":"` + email + `","role":"Auditor","password":"SuperSecret123!"}`

	rec := usersReqBody(t, http.MethodPost, "/api/v1/users", "", body, h.Create, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status=%d body=%s, want 201", rec.Code, rec.Body.String())
	}

	// The user landed in the caller's org, must change its temp password, and has a hash set.
	var gotOrg uuid.UUID
	var mustChange bool
	var hasHash bool
	if err := pool.QueryRow(ctx,
		`SELECT org_id, must_change_password, password_hash IS NOT NULL FROM users WHERE email = $1`, email).
		Scan(&gotOrg, &mustChange, &hasHash); err != nil {
		t.Fatalf("read created user: %v", err)
	}
	if gotOrg != orgID {
		t.Fatalf("created user org=%s, want %s (org scoping)", gotOrg, orgID)
	}
	if !mustChange {
		t.Fatalf("expected must_change_password on an admin-set temp password")
	}
	if !hasHash {
		t.Fatalf("expected password_hash set")
	}
	// Role assignment written.
	var roleCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM role_assignments ra JOIN users u ON u.id = ra.user_id
		  WHERE u.email = $1 AND ra.role = 'Auditor' AND ra.scope_org_id = $2`, email, orgID).Scan(&roleCount); err != nil {
		t.Fatalf("count role: %v", err)
	}
	if roleCount != 1 {
		t.Fatalf("expected 1 Auditor assignment, got %d", roleCount)
	}
	// Audited.
	var auditCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'user.create' AND org_id = $1`, orgID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("expected 1 user.create audit event, got %d", auditCount)
	}

	// Duplicate email in the same org → 409.
	if rec := usersReqBody(t, http.MethodPost, "/api/v1/users", "", body, h.Create, admin); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create: status=%d, want 409", rec.Code)
	}
}

// Privilege-escalation guard: a caller may not mint a user more privileged than themselves.
func TestUsers_Create_PrivEscalationBlocked(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	auditorID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Esc Org')`,
		orgID, "esc-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}

	h := NewUsers(d, audit.New(pool))
	// Caller holds only Auditor — cannot create a GlobalAdmin.
	caller := Subject{UserID: auditorID, OrgID: orgID,
		Assignments: []rbac.RoleAssignment{{Role: rbac.RoleAuditor, Scope: rbac.Scope{OrgID: orgID}}}}
	body := `{"email":"esc-` + uuid.NewString() + `@x.test","role":"GlobalAdmin","password":"SuperSecret123!"}`
	if rec := usersReqBody(t, http.MethodPost, "/api/v1/users", "", body, h.Create, caller); rec.Code != http.StatusForbidden {
		t.Fatalf("priv-escalation create: status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
}

// Update changes role (bumping epoch) and deactivates a user (cascade), all org-scoped.
func TestUsers_Update(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	otherOrgID := uuid.New()
	adminID := uuid.New()
	targetID := uuid.New()
	foreignID := uuid.New()

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id = ANY($1)`, []uuid.UUID{adminID, targetID, foreignID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE org_id = ANY($1)`, []uuid.UUID{orgID, otherOrgID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{adminID, targetID, foreignID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = ANY($1)`, []uuid.UUID{orgID, otherOrgID})
	})
	for _, o := range []uuid.UUID{orgID, otherOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Upd Org')`,
			o, "upd-org-"+o.String()); err != nil {
			t.Fatalf("insert org: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash, session_epoch)
VALUES ($1, $2, $3, 'A', 'x', 0), ($4, $2, $5, 'T', 'x', 0)`,
		adminID, orgID, "admin-"+adminID.String()+"@x.test", targetID, "target-"+targetID.String()+"@x.test"); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, 'F', 'x')`,
		foreignID, otherOrgID, "foreign-"+foreignID.String()+"@x.test"); err != nil {
		t.Fatalf("insert foreign: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'Auditor', $2)`,
		targetID, orgID); err != nil {
		t.Fatalf("insert target role: %v", err)
	}

	h := NewUsers(d, audit.New(pool))
	admin := globalAdmin(adminID, orgID)

	// Change role Auditor → SecurityAdmin.
	rec := usersReqBody(t, http.MethodPut, "/api/v1/users/x", targetID.String(), `{"role":"SecurityAdmin"}`, h.Update, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("update role: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var role string
	var epoch int64
	if err := pool.QueryRow(ctx, `SELECT role FROM role_assignments WHERE user_id = $1 AND scope_org_id = $2`, targetID, orgID).Scan(&role); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if role != "SecurityAdmin" {
		t.Fatalf("role=%s, want SecurityAdmin", role)
	}
	if err := pool.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id = $1`, targetID).Scan(&epoch); err != nil {
		t.Fatalf("read epoch: %v", err)
	}
	if epoch == 0 {
		t.Fatalf("expected session_epoch bumped on role change")
	}

	// Deactivate (active=false) → disabled true.
	rec = usersReqBody(t, http.MethodPut, "/api/v1/users/x", targetID.String(), `{"active":false}`, h.Update, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var disabled bool
	if err := pool.QueryRow(ctx, `SELECT disabled FROM users WHERE id = $1`, targetID).Scan(&disabled); err != nil {
		t.Fatalf("read disabled: %v", err)
	}
	if !disabled {
		t.Fatalf("expected user disabled after active=false")
	}

	// Org scoping: updating a user in another org returns 404.
	rec = usersReqBody(t, http.MethodPut, "/api/v1/users/x", foreignID.String(), `{"role":"Auditor"}`, h.Update, admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-org update: status=%d, want 404 (org scoping)", rec.Code)
	}

	// Self role change is rejected.
	rec = usersReqBody(t, http.MethodPut, "/api/v1/users/x", adminID.String(), `{"role":"Auditor"}`, h.Update, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("self role change: status=%d, want 400", rec.Code)
	}

	// Audited.
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'user.update' AND org_id = $1`, orgID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount < 2 {
		t.Fatalf("expected >=2 user.update audit events, got %d", auditCount)
	}
}
