package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	authpkg "github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// A1 (review fix): an admin-created user role binding must mirror into role_assignments (the
// authz source of truth) AND bump the target's session_epoch; deleting it must remove the
// grant and bump again. The role_bindings table alone is non-authoritative, so the previous
// behavior neither took effect nor invalidated prior JWTs.
func TestRoleBinding_MirrorsAssignmentAndBumpsEpoch(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	adminID := uuid.New()
	targetID := uuid.New()

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_bindings WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id = ANY($1)`, []uuid.UUID{adminID, targetID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{adminID, targetID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'RB Org')`,
		orgID, "rb-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash, session_epoch)
VALUES ($1, $2, $3, 'A', 'x', 0), ($4, $2, $5, 'T', 'x', 0)`,
		adminID, orgID, "rb-admin-"+adminID.String()+"@x.test", targetID, "rb-target-"+targetID.String()+"@x.test"); err != nil {
		t.Fatalf("insert users: %v", err)
	}

	h := NewAccessControl(d, audit.New(pool))
	admin := Subject{UserID: adminID, OrgID: orgID}

	// Create a binding granting the target the Auditor role.
	body, _ := json.Marshal(createRoleBindingRequest{SubjectID: targetID.String(), SubjectType: "user", RoleID: "Auditor"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access-control/role-bindings", bytes.NewReader(body))
	req = req.WithContext(WithSubject(req.Context(), admin))
	rec := httptest.NewRecorder()
	h.CreateRoleBinding(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create binding: status=%d body=%s, want 201", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	var assignments int
	var epoch int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE user_id = $1 AND role = 'Auditor' AND scope_org_id = $2`, targetID, orgID).Scan(&assignments); err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if assignments != 1 {
		t.Fatalf("expected role_assignment mirrored, got %d", assignments)
	}
	if err := pool.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id = $1`, targetID).Scan(&epoch); err != nil {
		t.Fatalf("read epoch: %v", err)
	}
	if epoch == 0 {
		t.Fatalf("session_epoch not bumped on grant")
	}

	// Delete the binding -> assignment removed and epoch bumped again.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/access-control/role-bindings/"+created.ID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", created.ID)
	delReq = delReq.WithContext(WithSubject(context.WithValue(delReq.Context(), chi.RouteCtxKey, rctx), admin))
	delRec := httptest.NewRecorder()
	h.DeleteRoleBinding(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete binding: status=%d body=%s, want 200", delRec.Code, delRec.Body.String())
	}
	var afterAssignments int
	var afterEpoch int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE user_id = $1 AND role = 'Auditor' AND scope_org_id = $2`, targetID, orgID).Scan(&afterAssignments); err != nil {
		t.Fatalf("count assignments after: %v", err)
	}
	if afterAssignments != 0 {
		t.Fatalf("expected role_assignment removed on unbind, got %d", afterAssignments)
	}
	if err := pool.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id = $1`, targetID).Scan(&afterEpoch); err != nil {
		t.Fatalf("read epoch after: %v", err)
	}
	if afterEpoch <= epoch {
		t.Fatalf("session_epoch not bumped on unbind (was %d now %d)", epoch, afterEpoch)
	}
}

// A4 (review fix): a user under forced password reset (must_change_password = TRUE) must NOT
// be able to authenticate via a Personal Access Token — the JWT path 403s such users, and the
// PAT path must reject them too, otherwise the forced-reset gate is trivially bypassed. The
// gate must NOT touch service-account-attached tokens.
func TestAuthenticateAPIToken_ForcedResetGate(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	email := "pat-reset-" + userID.String() + "@example.test"

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_tokens WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'PAT Reset Org')`,
		orgID, "pat-reset-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash, must_change_password)
VALUES ($1, $2, $3, 'PAT Reset User', 'x', FALSE)`, userID, orgID, email); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'GlobalAdmin', $2)`,
		userID, orgID); err != nil {
		t.Fatalf("insert role: %v", err)
	}

	raw := "cst_" + uuid.NewString()
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(ctx, `
INSERT INTO api_tokens (user_id, name, token_hash, scopes, status)
VALUES ($1, 'reset-test', $2, $3::jsonb, 'active')`,
		userID, hash, `["read-findings"]`); err != nil {
		t.Fatalf("insert token: %v", err)
	}

	load := func(ctx context.Context, uid uuid.UUID) ([]rbac.RoleAssignment, error) {
		rows, err := pool.Query(ctx, `SELECT role, scope_org_id FROM role_assignments WHERE user_id = $1`, uid)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []rbac.RoleAssignment
		for rows.Next() {
			var role string
			var org uuid.UUID
			if err := rows.Scan(&role, &org); err != nil {
				return nil, err
			}
			out = append(out, rbac.RoleAssignment{Role: role, Scope: rbac.Scope{OrgID: org}})
		}
		return out, rows.Err()
	}

	// must_change_password = FALSE -> token authenticates.
	if _, ok := AuthenticateAPIToken(ctx, pool, raw, 0, load); !ok {
		t.Fatalf("expected PAT to authenticate when must_change_password is FALSE")
	}

	// Flip the flag -> token must now be rejected (forced-reset gate on the PAT path).
	if _, err := pool.Exec(ctx, `UPDATE users SET must_change_password = TRUE WHERE id = $1`, userID); err != nil {
		t.Fatalf("set must_change: %v", err)
	}
	if _, ok := AuthenticateAPIToken(ctx, pool, raw, 0, load); ok {
		t.Fatalf("PAT bypassed forced-reset gate: authenticated while must_change_password is TRUE")
	}
}

// A2 (review fix): the local-login path must not give a user-enumeration oracle. An unknown
// user, an existing SSO-only user (password_hash IS NULL), and a wrong password must all return
// the SAME generic 401 body — no "local login not enabled" branch.
func TestLogin_NoUserEnumerationOracle(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	ssoUserID := uuid.New()
	localUserID := uuid.New()
	ssoEmail := "sso-only-" + ssoUserID.String() + "@example.test"
	localEmail := "local-" + localUserID.String() + "@example.test"
	password := "CorrectHorseBatteryStaple!1"
	hash, err := authpkg.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{ssoUserID, localUserID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Oracle Org')`,
		orgID, "oracle-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	// SSO-only user: no local password.
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash, oidc_issuer, oidc_subject)
VALUES ($1, $2, $3, 'SSO User', NULL, 'https://idp.test', $4)`,
		ssoUserID, orgID, ssoEmail, ssoUserID.String()); err != nil {
		t.Fatalf("insert sso user: %v", err)
	}
	// Local user with a password (for the wrong-password case).
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash)
VALUES ($1, $2, $3, 'Local User', $4)`, localUserID, orgID, localEmail, hash); err != nil {
		t.Fatalf("insert local user: %v", err)
	}

	h := NewAuth(d, testAuthSigner(t), nil, nil, nil, audit.New(pool))

	unknownBody := loginStatusForTest(t, h, map[string]string{
		"email": "nobody-" + uuid.NewString() + "@example.test", "password": "whatever-Pass-1",
	}, http.StatusUnauthorized).Body.String()
	ssoBody := loginStatusForTest(t, h, map[string]string{
		"email": ssoEmail, "password": "whatever-Pass-1",
	}, http.StatusUnauthorized).Body.String()
	wrongPwBody := loginStatusForTest(t, h, map[string]string{
		"email": localEmail, "password": "definitely-wrong-1",
	}, http.StatusUnauthorized).Body.String()

	if unknownBody != ssoBody || unknownBody != wrongPwBody {
		t.Fatalf("user-enumeration oracle: bodies differ\n unknown=%q\n sso=%q\n wrongpw=%q",
			unknownBody, ssoBody, wrongPwBody)
	}
}
