package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

// usersReq drives a Users handler method with a Subject in context and a chi {id} route param.
func usersReq(t *testing.T, method, path, idParam string, h http.HandlerFunc, subj Subject) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", idParam)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	req = req.WithContext(WithSubject(ctx, subj))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// A1 (review fix): disabling a user runs the full credential-revocation cascade atomically —
// session_epoch is bumped (live JWTs rejected), the user's PATs are revoked, and the user's
// role_assignments are torn down — and the operation is org-scoped + self-protected.
func TestUsers_DisableCascade(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	adminID := uuid.New()
	targetID := uuid.New()

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_tokens WHERE user_id = ANY($1)`, []uuid.UUID{adminID, targetID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id = ANY($1)`, []uuid.UUID{adminID, targetID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{adminID, targetID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Disable Org')`,
		orgID, "disable-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	for _, u := range []struct {
		id    uuid.UUID
		email string
	}{{adminID, "admin"}, {targetID, "target"}} {
		if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash, session_epoch)
VALUES ($1, $2, $3, 'U', 'x', 0)`, u.id, orgID, u.email+"-"+u.id.String()+"@example.test"); err != nil {
			t.Fatalf("insert user %s: %v", u.email, err)
		}
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'Auditor', $2)`,
		targetID, orgID); err != nil {
		t.Fatalf("insert target role: %v", err)
	}
	raw := "cst_" + uuid.NewString()
	sum := sha256.Sum256([]byte(raw))
	if _, err := pool.Exec(ctx, `
INSERT INTO api_tokens (user_id, name, token_hash, scopes, status)
VALUES ($1, 'tok', $2, '["read-findings"]'::jsonb, 'active')`,
		targetID, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("insert token: %v", err)
	}

	h := NewUsers(d, audit.New(pool))
	admin := Subject{UserID: adminID, OrgID: orgID}

	// Self-disable is rejected.
	if rec := usersReq(t, http.MethodPost, "/api/v1/users/x/disable", adminID.String(), h.Disable, admin); rec.Code != http.StatusBadRequest {
		t.Fatalf("self-disable: status=%d, want 400", rec.Code)
	}

	// Disable the target.
	if rec := usersReq(t, http.MethodPost, "/api/v1/users/x/disable", targetID.String(), h.Disable, admin); rec.Code != http.StatusOK {
		t.Fatalf("disable: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	var disabled bool
	var epoch int64
	if err := pool.QueryRow(ctx, `SELECT disabled, session_epoch FROM users WHERE id = $1`, targetID).Scan(&disabled, &epoch); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if !disabled {
		t.Fatalf("user not disabled")
	}
	if epoch == 0 {
		t.Fatalf("session_epoch not bumped")
	}
	var liveTokens, assignments int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, targetID).Scan(&liveTokens); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if liveTokens != 0 {
		t.Fatalf("expected PATs revoked, %d still live", liveTokens)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE user_id = $1`, targetID).Scan(&assignments); err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if assignments != 0 {
		t.Fatalf("expected role_assignments removed, %d remain", assignments)
	}
}

// A4 (review fix): an admin force-password-reset sets must_change_password, bumps session_epoch
// (live JWTs rejected), and revokes the user's PATs (so the reset cannot be sidestepped).
func TestUsers_ForcePasswordReset(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	adminID := uuid.New()
	targetID := uuid.New()

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_tokens WHERE user_id = ANY($1)`, []uuid.UUID{adminID, targetID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{adminID, targetID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Reset Org')`,
		orgID, "reset-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash, session_epoch, must_change_password)
VALUES ($1, $2, $3, 'A', 'x', 0, FALSE),
       ($4, $2, $5, 'T', 'x', 0, FALSE)`,
		adminID, orgID, "admin-"+adminID.String()+"@x.test", targetID, "target-"+targetID.String()+"@x.test"); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	raw := "cst_" + uuid.NewString()
	sum := sha256.Sum256([]byte(raw))
	if _, err := pool.Exec(ctx, `
INSERT INTO api_tokens (user_id, name, token_hash, scopes, status)
VALUES ($1, 'tok', $2, '["read-findings"]'::jsonb, 'active')`,
		targetID, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("insert token: %v", err)
	}

	h := NewUsers(d, audit.New(pool))
	admin := Subject{UserID: adminID, OrgID: orgID}

	if rec := usersReq(t, http.MethodPost, "/api/v1/users/x/force-password-reset", targetID.String(), h.ForcePasswordReset, admin); rec.Code != http.StatusOK {
		t.Fatalf("force reset: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var mustChange bool
	var epoch int64
	var liveTokens int
	if err := pool.QueryRow(ctx, `SELECT must_change_password, session_epoch FROM users WHERE id = $1`, targetID).Scan(&mustChange, &epoch); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if !mustChange {
		t.Fatalf("must_change_password not set")
	}
	if epoch == 0 {
		t.Fatalf("session_epoch not bumped")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, targetID).Scan(&liveTokens); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if liveTokens != 0 {
		t.Fatalf("expected PATs revoked on forced reset, %d still live", liveTokens)
	}
}
