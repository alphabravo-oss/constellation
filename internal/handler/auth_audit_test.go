package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	authpkg "github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// RSP-AUDIT-05: a failed local login emits an auth.login.failed audit row (server-side only; the
// HTTP response stays a generic 401), and once the threshold trips, an auth.login.locked row too.
// Runs against the shared test DB; skips when unreachable.
func TestAuth_LoginFailureAudited(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	email := "audit-" + userID.String() + "@example.test"
	password := "CorrectHorseBatteryStaple!1"
	hash, err := authpkg.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Audit Org')`,
		orgID, "audit-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash)
VALUES ($1, $2, $3, 'Audit Admin', $4)`, userID, orgID, email, hash); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	h := NewAuth(d, testAuthSigner(t), nil, nil, nil, audit.New(pool))

	// One bad password -> a generic 401 AND an auth.login.failed audit row with the reason.
	loginStatusForTest(t, h, map[string]string{"email": email, "password": "wrong-" + password}, http.StatusUnauthorized)

	var failedRows int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*) FROM audit_events
 WHERE action = 'auth.login.failed' AND target_id = $1 AND after->>'reason' = 'bad_password'`,
		userID.String()).Scan(&failedRows); err != nil {
		t.Fatalf("count failed audit rows: %v", err)
	}
	if failedRows == 0 {
		t.Fatalf("expected an auth.login.failed audit row after a bad password, got none")
	}

	// Drive to the lockout threshold; the trip must emit an auth.login.locked row.
	for i := 1; i < maxFailedLogins; i++ {
		loginStatusForTest(t, h, map[string]string{"email": email, "password": "wrong-" + password}, http.StatusUnauthorized)
	}
	var lockedRows int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*) FROM audit_events WHERE action = 'auth.login.locked' AND target_id = $1`,
		userID.String()).Scan(&lockedRows); err != nil {
		t.Fatalf("count locked audit rows: %v", err)
	}
	if lockedRows == 0 {
		t.Fatalf("expected an auth.login.locked audit row once the threshold tripped, got none")
	}
}

// AUTH-LOCKOUT-17: the admin unlock endpoint clears a user's failure counter and lockout stamp,
// scoped to the caller's org. Runs against the shared test DB; skips when unreachable.
func TestUsers_UnlockClearsLockout(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	adminID := uuid.New()
	targetID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{adminID, targetID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Unlock Org')`,
		orgID, "unlock-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES
 ($1, $2, $3, 'Admin'),
 ($4, $2, $5, 'Locked User')`,
		adminID, orgID, "admin-"+adminID.String()+"@x.test", targetID, "locked-"+targetID.String()+"@x.test"); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	// Put the target into a locked state.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET failed_login_count = 9, block_login_since = now() WHERE id = $1`, targetID); err != nil {
		t.Fatalf("lock target: %v", err)
	}

	h := NewUsers(d, audit.New(pool))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+targetID.String()+"/unlock", nil)
	r = r.WithContext(WithSubject(r.Context(), Subject{UserID: adminID, OrgID: orgID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", targetID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Unlock(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("unlock status = %d, body=%s", w.Code, w.Body.String())
	}

	var failed int
	var blocked *bool
	if err := pool.QueryRow(ctx,
		`SELECT failed_login_count, block_login_since IS NOT NULL FROM users WHERE id = $1`, targetID,
	).Scan(&failed, &blocked); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if failed != 0 || (blocked != nil && *blocked) {
		t.Fatalf("expected cleared lockout, got failed=%d blocked=%v", failed, blocked)
	}

	// Unlocking a user in another org must 404 (org scoping).
	otherOrg := uuid.New()
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+targetID.String()+"/unlock", nil)
	r2 = r2.WithContext(WithSubject(r2.Context(), Subject{UserID: adminID, OrgID: otherOrg}))
	rctx2 := chi.NewRouteContext()
	rctx2.URLParams.Add("id", targetID.String())
	r2 = r2.WithContext(context.WithValue(r2.Context(), chi.RouteCtxKey, rctx2))
	w2 := httptest.NewRecorder()
	h.Unlock(w2, r2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("cross-org unlock status = %d, want 404", w2.Code)
	}
}
