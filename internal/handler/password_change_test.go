package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	authpkg "github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// changePassword drives Auth.ChangePassword with a Subject in context and returns the
// recorder so the caller can assert status + body.
func changePassword(t *testing.T, h *Auth, subj Subject, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewReader(payload))
	req = req.WithContext(WithSubject(req.Context(), subj))
	rec := httptest.NewRecorder()
	h.ChangePassword(rec, req)
	return rec
}

// A4: the password-change endpoint rejects a weak new password, rejects reuse of the
// current/recent passwords, accepts a strong fresh one, clears must_change_password, and
// bumps session_epoch. Runs against the shared test DB; skips when unreachable.
func TestChangePassword_PolicyAndReuse(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	email := "pwchange-" + userID.String() + "@example.test"
	current := "CurrentPass-12345"
	hash, err := authpkg.HashPassword(current)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM password_history WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'PW Org')`,
		orgID, "pwchange-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash, must_change_password, session_epoch)
VALUES ($1, $2, $3, 'PW User', $4, TRUE, 0)`, userID, orgID, email, hash); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	h := NewAuth(d, testAuthSigner(t), nil, nil, nil, audit.New(pool))
	subj := Subject{UserID: userID, OrgID: orgID, Email: email}

	// Wrong current password -> 401.
	if rec := changePassword(t, h, subj, map[string]string{
		"current_password": "nope", "new_password": "BrandNewPass-99",
	}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current: status=%d, want 401", rec.Code)
	}

	// Weak new password -> 400.
	if rec := changePassword(t, h, subj, map[string]string{
		"current_password": current, "new_password": "short",
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("weak new: status=%d, want 400", rec.Code)
	}

	// Reuse of the current password -> 400.
	if rec := changePassword(t, h, subj, map[string]string{
		"current_password": current, "new_password": current,
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("reuse current: status=%d, want 400", rec.Code)
	}

	// A strong, fresh password -> 200; must_change cleared, epoch bumped.
	next := "FreshSecret-2026!"
	if rec := changePassword(t, h, subj, map[string]string{
		"current_password": current, "new_password": next,
	}); rec.Code != http.StatusOK {
		t.Fatalf("fresh change: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var mustChange bool
	var epoch int64
	if err := pool.QueryRow(ctx,
		`SELECT must_change_password, session_epoch FROM users WHERE id = $1`, userID,
	).Scan(&mustChange, &epoch); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if mustChange {
		t.Fatalf("must_change_password not cleared")
	}
	if epoch == 0 {
		t.Fatalf("session_epoch not bumped (still %d)", epoch)
	}

	// The old password is now in history; reusing it must be rejected. We must auth with
	// the NEW current password to get past the current-password check first.
	if rec := changePassword(t, h, subj, map[string]string{
		"current_password": next, "new_password": current,
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("reuse historical: status=%d, want 400", rec.Code)
	}
}
