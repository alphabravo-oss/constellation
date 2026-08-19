package handler

import (
	"context"
	"net/http"
	"testing"

	authpkg "github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/google/uuid"
)

// A2: N consecutive failed local logins lock the account for the window, a good password
// during the lockout is still rejected (generic 401, no oracle), and a later success
// resets the counter. Runs against the shared test DB; skips when unreachable.
func TestAuth_BruteForceLockout(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	email := "lockout-" + userID.String() + "@example.test"
	password := "CorrectHorseBatteryStaple!1"
	hash, err := authpkg.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Lockout Org')`,
		orgID, "lockout-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash)
VALUES ($1, $2, $3, 'Lockout Admin', $4)`, userID, orgID, email, hash); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'GlobalAdmin', $2)`,
		userID, orgID); err != nil {
		t.Fatalf("insert role: %v", err)
	}

	h := NewAuth(d, testAuthSigner(t), nil, nil, nil, audit.New(pool))

	// maxFailedLogins consecutive bad passwords -> the threshold trips the lockout.
	for i := 0; i < maxFailedLogins; i++ {
		loginStatusForTest(t, h, map[string]string{"email": email, "password": "wrong-" + password}, http.StatusUnauthorized)
	}

	// Confirm the lockout actually engaged in the DB.
	var failed int
	var blocked *bool
	if err := pool.QueryRow(ctx,
		`SELECT failed_login_count, block_login_since IS NOT NULL FROM users WHERE id = $1`, userID,
	).Scan(&failed, &blocked); err != nil {
		t.Fatalf("read lockout state: %v", err)
	}
	if failed < maxFailedLogins || blocked == nil || !*blocked {
		t.Fatalf("expected lockout: failed=%d blocked=%v", failed, blocked)
	}

	// The CORRECT password during the lockout window must still be rejected (generic 401).
	loginStatusForTest(t, h, map[string]string{"email": email, "password": password}, http.StatusUnauthorized)

	// Clear the block (simulating the window elapsing) and confirm a good password now
	// succeeds and resets the counter to 0.
	if _, err := pool.Exec(ctx, `UPDATE users SET block_login_since = NULL WHERE id = $1`, userID); err != nil {
		t.Fatalf("clear block: %v", err)
	}
	loginStatusForTest(t, h, map[string]string{"email": email, "password": password}, http.StatusOK)

	if err := pool.QueryRow(ctx, `SELECT failed_login_count FROM users WHERE id = $1`, userID).Scan(&failed); err != nil {
		t.Fatalf("read reset count: %v", err)
	}
	if failed != 0 {
		t.Fatalf("expected failed_login_count reset to 0 on success, got %d", failed)
	}
}
