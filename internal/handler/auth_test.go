package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authpkg "github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/google/uuid"
)

func TestAuth_LoginWithoutOrgUsesUniqueActiveUser(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	email := "single-org-" + userID.String() + "@example.test"
	password := "CorrectHorseBatteryStaple!1"
	hash, err := authpkg.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Single Org Login')`,
		orgID, "single-org-login-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash)
VALUES ($1, $2, $3, 'Single Org Admin', $4)`,
		userID, orgID, email, hash); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'GlobalAdmin', $2)`,
		userID, orgID); err != nil {
		t.Fatalf("insert role: %v", err)
	}

	signer := testAuthSigner(t)
	token := loginForTest(t, NewAuth(d, signer, nil, nil, nil, audit.New(pool)), map[string]string{
		"email":    email,
		"password": password,
	})
	claims, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.UserID != userID || claims.OrgID != orgID {
		t.Fatalf("claims = user %s org %s, want user %s org %s", claims.UserID, claims.OrgID, userID, orgID)
	}
}

func TestAuth_LoginWithoutOrgRejectsDuplicateEmail(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgA := uuid.New()
	orgB := uuid.New()
	userA := uuid.New()
	userB := uuid.New()
	email := "duplicate-login-" + userA.String() + "@example.test"
	password := "CorrectHorseBatteryStaple!1"
	hash, err := authpkg.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = ANY($1)`, []uuid.UUID{orgA, orgB})
	})
	orgAName := "auth-org-a-" + orgA.String()
	orgBName := "auth-org-b-" + orgB.String()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name)
VALUES ($1, $2, 'Auth Org A'), ($3, $4, 'Auth Org B')`,
		orgA, orgAName, orgB, orgBName); err != nil {
		t.Fatalf("insert orgs: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash)
VALUES
  ($1, $2, $3, 'Auth User A', $5),
  ($4, $6, $3, 'Auth User B', $5)`,
		userA, orgA, email, userB, hash, orgB); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_assignments (user_id, role, scope_org_id)
VALUES ($1, 'GlobalAdmin', $2), ($3, 'Auditor', $4)`,
		userA, orgA, userB, orgB); err != nil {
		t.Fatalf("insert roles: %v", err)
	}

	h := NewAuth(d, testAuthSigner(t), nil, nil, nil, audit.New(pool))
	loginStatusForTest(t, h, map[string]string{
		"email":    email,
		"password": password,
	}, http.StatusUnauthorized)
}

func testAuthSigner(t *testing.T) *authpkg.Signer {
	t.Helper()
	t.Setenv("CONSTELLATION_ALLOW_HS256_JWT", "true") // tests sign with a symmetric key
	signer, err := authpkg.NewSigner("constellation-test", "constellation-api", time.Hour, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func loginForTest(t *testing.T, h *Auth, body map[string]string) string {
	t.Helper()
	rec := loginStatusForTest(t, h, body, http.StatusOK)
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if out.Token == "" {
		t.Fatalf("empty token")
	}
	return out.Token
}

func loginStatusForTest(t *testing.T, h *Auth, body map[string]string, want int) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != want {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, want, rec.Body.String())
	}
	return rec
}
