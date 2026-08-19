//go:build integration

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/observability"
)

// TestEndToEndSmoke boots the server against a real Postgres, seeds a user, logs in via
// /api/v1/auth/login, hits /api/v1/auth/me, and lists findings.
func TestEndToEndSmoke(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set")
	}

	ctx := context.Background()
	tel, _ := observability.Init(ctx, "test")

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	// Seed an org + a local user.
	var orgID, userID string
	if err := pool.QueryRow(ctx, `
INSERT INTO orgs (name, display_name) VALUES ('smoketest', 'Smoke Test')
ON CONFLICT (name) DO UPDATE SET display_name = EXCLUDED.display_name
RETURNING id`).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	hash, _ := auth.HashPassword("hunter2!")
	if err := pool.QueryRow(ctx, `
INSERT INTO users (org_id, email, display_name, password_hash)
VALUES ($1, 'admin@smoke.test', 'Smoke Admin', $2)
ON CONFLICT (org_id, email) DO UPDATE SET password_hash = EXCLUDED.password_hash
RETURNING id`, orgID, hash).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_assignments (user_id, role, scope_org_id) VALUES ($1, 'GlobalAdmin', $2)
ON CONFLICT DO NOTHING`, userID, orgID); err != nil {
		t.Fatalf("seed role: %v", err)
	}

	dbHandle, err := db.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer dbHandle.Close()

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cfg := Config{
		ListenAddr:  ":0",
		DatabaseURL: databaseURL,
		JWTKeys:     [][]byte{key},
		JWTIssuer:   "constellation-test",
		JWTAudience: "constellation-api",
		JWTTTL:      time.Hour,
		CORSOrigins: []string{"http://localhost:5173"},
	}
	srv, err := New(ctx, cfg, tel, dbHandle)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. /healthz
	mustStatus(t, ts.URL+"/healthz", "", http.StatusOK)
	mustStatus(t, ts.URL+"/readyz", "", http.StatusOK)

	// 2. /openapi.json — exposed without auth.
	resp, err := http.Get(ts.URL + "/openapi.json")
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("openapi status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 3. local login
	loginBody, _ := json.Marshal(map[string]string{
		"email": "admin@smoke.test", "password": "hunter2!",
	})
	resp, err = http.Post(ts.URL+"/api/v1/auth/login", "application/json", strings.NewReader(string(loginBody)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var lr struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	_ = resp.Body.Close()
	if lr.Token == "" {
		t.Fatalf("empty token")
	}

	// 4. /api/v1/auth/me with bearer
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("me status %d", resp.StatusCode)
	}
	var me struct {
		Email string   `json:"email"`
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	_ = resp.Body.Close()
	if me.Email != "admin@smoke.test" || len(me.Roles) == 0 {
		t.Fatalf("me payload: %+v", me)
	}

	// 5. /api/v1/findings — should be empty, not error.
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("findings status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestAstronomerJWKSRouteIntegration(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set")
	}

	ctx := context.Background()
	tel, _ := observability.Init(ctx, "test")

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	orgName := "astrotest-" + strings.ReplaceAll(suffix, ".", "-")
	astroUserID := "astro-user-" + orgName
	disabledAstroUserID := "astro-disabled-" + orgName
	unmappedAstroUserID := "astro-unmapped-" + orgName

	var orgID, userID, disabledUserID string
	if err := pool.QueryRow(ctx, `
INSERT INTO orgs (name, display_name) VALUES ($1, 'Astronomer Integration Test')
RETURNING id`, orgName).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	}()
	if err := pool.QueryRow(ctx, `
INSERT INTO users (org_id, email, display_name)
VALUES ($1, $2, 'Mapped Astronomer User')
RETURNING id`, orgID, "mapped-"+orgName+"@astro.test").Scan(&userID); err != nil {
		t.Fatalf("seed mapped user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
INSERT INTO users (org_id, email, display_name, disabled)
VALUES ($1, $2, 'Disabled Astronomer User', true)
RETURNING id`, orgID, "disabled-"+orgName+"@astro.test").Scan(&disabledUserID); err != nil {
		t.Fatalf("seed disabled user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO role_assignments (user_id, role, scope_org_id)
VALUES ($1, 'Auditor', $2)`, userID, orgID); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO astronomer_identity_map (astronomer_user_id, user_id, org_id)
VALUES ($1, $2, $3), ($4, $5, $3)`,
		astroUserID, userID, orgID,
		disabledAstroUserID, disabledUserID); err != nil {
		t.Fatalf("seed identity map: %v", err)
	}

	priv, jwksServer := newTestJWKS(t, "astro-test-key")
	defer jwksServer.Close()

	dbHandle, err := db.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer dbHandle.Close()

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cfg := Config{
		ListenAddr:         ":0",
		DatabaseURL:        databaseURL,
		JWTKeys:            [][]byte{key},
		JWTIssuer:          "constellation-test",
		JWTAudience:        "constellation-api",
		JWTTTL:             time.Hour,
		CORSOrigins:        []string{"http://localhost:5173"},
		AstronomerJWKSURL:  jwksServer.URL,
		AstronomerIssuer:   "https://astronomer.test",
		AstronomerAudience: "constellation-security",
	}
	srv, err := New(ctx, cfg, tel, dbHandle)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	validToken := signAstronomerToken(t, priv, "astro-test-key", jwt.MapClaims{
		"sub": astroUserID,
		"iss": "https://astronomer.test",
		"aud": "constellation-security",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	mustBearerStatus(t, ts.URL+"/api/v1/security/findings", validToken, http.StatusOK)

	unmappedToken := signAstronomerToken(t, priv, "astro-test-key", jwt.MapClaims{
		"sub": unmappedAstroUserID,
		"iss": "https://astronomer.test",
		"aud": "constellation-security",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	mustBearerStatus(t, ts.URL+"/api/v1/security/findings", unmappedToken, http.StatusForbidden)

	disabledToken := signAstronomerToken(t, priv, "astro-test-key", jwt.MapClaims{
		"sub": disabledAstroUserID,
		"iss": "https://astronomer.test",
		"aud": "constellation-security",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	mustBearerStatus(t, ts.URL+"/api/v1/security/findings", disabledToken, http.StatusForbidden)

	wrongAudienceToken := signAstronomerToken(t, priv, "astro-test-key", jwt.MapClaims{
		"sub": astroUserID,
		"iss": "https://astronomer.test",
		"aud": "another-product",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	mustBearerStatus(t, ts.URL+"/api/v1/security/findings", wrongAudienceToken, http.StatusUnauthorized)

	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen mismatched key: %v", err)
	}
	badSignatureToken := signAstronomerToken(t, otherPriv, "astro-test-key", jwt.MapClaims{
		"sub": astroUserID,
		"iss": "https://astronomer.test",
		"aud": "constellation-security",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	mustBearerStatus(t, ts.URL+"/api/v1/security/findings", badSignatureToken, http.StatusUnauthorized)
}

func mustStatus(t *testing.T, url string, _ string, want int) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	if resp.StatusCode != want {
		t.Fatalf("status %s = %d, want %d", url, resp.StatusCode, want)
	}
	_ = resp.Body.Close()
}

func mustBearerStatus(t *testing.T, url, token string, want int) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	if resp.StatusCode != want {
		t.Fatalf("status %s = %d, want %d", url, resp.StatusCode, want)
	}
	_ = resp.Body.Close()
}

func newTestJWKS(t *testing.T, kid string) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": kid,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		}},
	}
	return priv, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
}

func signAstronomerToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}
