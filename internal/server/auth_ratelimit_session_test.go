package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/auth"
)

// maxConcurrentSessions mirrors the handler-package cap (handler.maxConcurrentSessions).
// Duplicated here because it is an unexported const in another package; if the handler
// value changes, this test asserts against the new behavior only after this is updated.
const maxConcurrentSessions = 5

// postJSON issues a POST with a JSON body and returns the status code + decoded token (if any).
func postLogin(t *testing.T, baseURL, email, password string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Token
}

// A3: hammering the unauthenticated /auth/login past the per-IP limit returns 429.
func TestAuthRateLimit_429PastIPLimit(t *testing.T) {
	ts, _, _, _, _ := newAuthTestServer(t)

	// authIPRateLimit requests should be allowed (each 401 on bad creds, but not 429),
	// then the next one trips the limiter.
	saw429 := false
	for i := 0; i < authIPRateLimit+5; i++ {
		status, _ := postLogin(t, ts.URL, "nobody@example.test", "wrong")
		if status == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Fatalf("expected a 429 within %d requests, never saw one", authIPRateLimit+5)
	}
}

// A3: a user logging in more than maxConcurrentSessions times has the oldest session(s)
// evicted, and the evicted JWT is rejected by the auth middleware while the newest is
// still accepted.
func TestConcurrentSessionCap_EvictsOldest(t *testing.T) {
	ts, pool, _, userID, orgID := newAuthTestServer(t)
	ctx := context.Background()

	pw := "SessionCapPass-1!"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	email := "sescap-" + userID.String() + "@example.test"
	if _, err := pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, email = $3 WHERE id = $1`, userID, hash, email); err != nil {
		t.Fatalf("set password: %v", err)
	}

	// First login -> the session we will check gets evicted once we exceed the cap.
	status, firstTok := postLogin(t, ts.URL, email, pw)
	if status != http.StatusOK || firstTok == "" {
		t.Fatalf("first login: status=%d token=%q", status, firstTok)
	}
	if got := getMe(t, ts.URL, firstTok); got != http.StatusOK {
		t.Fatalf("first token /me = %d, want 200", got)
	}

	// Log in maxConcurrentSessions more times: that is cap+1 total live sessions, so the
	// oldest (firstTok) must be evicted.
	var lastTok string
	for i := 0; i < maxConcurrentSessions; i++ {
		st, tok := postLogin(t, ts.URL, email, pw)
		if st != http.StatusOK || tok == "" {
			t.Fatalf("login %d: status=%d token=%q", i, st, tok)
		}
		lastTok = tok
	}

	// The cap holds in the DB.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_sessions WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if n != maxConcurrentSessions {
		t.Fatalf("session count = %d, want %d", n, maxConcurrentSessions)
	}

	// The first (evicted) token is now rejected; the newest still works.
	if got := getMe(t, ts.URL, firstTok); got != http.StatusUnauthorized {
		t.Fatalf("evicted token /me = %d, want 401", got)
	}
	if got := getMe(t, ts.URL, lastTok); got != http.StatusOK {
		t.Fatalf("newest token /me = %d, want 200", got)
	}
	_ = orgID
}

// A4: while must_change_password is set, every route except the password-change/logout
// endpoints is blocked with 403; clearing the flag (via the change endpoint) restores access.
func TestForcedPasswordReset_BlocksOtherRequests(t *testing.T) {
	ts, pool, signer, userID, orgID := newAuthTestServer(t)
	ctx := context.Background()

	pw := "ForcedReset-Pass1!"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, must_change_password = TRUE WHERE id = $1`, userID, hash); err != nil {
		t.Fatalf("set must_change: %v", err)
	}

	tok := issueFor(t, signer, userID, orgID, 0)
	// Record the session so the cap check doesn't reject the hand-minted token.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_sessions (session_id, user_id) VALUES ($1, $2)`,
		mustSessionID(t, signer, tok), userID); err != nil {
		t.Fatalf("record session: %v", err)
	}

	// /me is blocked with 403 while the flag is set.
	if got := getMe(t, ts.URL, tok); got != http.StatusForbidden {
		t.Fatalf("forced-reset /me = %d, want 403", got)
	}

	// The change-password endpoint is reachable; a valid change clears the flag.
	body, _ := json.Marshal(map[string]string{"current_password": pw, "new_password": "AfterReset-Pass2!"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change-password status = %d, want 200", resp.StatusCode)
	}

	var mustChange bool
	if err := pool.QueryRow(ctx, `SELECT must_change_password FROM users WHERE id = $1`, userID).Scan(&mustChange); err != nil {
		t.Fatalf("read flag: %v", err)
	}
	if mustChange {
		t.Fatalf("must_change_password still set after change")
	}
}

// mustSessionID parses the jti out of a signed token for session-row seeding in tests.
func mustSessionID(t *testing.T, signer *auth.Signer, tok string) uuid.UUID {
	t.Helper()
	claims, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("verify for sid: %v", err)
	}
	return claims.SessionID()
}
