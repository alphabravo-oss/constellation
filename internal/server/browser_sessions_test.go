package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
)

func browserRequest(t *testing.T, server *httptest.Server, method, path string, cookies []*http.Cookie, body any, headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, server.URL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(auth.BrowserHeader, "browser")
	request.Header.Set("Origin", server.URL)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return response, result
}

func browserCredentials(t *testing.T, pool *pgxpool.Pool, userID uuid.UUID) map[string]string {
	t.Helper()
	password := "CookieSession-Passphrase1!"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	email := userID.String() + "@browser.example.test"
	if _, err := pool.Exec(context.Background(), `UPDATE users SET email=$2, password_hash=$3 WHERE id=$1`, userID, email, hash); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"email": email, "password": password}
}

func browserLogin(t *testing.T, server *httptest.Server, credentials map[string]string) []*http.Cookie {
	t.Helper()
	response, body := browserRequest(t, server, http.MethodPost, "/api/v1/auth/login", nil, credentials, nil)
	if response.StatusCode != http.StatusOK || body["token"] != nil || len(response.Cookies()) != 2 {
		t.Fatalf("browser login: status=%d body=%v cookies=%d", response.StatusCode, body, len(response.Cookies()))
	}
	for _, cookie := range response.Cookies() {
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge <= 0 {
			t.Fatalf("unsafe cookie attributes for %s", cookie.Name)
		}
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("session response may be cached")
	}
	return response.Cookies()
}

func sessionCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("missing %s", name)
	return nil
}

func TestBrowserSessionRotationReuseAndBearerPrecedence(t *testing.T) {
	_, server, pool, signer, userID, _, orgID := newSysConfigTestServer(t)
	credentials := browserCredentials(t, pool, userID)
	cookies := browserLogin(t, server, credentials)
	claims, err := signer.Verify(sessionCookie(t, cookies, auth.AccessCookie).Value)
	if err != nil || !claims.Tracked || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 15*time.Minute {
		t.Fatalf("access token must be tracked and short-lived: %v", err)
	}
	for _, headers := range []map[string]string{nil, {"Authorization": "Basic invalid"}, {"Authorization": "Bearer invalid"}} {
		response, _ := browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", cookies, nil, headers)
		want := http.StatusOK
		if headers != nil {
			want = http.StatusUnauthorized
		}
		if response.StatusCode != want {
			t.Fatalf("explicit authorization precedence: got %d want %d", response.StatusCode, want)
		}
	}
	foreign, _, err := signer.Issue(userID, uuid.New(), credentials["email"], nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	response, _ := browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", cookies, nil, map[string]string{"Authorization": "Bearer " + foreign})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("cross-organization claim accepted")
	}
	response, body := browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", cookies, nil, nil)
	if response.StatusCode != http.StatusOK || body["token"] != nil {
		t.Fatalf("refresh: %d %v", response.StatusCode, body)
	}
	rotated := response.Cookies()
	if sessionCookie(t, rotated, auth.RefreshCookie).Value == sessionCookie(t, cookies, auth.RefreshCookie).Value {
		t.Fatal("refresh secret was not rotated")
	}
	if !sessionCookie(t, rotated, auth.RefreshCookie).Expires.Equal(sessionCookie(t, cookies, auth.RefreshCookie).Expires) {
		t.Fatal("refresh extended absolute session lifetime")
	}
	newClaims, err := signer.Verify(sessionCookie(t, rotated, auth.AccessCookie).Value)
	if err != nil || newClaims.SessionID() != claims.SessionID() {
		t.Fatalf("refresh changed session family: %v", err)
	}
	var total, consumed, rawSecrets int
	err = pool.QueryRow(context.Background(), `SELECT count(*), count(consumed_at), count(*) FILTER (WHERE token_hash=$2) FROM browser_refresh_tokens WHERE session_id=$1`, claims.SessionID(), sessionCookie(t, rotated, auth.RefreshCookie).Value).Scan(&total, &consumed, &rawSecrets)
	if err != nil || total != 2 || consumed != 1 || rawSecrets != 0 {
		t.Fatalf("refresh persistence: total=%d consumed=%d raw=%d err=%v", total, consumed, rawSecrets, err)
	}
	response, _ = browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", cookies, nil, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("consumed token replay accepted")
	}
	for _, path := range []string{"/api/v1/auth/me", "/api/v1/auth/refresh"} {
		method := http.MethodGet
		if path == "/api/v1/auth/refresh" {
			method = http.MethodPost
		}
		response, _ = browserRequest(t, server, method, path, rotated, nil, nil)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked session family accepted at %s", path)
		}
	}
	var auditCount int
	err = pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='auth.refresh.reuse'`, orgID).Scan(&auditCount)
	if err != nil || auditCount != 1 {
		t.Fatalf("missing reuse audit: %d %v", auditCount, err)
	}
	status, bearer := postLogin(t, server.URL, credentials["email"], credentials["password"])
	if status != http.StatusOK || bearer == "" || getMe(t, server.URL, bearer) != http.StatusOK {
		t.Fatal("CLI bearer login regressed")
	}
}

func TestBrowserSessionCSRFLogoutAndRevocation(t *testing.T) {
	serverHandle, server, pool, _, userID, _, _ := newSysConfigTestServer(t)
	credentials := browserCredentials(t, pool, userID)
	cookies := browserLogin(t, server, credentials)
	for _, headers := range []map[string]string{
		{auth.BrowserHeader: ""}, {"Origin": "https://attacker.test"}, {"Origin": "null"},
		{"Origin": ""}, {"Origin": server.URL + ".attacker.test"},
	} {
		for _, path := range []string{"/api/v1/auth/logout", "/api/v1/auth/refresh", "/api/v1/auth/login"} {
			response, _ := browserRequest(t, server, http.MethodPost, path, cookies, credentials, headers)
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("CSRF accepted %s headers=%v status=%d", path, headers, response.StatusCode)
			}
		}
	}
	response, _ := browserRequest(t, server, http.MethodPost, "/api/v1/auth/logout", cookies, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("logout: %d", response.StatusCode)
	}
	for _, cookie := range response.Cookies() {
		if cookie.MaxAge != -1 || !cookie.HttpOnly || !cookie.Secure {
			t.Fatal("logout did not expire secure cookies")
		}
	}
	response, _ = browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", cookies, nil, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("refresh survived logout")
	}
	for _, mutation := range []string{
		`UPDATE users SET session_epoch=session_epoch+1 WHERE id=$1`,
		`UPDATE users SET disabled=true WHERE id=$1`,
		`UPDATE browser_refresh_tokens SET expires_at=now()-interval '1 second' WHERE session_id IN (SELECT session_id FROM user_sessions WHERE user_id=$1)`,
		`UPDATE user_sessions SET last_seen_at=now()-interval '1 hour' WHERE user_id=$1`,
	} {
		if _, err := pool.Exec(context.Background(), `UPDATE users SET disabled=false WHERE id=$1`, userID); err != nil {
			t.Fatal(err)
		}
		serverHandle.cfg.SessionIdleTimeout = 30 * time.Minute
		if _, err := pool.Exec(context.Background(), `INSERT INTO auth_policy(org_id,policy) SELECT org_id,'{"idle_timeout_minutes":30}'::jsonb FROM users WHERE id=$1 ON CONFLICT(org_id) DO UPDATE SET policy=EXCLUDED.policy`, userID); err != nil {
			t.Fatal(err)
		}
		cookies = browserLogin(t, server, credentials)
		if _, err := pool.Exec(context.Background(), mutation, userID); err != nil {
			t.Fatal(err)
		}
		response, _ = browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", cookies, nil, nil)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked/expired refresh accepted after %s: %d", mutation, response.StatusCode)
		}
	}
}

func TestBrowserSessionConcurrentRefreshRevokesReusedFamily(t *testing.T) {
	_, server, pool, _, userID, _, _ := newSysConfigTestServer(t)
	cookies := browserLogin(t, server, browserCredentials(t, pool, userID))
	var workers sync.WaitGroup
	responses := make(chan *http.Response, 2)
	start := make(chan struct{})
	for worker := 0; worker < 2; worker++ {
		workers.Go(func() {
			<-start
			response, _ := browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", cookies, nil, nil)
			responses <- response
		})
	}
	close(start)
	workers.Wait()
	close(responses)
	succeeded, rejected := 0, 0
	for response := range responses {
		switch response.StatusCode {
		case http.StatusOK:
			succeeded++
			check, _ := browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", response.Cookies(), nil, nil)
			if check.StatusCode != http.StatusUnauthorized {
				t.Fatal("concurrently replayed session remains authorized")
			}
		case http.StatusUnauthorized:
			rejected++
		default:
			t.Fatalf("unexpected concurrent refresh status %d", response.StatusCode)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("refresh must serialize: succeeded=%d rejected=%d", succeeded, rejected)
	}
}

func TestBrowserSessionRefreshRateLimitDoesNotConsumeLoginBudget(t *testing.T) {
	_, server, pool, _, userID, _, _ := newSysConfigTestServer(t)
	credentials := browserCredentials(t, pool, userID)
	for attempt := 0; attempt < 61; attempt++ {
		response, _ := browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", nil, nil, nil)
		want := http.StatusUnauthorized
		if attempt == 60 {
			want = http.StatusTooManyRequests
		}
		if response.StatusCode != want {
			t.Fatalf("refresh rate limit attempt %d: got %d want %d", attempt, response.StatusCode, want)
		}
	}
	browserLogin(t, server, credentials)
}
