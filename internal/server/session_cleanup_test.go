//go:build integration

package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/lifecycle"
)

func TestSessionCleanupPreservesBrowserRefreshAndReuseRevocation(t *testing.T) {
	_, server, pool, signer, userID, _, _ := newSysConfigTestServer(t)
	original := browserLogin(t, server, browserCredentials(t, pool, userID))
	claims, err := signer.Verify(sessionCookie(t, original, auth.AccessCookie).Value)
	if err != nil {
		t.Fatal(err)
	}
	var expiry, refreshExpiry time.Time
	err = pool.QueryRow(t.Context(), `SELECT s.expires_at,t.expires_at FROM user_sessions s JOIN browser_refresh_tokens t USING(session_id) WHERE s.session_id=$1`, claims.SessionID()).Scan(&expiry, &refreshExpiry)
	if err != nil || expiry.Before(refreshExpiry) || !expiry.After(claims.ExpiresAt.Time) {
		t.Fatalf("session expiry does not cover refresh: %s %s %v", expiry, refreshExpiry, err)
	}
	response, _ := browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", original, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d", response.StatusCode)
	}
	rotated := response.Cookies()
	if _, err := lifecycle.ReapSessions(t.Context(), pool, 100); err != nil {
		t.Fatal(err)
	}
	response, _ = browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", rotated, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("cleanup logged out active browser: %d", response.StatusCode)
	}
	response, _ = browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", original, nil, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("consumed refresh replay accepted: %d", response.StatusCode)
	}
	response, _ = browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", rotated, nil, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cleanup weakened replay revocation: %d", response.StatusCode)
	}
}
