//go:build integration

package server

import (
	"net/http"
	"testing"
)

// The UI's 3-mode theme is server-synced: defaults to system, persists per
// user, rejects unknown values, and shares storage with /settings/user.
func TestPreferencesThemeRoundTrip(t *testing.T) {
	_, ts, _, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	url := ts.URL + "/api/v1/me/preferences"

	if status, body := doJSON(t, http.MethodGet, url, admin, nil); status != http.StatusOK || body["theme"] != "system" {
		t.Fatalf("default: %d %+v", status, body)
	}
	if status, body := doJSON(t, http.MethodPut, url, admin, map[string]any{"theme": "dark"}); status != http.StatusOK || body["theme"] != "dark" || body["updated_at"] == nil {
		t.Fatalf("put dark: %d %+v", status, body)
	}
	if status, body := doJSON(t, http.MethodGet, url, admin, nil); status != http.StatusOK || body["theme"] != "dark" {
		t.Fatalf("get after put: %d %+v", status, body)
	}
	// Per user: another user still sees the default.
	if status, body := doJSON(t, http.MethodGet, url, auditor, nil); status != http.StatusOK || body["theme"] != "system" {
		t.Fatalf("other user: %d %+v", status, body)
	}
	for _, bad := range []map[string]any{{"theme": "purple"}, {"theme": "dark", "font": "huge"}} {
		if status, body := doJSON(t, http.MethodPut, url, admin, bad); status != http.StatusBadRequest || errCode(body) != "invalid_argument" {
			t.Fatalf("bad %v: %d %+v", bad, status, body)
		}
	}
	if status, _ := doJSON(t, http.MethodPatch, ts.URL+"/api/v1/settings/user", admin, map[string]any{"theme": "sepia"}); status != http.StatusBadRequest {
		t.Fatalf("settings bag accepted an invalid theme: %d", status)
	}
	if status, body := doJSON(t, http.MethodGet, ts.URL+"/api/v1/settings/user", admin, nil); status != http.StatusOK || body["settings"].(map[string]any)["theme"] != "dark" {
		t.Fatalf("shared storage: %d %+v", status, body)
	}
	if status, _ := doJSON(t, http.MethodGet, url, "", nil); status != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", status)
	}
}

func errCode(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}
