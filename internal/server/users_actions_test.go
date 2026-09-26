package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestUserActions_RoutesEnforceRBACAndAudit(t *testing.T) {
	_, server, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	ctx := context.Background()
	targetID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash, failed_login_count, block_login_since)
VALUES ($1, $2, $3, 'Action Target', 'hash', 9, now())`, targetID, orgID, "target-"+targetID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, targetID)
	})
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	target := issueFor(t, signer, targetID, orgID, 0)
	userState := func() map[string]any {
		t.Helper()
		status, body := doJSON(t, http.MethodGet, server.URL+"/api/v1/access-control", admin, nil)
		if status != http.StatusOK {
			t.Fatalf("access-control overview: status=%d body=%v", status, body)
		}
		users, ok := body["users"].([]any)
		if !ok {
			t.Fatalf("access-control users missing: %v", body)
		}
		for _, raw := range users {
			user, ok := raw.(map[string]any)
			if ok && user["id"] == targetID.String() {
				return user
			}
		}
		t.Fatalf("target absent from access-control overview: %v", users)
		return nil
	}
	if state := userState(); state["local_password"] != true || state["locked"] != true || state["password_reset_required"] != false {
		t.Fatalf("initial recovery state: %v", state)
	}
	if got := getMe(t, server.URL, target); got != http.StatusOK {
		t.Fatalf("target token before reset: %d", got)
	}
	for _, action := range []string{"unlock", "force-password-reset"} {
		path := server.URL + "/api/v1/users/" + targetID.String() + "/" + action
		if status, _ := doJSON(t, http.MethodPost, path, auditor, nil); status != http.StatusForbidden {
			t.Fatalf("auditor %s: status=%d, want 403", action, status)
		}
	}
	unlockPath := server.URL + "/api/v1/users/" + targetID.String() + "/unlock"
	if status, body := doJSON(t, http.MethodPost, unlockPath, admin, nil); status != http.StatusOK || body["status"] != "unlocked" {
		t.Fatalf("admin unlock: status=%d body=%v", status, body)
	}
	resetPath := server.URL + "/api/v1/users/" + targetID.String() + "/force-password-reset"
	if status, body := doJSON(t, http.MethodPost, resetPath, admin, nil); status != http.StatusOK || body["status"] != "reset_required" {
		t.Fatalf("admin reset: status=%d body=%v", status, body)
	}
	if got := getMe(t, server.URL, target); got != http.StatusUnauthorized {
		t.Fatalf("target token after reset: %d, want 401", got)
	}
	if state := userState(); state["local_password"] != true || state["locked"] != false || state["password_reset_required"] != true {
		t.Fatalf("recovered user state: %v", state)
	}
	var failedCount int
	var blocked, mustChange bool
	if err := pool.QueryRow(ctx, `SELECT failed_login_count, block_login_since IS NOT NULL, must_change_password FROM users WHERE id=$1`, targetID).Scan(&failedCount, &blocked, &mustChange); err != nil {
		t.Fatal(err)
	}
	if failedCount != 0 || blocked || !mustChange {
		t.Fatalf("target state: failed=%d blocked=%t mustChange=%t", failedCount, blocked, mustChange)
	}
	for _, action := range []string{"user.unlock", "user.force_password_reset"} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND actor_id=$2 AND target_id=$3 AND action=$4`, orgID, adminID, targetID.String(), action).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s audit rows=%d, want 1", action, count)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET password_hash=NULL, block_login_since=now() - interval '2 days' WHERE id=$1`, targetID); err != nil {
		t.Fatal(err)
	}
	if state := userState(); state["local_password"] != false || state["locked"] != false || state["password_reset_required"] != true {
		t.Fatalf("SSO-only expired-lockout state: %v", state)
	}
	if status, body := doJSON(t, http.MethodPost, resetPath, admin, nil); status != http.StatusNotFound {
		t.Fatalf("SSO-only reset: status=%d body=%v, want 404", status, body)
	}
}
