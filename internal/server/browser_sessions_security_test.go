package server

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
)

func TestBrowserSessionsSecurityAccessCannotOutliveAbsoluteDeadline(t *testing.T) {
	_, server, pool, signer, userID, _, _ := newSysConfigTestServer(t)
	cookies := browserLogin(t, server, browserCredentials(t, pool, userID))
	claims, err := signer.Verify(sessionCookie(t, cookies, auth.AccessCookie).Value)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(1500 * time.Millisecond).UTC()
	if _, err := pool.Exec(context.Background(), `UPDATE browser_refresh_tokens SET expires_at=$2 WHERE session_id=$1`, claims.SessionID(), deadline); err != nil {
		t.Fatal(err)
	}
	response, body := browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", cookies, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("refresh before absolute deadline: %d %v", response.StatusCode, body)
	}
	rotated := response.Cookies()
	refreshed, err := signer.Verify(sessionCookie(t, rotated, auth.AccessCookie).Value)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.ExpiresAt.Time.After(deadline) {
		t.Errorf("refreshed access expires %s, after absolute browser-session deadline %s", refreshed.ExpiresAt.Time, deadline)
	}
	time.Sleep(max(0, time.Until(deadline)+100*time.Millisecond))
	response, body = browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", rotated, nil, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("access after absolute browser-session expiry: status=%d body=%v, want 401", response.StatusCode, body)
	}
}

func TestBrowserSessionsSecurityPasswordChangeRevokesBothCredentialTypes(t *testing.T) {
	_, server, pool, _, userID, _, _ := newSysConfigTestServer(t)
	credentials := browserCredentials(t, pool, userID)
	first := browserLogin(t, server, credentials)
	sibling := browserLogin(t, server, credentials)
	newPassword := "NewBrowser-SecurityPassphrase2!"
	response, body := browserRequest(t, server, http.MethodPost, "/api/v1/auth/change-password", first, map[string]string{
		"current_password": credentials["password"], "new_password": newPassword,
	}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("change password: %d %v", response.StatusCode, body)
	}
	for index, cookies := range [][]*http.Cookie{first, sibling} {
		for _, endpoint := range []struct{ method, path string }{{http.MethodGet, "/api/v1/auth/me"}, {http.MethodPost, "/api/v1/auth/refresh"}} {
			response, body := browserRequest(t, server, endpoint.method, endpoint.path, cookies, nil, nil)
			if response.StatusCode != http.StatusUnauthorized {
				t.Errorf("revoked password session %d at %s: %d %v", index, endpoint.path, response.StatusCode, body)
			}
		}
	}
	credentials["password"] = newPassword
	replacement := browserLogin(t, server, credentials)
	response, body = browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", replacement, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("new password session could not refresh: %d %v", response.StatusCode, body)
	}
}

func TestBrowserSessionsSecurityRoleGrantAndRemovalRevokeRefresh(t *testing.T) {
	_, server, pool, signer, adminID, userID, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	credentials := browserCredentials(t, pool, userID)
	cookies := browserLogin(t, server, credentials)
	status, body := doJSON(t, http.MethodPost, server.URL+"/api/v1/access-control/role-bindings", admin, map[string]any{
		"subject_id": userID.String(), "subject_type": "user", "role_id": "GlobalAdmin", "scopes": []any{},
	})
	if status != http.StatusCreated {
		t.Fatalf("grant: %d %v", status, body)
	}
	bindingID, ok := body["id"].(string)
	if !ok {
		t.Fatal("missing role binding ID")
	}
	for _, endpoint := range []struct{ method, path string }{{http.MethodGet, "/api/v1/auth/me"}, {http.MethodPost, "/api/v1/auth/refresh"}} {
		response, body := browserRequest(t, server, endpoint.method, endpoint.path, cookies, nil, nil)
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("pre-grant credential at %s: %d %v", endpoint.path, response.StatusCode, body)
		}
	}
	cookies = browserLogin(t, server, credentials)
	response, body := browserRequest(t, server, http.MethodGet, "/api/v1/system/config", cookies, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("granted role missing: %d %v", response.StatusCode, body)
	}
	status, body = doJSON(t, http.MethodDelete, server.URL+"/api/v1/access-control/role-bindings/"+bindingID, admin, nil)
	if status != http.StatusOK {
		t.Fatalf("remove grant: %d %v", status, body)
	}
	for _, endpoint := range []struct{ method, path string }{{http.MethodGet, "/api/v1/auth/me"}, {http.MethodPost, "/api/v1/auth/refresh"}} {
		response, body := browserRequest(t, server, endpoint.method, endpoint.path, cookies, nil, nil)
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("removed-role credential at %s: %d %v", endpoint.path, response.StatusCode, body)
		}
	}
	cookies = browserLogin(t, server, credentials)
	response, body = browserRequest(t, server, http.MethodGet, "/api/v1/system/config", cookies, nil, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("removed admin grant survived new login: %d %v", response.StatusCode, body)
	}
}

func TestBrowserSessionsSecurityCookieCannotOverrideMutationBearer(t *testing.T) {
	_, server, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	cookies := browserLogin(t, server, browserCredentials(t, pool, adminID))
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	for _, authorization := range []string{"Bearer " + auditor, "Bearer invalid", "Basic invalid", "Bearer "} {
		response, body := browserRequest(t, server, http.MethodPatch, "/api/v1/system/config", cookies, map[string]bool{"tls_verify": false}, map[string]string{
			"Authorization": authorization, "Origin": "https://attacker.test", auth.BrowserHeader: "",
		})
		if response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusUnauthorized {
			t.Errorf("cookie privilege leaked into explicit bearer mutation: %d %v", response.StatusCode, body)
		}
	}
	response, body := browserRequest(t, server, http.MethodGet, "/api/v1/system/config", cookies, nil, nil)
	config, ok := body["config"].(map[string]any)
	if response.StatusCode != http.StatusOK || !ok || config["tls_verify"] != true {
		t.Fatalf("rejected bearer requests changed config: %d %v", response.StatusCode, body)
	}
	admin := sessionCookie(t, cookies, auth.AccessCookie).Value
	response, body = browserRequest(t, server, http.MethodPatch, "/api/v1/system/config", nil, map[string]bool{"tls_verify": false}, map[string]string{
		"Authorization": "Bearer " + admin, "Origin": "https://attacker.test", auth.BrowserHeader: "",
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("explicit authorized bearer incorrectly required cookie CSRF proof: %d %v", response.StatusCode, body)
	}
}

func TestBrowserSessionsSecurityRefreshWaitsForRevocationCommit(t *testing.T) {
	_, server, pool, signer, userID, _, _ := newSysConfigTestServer(t)
	cookies := browserLogin(t, server, browserCredentials(t, pool, userID))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `UPDATE users SET session_epoch=session_epoch+1 WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	refreshToken := sessionCookie(t, cookies, auth.RefreshCookie).Value
	go func() {
		_, err := auth.RotateBrowserSession(ctx, pool, signer, refreshToken, 0)
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("refresh bypassed uncommitted revocation lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, auth.ErrRefreshInvalid) {
		t.Fatalf("refresh survived committed epoch change: %v", err)
	}
	response, body := browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", cookies, nil, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("access survived committed revocation: %d %v", response.StatusCode, body)
	}
}

func TestBrowserSessionsSecurityIdleExpiryDoesNotRevokeActiveSibling(t *testing.T) {
	_, server, pool, signer, userID, _, orgID := newSysConfigTestServer(t)
	credentials := browserCredentials(t, pool, userID)
	expired := browserLogin(t, server, credentials)
	active := browserLogin(t, server, credentials)
	claims, err := signer.Verify(sessionCookie(t, expired, auth.AccessCookie).Value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO auth_policy(org_id, policy) VALUES ($1,'{"idle_timeout_minutes":1}'::jsonb) ON CONFLICT(org_id) DO UPDATE SET policy=EXCLUDED.policy`, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE user_sessions SET last_seen_at=now()-interval '2 minutes' WHERE session_id=$1`, claims.SessionID()); err != nil {
		t.Fatal(err)
	}
	response, body := browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", expired, nil, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("idle session accepted: %d %v", response.StatusCode, body)
	}
	response, body = browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", active, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Errorf("independently active sibling revoked by another family's idle timeout: %d %v", response.StatusCode, body)
	}
	response, body = browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", active, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Errorf("active sibling refresh revoked by another family's idle timeout: %d %v", response.StatusCode, body)
	}
}

func TestBrowserSessionsSecurityForeignRoleBindingCannotRevokeOtherOrg(t *testing.T) {
	_, server, pool, signer, adminID, _, orgID := newSysConfigTestServer(t)
	foreignOrg, foreignUser := uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES ($1,$2,'Foreign session security test')`, foreignOrg, foreignOrg.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM role_assignments WHERE user_id=$1`, foreignUser)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, foreignUser)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, foreignOrg)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,org_id,email,display_name) VALUES ($1,$2,$3,'Foreign user')`, foreignUser, foreignOrg, foreignUser.String()+"@foreign.test"); err != nil {
		t.Fatal(err)
	}
	cookies := browserLogin(t, server, browserCredentials(t, pool, foreignUser))
	status, body := doJSON(t, http.MethodPost, server.URL+"/api/v1/access-control/role-bindings", issueFor(t, signer, adminID, orgID, 0), map[string]any{
		"subject_id": foreignUser.String(), "subject_type": "user", "role_id": "Auditor", "scopes": []any{},
	})
	if status != http.StatusNotFound && status != http.StatusBadRequest && status != http.StatusForbidden {
		t.Errorf("cross-org role mutation accepted: %d %v", status, body)
	}
	response, body := browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", cookies, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Errorf("foreign org admin revoked victim's access session: %d %v", response.StatusCode, body)
	}
	response, body = browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", cookies, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Errorf("foreign org admin revoked victim's refresh session: %d %v", response.StatusCode, body)
	}
	if response.StatusCode == http.StatusOK {
		cookies = response.Cookies()
	}
	admin := issueFor(t, signer, adminID, orgID, 0)
	for _, endpoint := range []struct{ method, suffix string }{
		{http.MethodPost, "/disable"}, {http.MethodPost, "/force-password-reset"},
		{http.MethodPost, "/unlock"}, {http.MethodDelete, ""},
	} {
		status, body = doJSON(t, endpoint.method, server.URL+"/api/v1/users/"+foreignUser.String()+endpoint.suffix, admin, nil)
		if status != http.StatusNotFound {
			t.Errorf("foreign user lifecycle %s %s: %d %v", endpoint.method, endpoint.suffix, status, body)
		}
	}
	legacyBinding := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO role_bindings(id,org_id,subject_id,subject_type,role_id) VALUES($1,$2,$3,'user','Auditor')`, legacyBinding, orgID, foreignUser.String()); err != nil {
		t.Fatal(err)
	}
	status, body = doJSON(t, http.MethodDelete, server.URL+"/api/v1/access-control/role-bindings/"+legacyBinding.String(), admin, nil)
	if status != http.StatusNotFound {
		t.Errorf("legacy foreign-target binding deletion accepted: %d %v", status, body)
	}
	var epoch int64
	if err := pool.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id=$1`, foreignUser).Scan(&epoch); err != nil || epoch != 0 {
		t.Errorf("foreign user epoch changed: %d %v", epoch, err)
	}
	response, body = browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", cookies, nil, nil)
	if response.StatusCode != http.StatusOK {
		t.Errorf("foreign lifecycle/delete revoked victim: %d %v", response.StatusCode, body)
	}
}

func TestBrowserSessionsSecurityRefreshCannotMoveActivityBackwards(t *testing.T) {
	_, server, pool, signer, userID, _, _ := newSysConfigTestServer(t)
	cookies := browserLogin(t, server, browserCredentials(t, pool, userID))
	claims, err := signer.Verify(sessionCookie(t, cookies, auth.AccessCookie).Value)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(testDBURL())
	if err != nil {
		t.Fatal(err)
	}
	application := "browser-security-" + uuid.NewString()
	config.ConnConfig.RuntimeParams["application_name"] = application
	config.MaxConns = 1
	refreshPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer refreshPool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	refreshToken := sessionCookie(t, cookies, auth.RefreshCookie).Value
	go func() {
		_, err := auth.RotateBrowserSession(ctx, refreshPool, signer, refreshToken, time.Minute)
		result <- err
	}()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')`, application).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("refresh completed before user-row lock released: %v", err)
		case <-ctx.Done():
			t.Fatal("refresh never reached the controlled lock wait")
		case <-time.After(5 * time.Millisecond):
		}
	}
	var activityBeforeRefresh time.Time
	if err := tx.QueryRow(ctx, `UPDATE user_sessions SET last_seen_at=clock_timestamp() WHERE session_id=$1 RETURNING last_seen_at`, claims.SessionID()).Scan(&activityBeforeRefresh); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("refresh after current activity: %v", err)
	}
	var activityAfterRefresh time.Time
	if err := pool.QueryRow(ctx, `SELECT last_seen_at FROM user_sessions WHERE session_id=$1`, claims.SessionID()).Scan(&activityAfterRefresh); err != nil {
		t.Fatal(err)
	}
	if activityAfterRefresh.Before(activityBeforeRefresh) {
		t.Fatalf("refresh moved activity backwards: before=%s after=%s", activityBeforeRefresh, activityAfterRefresh)
	}
}

func TestBrowserSessionsSecurityRefreshPreservesScopedAuthorization(t *testing.T) {
	_, server, pool, signer, userID, otherUserID, orgID := newSysConfigTestServer(t)
	clusterID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,$3)`, clusterID, orgID, clusterID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id=$1`, clusterID) })
	if _, err := pool.Exec(context.Background(), `UPDATE role_assignments SET scope_cluster_id=$2,scope_namespace='blue' WHERE user_id=$1`, userID, clusterID); err != nil {
		t.Fatal(err)
	}
	cookies := browserLogin(t, server, browserCredentials(t, pool, userID))
	claims, err := signer.Verify(sessionCookie(t, cookies, auth.AccessCookie).Value)
	if err != nil {
		t.Fatal(err)
	}
	wrongOwner, _, err := signer.IssueTracked(time.Minute, claims.SessionID(), otherUserID, orgID, "wrong-owner@test", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	response, body := browserRequest(t, server, http.MethodGet, "/api/v1/auth/me", cookies, nil, map[string]string{"Authorization": "Bearer " + wrongOwner})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tracked session accepted another user's session ID: %d %v", response.StatusCode, body)
	}
	for attempt := 0; attempt < 2; attempt++ {
		response, body = browserRequest(t, server, http.MethodGet, "/api/v1/system/config", cookies, nil, nil)
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("scoped GlobalAdmin widened to organization access: %d %v", response.StatusCode, body)
		}
		response, body = browserRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", cookies, nil, nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("scoped user refresh failed: %d %v", response.StatusCode, body)
		}
		cookies = response.Cookies()
	}
}

func TestBrowserSessionsSecurityRoleBindingTenantSubjectsAndScopes(t *testing.T) {
	_, server, pool, signer, adminID, localUser, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	ctx := context.Background()
	foreignOrg := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Binding scope security')`, foreignOrg, foreignOrg.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, foreignOrg) })
	localSA, foreignSA := uuid.New(), uuid.New()
	localCluster, foreignCluster := uuid.New(), uuid.New()
	localProject, foreignProject := uuid.New(), uuid.New()
	for _, fixture := range []struct {
		query string
		id    uuid.UUID
		org   uuid.UUID
	}{
		{`INSERT INTO service_accounts(id,org_id,name) VALUES($1,$2,$3)`, localSA, orgID},
		{`INSERT INTO service_accounts(id,org_id,name) VALUES($1,$2,$3)`, foreignSA, foreignOrg},
		{`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,$3)`, localCluster, orgID},
		{`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,$3)`, foreignCluster, foreignOrg},
		{`INSERT INTO projects(id,org_id,name) VALUES($1,$2,$3)`, localProject, orgID},
		{`INSERT INTO projects(id,org_id,name) VALUES($1,$2,$3)`, foreignProject, foreignOrg},
	} {
		if _, err := pool.Exec(ctx, fixture.query, fixture.id, fixture.org, fixture.id.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, testcase := range []struct {
		name        string
		subjectType string
		subjectID   string
		scopes      []any
		want        int
	}{
		{"foreign service account", "service_account", foreignSA.String(), nil, http.StatusNotFound},
		{"missing user", "user", uuid.NewString(), nil, http.StatusNotFound},
		{"invalid user", "user", "not-a-uuid", nil, http.StatusBadRequest},
		{"unsupported group", "group", foreignSA.String(), nil, http.StatusBadRequest},
		{"unknown subject type", "other", localUser.String(), nil, http.StatusBadRequest},
		{"foreign cluster", "user", localUser.String(), []any{map[string]any{"kind": "cluster", "values": []string{foreignCluster.String()}}}, http.StatusNotFound},
		{"foreign project", "user", localUser.String(), []any{map[string]any{"kind": "project", "values": []string{foreignProject.String()}}}, http.StatusNotFound},
		{"foreign explicit org", "user", localUser.String(), []any{map[string]any{"kind": "org", "values": []string{foreignOrg.String()}}}, http.StatusNotFound},
		{"foreign scope hidden by org", "user", localUser.String(), []any{map[string]any{"kind": "org"}, map[string]any{"kind": "cluster", "values": []string{foreignCluster.String()}}}, http.StatusNotFound},
		{"local service account", "service_account", localSA.String(), nil, http.StatusCreated},
		{"local cluster", "user", localUser.String(), []any{map[string]any{"kind": "cluster", "values": []string{localCluster.String()}}}, http.StatusCreated},
		{"local project", "user", localUser.String(), []any{map[string]any{"kind": "project", "values": []string{localProject.String()}}}, http.StatusCreated},
		{"normalized local user", " USER ", " " + localUser.String() + " ", nil, http.StatusCreated},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			var beforeEpoch int64
			if err := pool.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id=$1`, localUser).Scan(&beforeEpoch); err != nil {
				t.Fatal(err)
			}
			status, body := doJSON(t, http.MethodPost, server.URL+"/api/v1/access-control/role-bindings", admin, map[string]any{
				"subject_type": testcase.subjectType, "subject_id": testcase.subjectID, "role_id": "SecurityAdmin", "scopes": testcase.scopes,
			})
			if status != testcase.want {
				t.Fatalf("status=%d body=%v, want %d", status, body, testcase.want)
			}
			if status == http.StatusCreated {
				bindingID, ok := body["id"].(string)
				if !ok {
					t.Fatal("missing binding ID")
				}
				status, body = doJSON(t, http.MethodDelete, server.URL+"/api/v1/access-control/role-bindings/"+bindingID, admin, nil)
				if status != http.StatusOK {
					t.Fatalf("local binding deletion failed: %d %v", status, body)
				}
			} else {
				var afterEpoch int64
				if err := pool.QueryRow(ctx, `SELECT session_epoch FROM users WHERE id=$1`, localUser).Scan(&afterEpoch); err != nil || afterEpoch != beforeEpoch {
					t.Fatalf("rejected binding changed epoch: before=%d after=%d err=%v", beforeEpoch, afterEpoch, err)
				}
			}
			var bindings int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_bindings WHERE org_id=$1`, orgID).Scan(&bindings); err != nil || bindings != 0 {
				t.Fatalf("binding leaked after rejection/deletion: count=%d err=%v", bindings, err)
			}
		})
	}
}
