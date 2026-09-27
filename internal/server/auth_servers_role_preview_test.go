package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAuthServerRolePreviewProvidersScopeAndSourceRejection(t *testing.T) {
	_, ts, pool, signer, adminID, auditorID, orgID := newAuthServersTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	clusterID := uuid.New()
	foreignOrgID := uuid.New()
	foreignClusterID := uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Foreign preview org')`, foreignOrgID, "preview-foreign-"+foreignOrgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,'preview-local'),($3,$4,'preview-foreign')`, clusterID, orgID, foreignClusterID, foreignOrgID); err != nil {
		t.Fatal(err)
	}
	foreignProviderID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO auth_servers (id, org_id, type, name, enabled, config, role_mapping) VALUES ($1,$2,'oidc','foreign-preview',false,$3::jsonb,$4::jsonb)`, foreignProviderID, foreignOrgID,
		`{"issuer_url":"https://foreign.example.test","client_id":"foreign"}`, `{"rules":{"sec-team":"GlobalAdmin"}}`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = ANY($1)`, []uuid.UUID{clusterID, foreignClusterID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, foreignOrgID)
	})

	providers := []struct {
		kind, inputKind string
		config          map[string]any
	}{
		{"ldap", "ldap_group_cn", map[string]any{"url": "ldaps://ldap.example.test", "base_dn": "dc=example,dc=test", "user_filter": "(uid=%s)", "bind_password": "ldap-secret"}},
		{"saml", "saml_group_attribute", map[string]any{"idp_metadata_xml": "<secret-metadata/>", "acs_url": "https://example.test/acs", "sp_key_pem": "saml-secret"}},
		{"oidc", "oidc_groups_claim", map[string]any{"issuer_url": "https://issuer.example.test", "client_id": "preview-client", "client_secret": "oidc-secret"}},
	}
	for _, provider := range providers {
		t.Run(provider.kind, func(t *testing.T) {
			status, created := doJSON(t, http.MethodPost, ts.URL+"/api/v1/auth-servers", admin, map[string]any{
				"type": provider.kind, "name": "preview-" + provider.kind, "enabled": false,
				"config":       provider.config,
				"role_mapping": map[string]any{"rules": map[string]string{"sec-team": "SecurityAdmin"}, "default": "Auditor"},
			})
			if status != http.StatusCreated {
				t.Fatalf("create %d: %v", status, created)
			}
			id := created["id"].(string)
			path := ts.URL + "/api/v1/auth-servers/" + id + "/role-preview"
			status, result := doJSON(t, http.MethodPost, path, admin, map[string]any{"groups": []string{" SEC-TEAM ", "unmapped-private"}})
			if status != http.StatusOK || result["input_kind"] != provider.inputKind || result["matched_group_count"] != float64(1) || result["default_applied"] != false {
				t.Fatalf("preview %d: %v", status, result)
			}
			grants := result["grants"].([]any)
			if len(grants) != 1 || grants[0].(map[string]any)["role"] != "SecurityAdmin" || grants[0].(map[string]any)["scope"] != "organization" {
				t.Fatalf("mapped grants: %v", grants)
			}
			body, _ := json.Marshal(result)
			for _, secret := range []string{"SEC-TEAM", "unmapped-private", "ldap-secret", "saml-secret", "oidc-secret", "secret-metadata"} {
				if strings.Contains(strings.ToLower(string(body)), strings.ToLower(secret)) {
					t.Fatalf("preview leaked %q", secret)
				}
			}
			status, result = doJSON(t, http.MethodPost, path, admin, map[string]any{"groups": []string{"unknown"}})
			if status != http.StatusOK || result["default_applied"] != true || result["grants"].([]any)[0].(map[string]any)["role"] != "Auditor" {
				t.Fatalf("default preview %d: %v", status, result)
			}
			status, _ = doJSON(t, http.MethodPost, path, auditor, map[string]any{"groups": []string{"sec-team"}})
			if status != http.StatusForbidden {
				t.Fatalf("auditor preview status %d", status)
			}
			for _, bad := range []map[string]any{
				{"groups": []string{"sec-team"}, "id_token": "secret"},
				{"assertion": "secret"},
				{"groups": []string{""}},
				{"groups": []string{strings.Repeat("x", 257)}},
				{"groups": make([]string, 51)},
				{"groups": "sec-team"},
			} {
				status, _ = doJSON(t, http.MethodPost, path, admin, bad)
				if status != http.StatusBadRequest {
					t.Fatalf("bad source %v accepted: %d", bad, status)
				}
			}
			status, _ = doJSON(t, http.MethodPost, ts.URL+"/api/v1/auth-servers/"+foreignProviderID.String()+"/role-preview", admin, map[string]any{"groups": []string{"sec-team"}})
			if status != http.StatusNotFound {
				t.Fatalf("foreign/missing provider status %d", status)
			}
			status, _ = doJSON(t, http.MethodPost, ts.URL+"/api/v1/auth-servers/"+id+"/scoped-mappings", admin, map[string]any{
				"group": "sec-team", "role": "Analyst", "cluster_id": foreignClusterID.String(), "namespace": "prod",
			})
			if status != http.StatusBadRequest {
				t.Fatalf("foreign cluster mapping status %d", status)
			}
			status, _ = doJSON(t, http.MethodPost, ts.URL+"/api/v1/auth-servers/"+id+"/scoped-mappings", admin, map[string]any{
				"group": "sec-team", "role": "Analyst", "cluster_id": clusterID.String(), "namespace": "prod",
			})
			if status != http.StatusCreated {
				t.Fatalf("scoped mapping create status %d", status)
			}
			status, result = doJSON(t, http.MethodPost, path, admin, map[string]any{"groups": []string{"Sec-Team"}})
			if status != http.StatusOK || len(result["grants"].([]any)) != 2 {
				t.Fatalf("scoped preview %d: %v", status, result)
			}
			mappedScope := result["grants"].([]any)[1].(map[string]any)
			if mappedScope["scope"] != "namespace" || mappedScope["cluster_id"] != clusterID.String() || mappedScope["namespace"] != "prod" {
				t.Fatalf("scoped grant: %v", mappedScope)
			}
			status, _ = doJSON(t, http.MethodPost, ts.URL+"/api/v1/auth-servers/"+id+"/scoped-mappings", admin, map[string]any{
				"group": "scope-only", "role": "Analyst", "cluster_id": clusterID.String(),
			})
			if status != http.StatusCreated {
				t.Fatalf("scope-only mapping status %d", status)
			}
			status, result = doJSON(t, http.MethodPost, path, admin, map[string]any{"groups": []string{"SCOPE-ONLY"}})
			if status != http.StatusOK || result["default_applied"] != true || result["matched_group_count"] != float64(1) || len(result["grants"].([]any)) != 2 {
				t.Fatalf("scope-only preview %d: %v", status, result)
			}
			var invalidMappingID uuid.UUID
			if err := pool.QueryRow(ctx, `INSERT INTO sso_role_mappings (org_id, auth_server_id, group_value, role, scope_cluster_id, scope_namespace) VALUES ($1,$2,'sec-team','GlobalAdmin',$3,'prod') RETURNING id`, orgID, id, foreignClusterID).Scan(&invalidMappingID); err != nil {
				t.Fatal(err)
			}
			status, result = doJSON(t, http.MethodPost, path, admin, map[string]any{"groups": []string{"sec-team"}})
			if status != http.StatusConflict || result["error"] != "scoped mapping unavailable" {
				t.Fatalf("invalid stored scope preview %d: %v", status, result)
			}
			if _, err := pool.Exec(ctx, `DELETE FROM sso_role_mappings WHERE id=$1`, invalidMappingID); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, `INSERT INTO sso_role_mappings (org_id, auth_server_id, group_value, role) VALUES ($1,$2,'sec-team','GlobalAdmin') RETURNING id`, foreignOrgID, id).Scan(&invalidMappingID); err != nil {
				t.Fatal(err)
			}
			status, result = doJSON(t, http.MethodPost, path, admin, map[string]any{"groups": []string{"sec-team"}})
			if status != http.StatusConflict || result["error"] != "scoped mapping unavailable" {
				t.Fatalf("foreign scoped row preview %d: %v", status, result)
			}
			if _, err := pool.Exec(ctx, `DELETE FROM sso_role_mappings WHERE id=$1`, invalidMappingID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
