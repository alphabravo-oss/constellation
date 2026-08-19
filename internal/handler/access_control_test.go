package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccessControl_ListWithoutStorageReturnsRoleCatalogOnly(t *testing.T) {
	w := httptest.NewRecorder()
	NewAccessControl().List(w, httptest.NewRequest("GET", "/api/v1/access-control", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}

	var got accessControlOverviewDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Summary.GeneratedAt == "" {
		t.Fatalf("missing generated_at: %+v", got.Summary)
	}
	if got.Summary.UsersTotal != len(got.Users) ||
		got.Summary.RolesTotal != len(got.Roles) ||
		got.Summary.RoleBindingsTotal != len(got.RoleBindings) ||
		got.Summary.AuthProvidersTotal != len(got.AuthProviders) ||
		got.Summary.ServiceAccountsTotal != len(got.ServiceAccounts) ||
		got.Summary.APITokensTotal != len(got.APITokens) {
		t.Fatalf("summary totals mismatch: %+v", got.Summary)
	}
	if len(got.Users) != 0 || len(got.RoleBindings) != 0 || len(got.AuthProviders) != 0 || len(got.ServiceAccounts) != 0 || len(got.APITokens) != 0 {
		t.Fatalf("no-storage mode must not return invented tenant identity data: %+v", got)
	}
	if len(got.Roles) < 4 {
		t.Fatalf("role catalog unexpectedly sparse: %+v", got.Summary)
	}
	if len(got.PermissionMatrix) == 0 || len(got.Guardrails) == 0 {
		t.Fatalf("missing matrix or guardrails: matrix=%d guardrails=%d", len(got.PermissionMatrix), len(got.Guardrails))
	}
	if len(got.Summary.UsersByStatus) != 0 {
		t.Fatalf("unexpected user status summary: %+v", got.Summary.UsersByStatus)
	}

	activeGuardrails := 0
	for _, guardrail := range got.Guardrails {
		if guardrail.Status == "active" {
			activeGuardrails++
		}
		if guardrail.ID == "" || guardrail.Name == "" || guardrail.Severity == "" || guardrail.Description == "" || guardrail.Evidence == "" || len(guardrail.AppliesTo) == 0 {
			t.Fatalf("incomplete guardrail: %+v", guardrail)
		}
	}
	if got.Summary.ActiveGuardrailsTotal != activeGuardrails {
		t.Fatalf("active guardrail summary mismatch: %+v active=%d", got.Summary, activeGuardrails)
	}
}

func TestAccessControl_RolesAndGuardrailsAreComplete(t *testing.T) {
	catalog := accessControlOverview()

	roles := map[string]bool{}
	for _, role := range catalog.Roles {
		if role.ID == "" || role.Name == "" || role.Type == "" || len(role.Permissions) == 0 {
			t.Fatalf("incomplete role: %+v", role)
		}
		roles[role.ID] = true
	}
	for _, row := range catalog.PermissionMatrix {
		if row.Domain == "" || len(row.Permissions) == 0 || len(row.Roles) == 0 {
			t.Fatalf("incomplete permission matrix row: %+v", row)
		}
		for _, roleID := range row.Roles {
			if !roles[roleID] {
				t.Fatalf("permission matrix references unknown role %q in %+v", roleID, row)
			}
		}
	}
	for _, guardrail := range catalog.Guardrails {
		if guardrail.ID == "" || guardrail.Name == "" || guardrail.Status == "" || guardrail.Severity == "" || guardrail.Description == "" || guardrail.Evidence == "" || len(guardrail.AppliesTo) == 0 {
			t.Fatalf("incomplete guardrail: %+v", guardrail)
		}
	}
}

func TestAccessControl_OverviewMatchesListShape(t *testing.T) {
	w := httptest.NewRecorder()
	NewAccessControl().Overview(w, httptest.NewRequest("GET", "/api/v1/access-control/overview", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}

	var got struct {
		Summary          accessControlSummaryDTO            `json:"summary"`
		Users            []accessControlUserDTO             `json:"users"`
		Roles            []accessControlRoleDTO             `json:"roles"`
		RoleBindings     []accessControlRoleBindingDTO      `json:"role_bindings"`
		AuthProviders    []accessControlAuthProviderDTO     `json:"auth_providers"`
		ServiceAccounts  []accessControlServiceAccountDTO   `json:"service_accounts"`
		APITokens        []accessControlAPITokenDTO         `json:"api_tokens"`
		PermissionMatrix []accessControlPermissionMatrixDTO `json:"permission_matrix"`
		Guardrails       []accessControlGuardrailDTO        `json:"guardrails"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Summary.RolesTotal == 0 || len(got.Roles) == 0 || len(got.PermissionMatrix) == 0 || len(got.Guardrails) == 0 {
		t.Fatalf("unexpected empty overview: %+v", got)
	}
	if len(got.Users) != 0 || len(got.RoleBindings) != 0 || len(got.AuthProviders) != 0 || len(got.ServiceAccounts) != 0 || len(got.APITokens) != 0 {
		t.Fatalf("overview should not include invented tenant identity data: %+v", got)
	}
}
