package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// TestValidKinds_AcceptsNewConnectors proves REG-KINDS-34 opened the previously-unreachable
// connectors: their kinds are now in the accepted set.
func TestValidKinds_AcceptsNewConnectors(t *testing.T) {
	for _, k := range []string{"ibmcloud", "openshift", "nexus", "generic-v2"} {
		if !validKinds[k] {
			t.Errorf("validKinds[%q] = false, want true", k)
		}
	}
	if validKinds["not-a-registry"] {
		t.Errorf("validKinds accepted a bogus kind")
	}
}

func TestRegistryCreateKindValidation(t *testing.T) {
	for _, kind := range []string{
		"docker-hub", "ghcr", "ecr", "gcr", "acr", "quay", "harbor", "gitlab", "jfrog",
		"ibmcloud", "openshift", "nexus", "generic-v2",
	} {
		t.Run(kind, func(t *testing.T) {
			req := &registryCreateRequest{Name: "test", Kind: kind, Endpoint: "registry.example.com", AuthKind: "none"}
			if err := validateCreate(req); err != nil {
				t.Fatalf("advertised kind %q rejected: %v", kind, err)
			}
		})
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/registries", strings.NewReader(`{"name":"test","kind":"unknown","endpoint":"registry.example.com","auth_kind":"none"}`))
	req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: uuid.New(), UserID: uuid.New()}))
	response := httptest.NewRecorder()
	(&Registries{}).Create(response, req)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `unsupported registry kind`) {
		t.Fatalf("unsupported create status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRegistryPatchRejectsKind(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"unsupported kind with other fields", `{"kind":"unknown","name":"renamed"}`, `unsupported registry kind`},
		{"supported kind is immutable", `{"kind":"ghcr","name":"renamed"}`, `kind cannot be updated`},
		{"null kind is not ignored", `{"kind":null,"name":"renamed"}`, `kind must be a non-empty string`},
		{"empty kind is not ignored", `{"kind":"","name":"renamed"}`, `kind must be a non-empty string`},
		{"non-string kind is rejected", `{"kind":42,"name":"renamed"}`, `kind must be a non-empty string`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := uuid.New().String()
			req := httptest.NewRequest(http.MethodPatch, "/api/v1/registries/"+id, strings.NewReader(tc.body))
			route := chi.NewRouteContext()
			route.URLParams.Add("id", id)
			req = req.WithContext(WithSubject(context.WithValue(req.Context(), chi.RouteCtxKey, route), Subject{OrgID: uuid.New(), UserID: uuid.New()}))
			response := httptest.NewRecorder()
			(&Registries{}).Patch(response, req)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), tc.want) {
				t.Fatalf("patch status=%d body=%s, want %q", response.Code, response.Body.String(), tc.want)
			}
		})
	}
}

// TestBuildConnector_RoutesNewKinds proves BuildConnector constructs the right connector for
// each new kind (and errors on an unknown kind). DB-gated: BuildConnector opens the org's
// live HTTP client via syscfg, which needs a pool.
func TestBuildConnector_RoutesNewKinds(t *testing.T) {
	d := openTestDB(t)
	pool := d.Pool()
	ctx := context.Background()
	org := uuid.New()

	cases := []struct {
		kind     string
		endpoint string
		want     string
	}{
		{"ibmcloud", "us.icr.io", "ibmcloud"},
		{"openshift", "registry.apps.example.com", "openshift"},
		{"nexus", "nexus.example:8082", "nexus"},
		{"generic-v2", "registry.example:5000", "generic-v2"},
	}
	for _, tc := range cases {
		conn, err := BuildConnector(ctx, pool, org, tc.kind, tc.endpoint, "static", nil)
		if err != nil {
			t.Fatalf("BuildConnector(%q): %v", tc.kind, err)
		}
		if conn.Name() != tc.want {
			t.Errorf("BuildConnector(%q).Name() = %q, want %q", tc.kind, conn.Name(), tc.want)
		}
	}
	if _, err := BuildConnector(ctx, pool, org, "not-a-registry", "x", "static", nil); err == nil {
		t.Errorf("BuildConnector(unknown kind) = nil error, want error")
	}
}
