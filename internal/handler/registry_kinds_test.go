package handler

import (
	"context"
	"testing"

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
