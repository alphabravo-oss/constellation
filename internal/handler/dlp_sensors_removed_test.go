package handler

// P0-01 (delete path): the /dlp/sensors REST CRUD, its DLPSensors handler, the
// ConstellationDLPSensor CRD (+ reconciler, store methods, RBAC, CRD manifest) and the
// dlp_sensors backup entry were all removed because the dlp_sensors table never reached
// the dataplane — no agent bundle endpoint, no sync worker, no dp consumer ever read it,
// so authored sensors enforced nothing (byte-for-byte the WS-G G1 waf/groups defect). The
// authoritative enforced DLP path is runtime_dlp_rules, seeded from the code-level
// dlp.DefaultCatalog() in rules_builtin.go and served to agents via AgentBundle. These
// tests are the DoD grep guard: they fail if anyone re-introduces the orphan surface.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDLPSensorsHandlerRemoved asserts the DLP-sensor CRUD handler type, its routes, the
// CRD type, and the operator store methods are gone from the source tree. We grep source
// rather than spin up a router/manager so the test needs no DB or Kubernetes.
func TestDLPSensorsHandlerRemoved(t *testing.T) {
	// repo root is two dirs up from internal/handler.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	// Forbidden tokens → the file(s) they must not appear in.
	type check struct {
		token string
		rel   string
	}
	checks := []check{
		{"NewDLPSensors", "internal/handler/runtime/waf_dlp.go"},
		{"type DLPSensors", "internal/handler/runtime/waf_dlp.go"},
		{`"/dlp/sensors"`, "internal/server/server.go"},
		{"dlpSensors.", "internal/server/server.go"},
		{"UpsertDLPSensor", "deploy/operator/policydb/store_matrix.go"},
		{"type ConstellationDLPSensor", "deploy/operator/api/v1alpha1/policy_matrix_types.go"},
		{"dlp_sensors", "pkg/backup/manifest.go"},
		{"dlp_sensors", "pkg/backup/configio.go"},
	}
	for _, c := range checks {
		b, err := os.ReadFile(filepath.Join(root, c.rel))
		if err != nil {
			t.Fatalf("read %s: %v", c.rel, err)
		}
		if strings.Contains(string(b), c.token) {
			t.Errorf("orphan DLP-sensor surface: %q still present in %s; the /dlp/sensors CRUD + ConstellationDLPSensor CRD were removed in P0-01 (never enforced), use runtime_dlp_rules instead", c.token, c.rel)
		}
	}
}

// TestDLPSensorCRDFilesRemoved asserts the reconciler and CRD manifest files are gone.
func TestDLPSensorCRDFilesRemoved(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"deploy/operator/controllers/dlpsensor_controller.go",
		"deploy/charts/constellation/crds/constellationdlpsensor.yaml",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			t.Errorf("orphan DLP-sensor file still present: %s (removed in P0-01)", rel)
		}
	}
}
