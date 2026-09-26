package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/rbac"
	"github.com/alphabravocompany/constellation/pkg/vulnprofile"
)

func TestMigrationRemainingCanonicalFixtureLifecycle(t *testing.T) {
	fixture := newMigrationRemainingFixture(t)
	raw, err := os.ReadFile("../migration/neuvector/testdata/remaining_families.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile("../migration/neuvector/testdata/remaining_families.counts.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		SourceTotal        int            `json:"source_total"`
		Profiles           int            `json:"converted_vulnerability_profiles"`
		Registries         int            `json:"converted_registries"`
		Unsupported        int            `json:"unsupported_diagnostics"`
		UnsupportedSources int            `json:"unsupported_source_objects"`
		Omissions          int            `json:"omission_diagnostics"`
		Applied            map[string]int `json:"applied"`
		RolledBack         map[string]int `json:"rolled_back"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SourceTotal != manifest.Profiles+manifest.Registries+manifest.UnsupportedSources || manifest.Unsupported != manifest.UnsupportedSources+manifest.Omissions {
		t.Fatal("canonical source and diagnostic counts do not reconcile")
	}
	preview, response := migrationRemainingPreviewCall(t, fixture.h, Subject{OrgID: fixture.org, UserID: fixture.user}, string(raw))
	if strings.Contains(response, "SECRET_") {
		t.Fatal("canonical preview leaked secret markers")
	}
	if len(preview.VulnerabilityProfiles) != manifest.Profiles || len(preview.Registries) != manifest.Registries || len(preview.Unsupported) != manifest.Unsupported {
		t.Fatalf("preview disagrees with canonical manifest: %+v", preview.Summary)
	}
	var sourceTotal int
	if err := json.Unmarshal(preview.Summary["source_total"], &sourceTotal); err != nil || sourceTotal != manifest.SourceTotal {
		t.Fatalf("source total=%d expected=%d error=%v", sourceTotal, manifest.SourceTotal, err)
	}
	fixture.counts(0, 0)
	applied := fixture.call(fixture.h.MigrationApply, http.MethodPost, preview.ImportID, http.StatusOK)
	var counts map[string]int
	if err := json.Unmarshal(applied["applied"], &counts); err != nil {
		t.Fatal(err)
	}
	if counts["vulnerability_profiles"] != manifest.Profiles || counts["registries"] != manifest.Registries || counts["created"] != manifest.Profiles+manifest.Registries {
		t.Fatalf("applied counts=%v", counts)
	}
	for key, expected := range manifest.Applied {
		if counts[key] != expected {
			t.Fatalf("canonical applied %s=%d expected=%d", key, counts[key], expected)
		}
	}
	fixture.counts(manifest.Profiles, manifest.Registries)
	var profile vulnprofile.Profile
	var entries []byte
	if err := fixture.d.Pool().QueryRow(context.Background(), `SELECT active, entries FROM vuln_profiles WHERE org_id=$1 AND name='approved-cves'`, fixture.org).Scan(&profile.Active, &entries); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(entries, &profile.Entries); err != nil {
		t.Fatal(err)
	}
	decisions := profile.Evaluate([]vulnprofile.CVE{{ID: "CVE-2026-1234"}, {ID: "CVE-2025-9999"}, {ID: "CVE-2026-9999"}})
	if !profile.Active || decisions[0].Decision != vulnprofile.DecisionSuppressAccept || decisions[1].Decision != vulnprofile.DecisionSuppressAccept || decisions[2].Decision != vulnprofile.DecisionNone {
		t.Fatalf("stored profile is not effective or broadens suppression: %+v", decisions)
	}
	bundle := fixture.call(fixture.h.MigrationRollbackBundle, http.MethodGet, preview.ImportID, http.StatusOK)
	bundleRaw, _ := json.Marshal(bundle)
	if strings.Contains(string(bundleRaw), "SECRET_") {
		t.Fatal("canonical rollback bundle leaked secret markers")
	}
	rollback := fixture.call(fixture.h.MigrationRollback, http.MethodPost, preview.ImportID, http.StatusOK)
	var deleted int
	if err := json.Unmarshal(rollback["deleted"], &deleted); err != nil || deleted != manifest.Profiles+manifest.Registries {
		t.Fatalf("rollback deleted=%d error=%v", deleted, err)
	}
	for key, expected := range manifest.RolledBack {
		var actual int
		if err := json.Unmarshal(rollback[key], &actual); err != nil || actual != expected {
			t.Fatalf("canonical rollback %s=%d expected=%d error=%v", key, actual, expected, err)
		}
	}
	fixture.counts(0, 0)
	repeated := fixture.call(fixture.h.MigrationRollback, http.MethodPost, preview.ImportID, http.StatusOK)
	if string(repeated["already_rolled_back"]) != "true" {
		t.Fatal("rollback retry was not idempotent")
	}
	fixture.call(fixture.h.MigrationApply, http.MethodPost, preview.ImportID, http.StatusOK)
	fixture.counts(manifest.Profiles, manifest.Registries)
	fixture.call(fixture.h.MigrationRollback, http.MethodPost, preview.ImportID, http.StatusOK)
	fixture.counts(0, 0)
	for _, query := range []string{
		`SELECT COALESCE(jsonb_agg(to_jsonb(history))::text, '[]') FROM migration_imports history WHERE org_id=$1`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(event))::text, '[]') FROM audit_events event WHERE org_id=$1`,
	} {
		var persisted string
		if err := fixture.d.Pool().QueryRow(context.Background(), query, fixture.org).Scan(&persisted); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(persisted, "SECRET_") {
			t.Fatal("canonical persisted history or audit leaked secret markers")
		}
	}
}

func TestMigrationRemainingRequiresRegistryPermission(t *testing.T) {
	fixture := newMigrationRemainingFixture(t)
	preview := fixture.preview(migrationRemainingExport(t, nil))
	subject := Subject{OrgID: fixture.org, UserID: fixture.user, Assignments: []rbac.RoleAssignment{{Role: rbac.RoleSecurityAdmin, Scope: rbac.Scope{OrgID: fixture.org}}}, TokenScopes: []rbac.Verb{rbac.VerbManagePolicies}}
	request := migrationActionRequestWithSubject(http.MethodPost, "/migration/apply", preview.ImportID, subject)
	response := httptest.NewRecorder()
	fixture.h.MigrationApply(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("policy-only token imported registries: %d %s", response.Code, response.Body.String())
	}
	fixture.counts(0, 0)
	fixture.call(fixture.h.MigrationApply, http.MethodPost, preview.ImportID, http.StatusOK)
	request = migrationActionRequestWithSubject(http.MethodPost, "/migration/rollback", preview.ImportID, subject)
	response = httptest.NewRecorder()
	fixture.h.MigrationRollback(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("policy-only token rolled back registries: %d %s", response.Code, response.Body.String())
	}
	fixture.counts(2, 1)
}

func TestMigrationRemainingRollbackRefusesOperatorChanges(t *testing.T) {
	for _, family := range []string{"registry", "vulnerability_profile", "registry_usage"} {
		t.Run(family, func(t *testing.T) {
			fixture := newMigrationRemainingFixture(t)
			preview := fixture.preview(migrationRemainingExport(t, nil))
			fixture.call(fixture.h.MigrationApply, http.MethodPost, preview.ImportID, http.StatusOK)
			statement := `UPDATE registries SET scan_cadence='daily', updated_at=clock_timestamp() WHERE org_id=$1`
			if family == "vulnerability_profile" {
				statement = `UPDATE vuln_profiles SET description='operator update', updated_at=clock_timestamp() WHERE org_id=$1`
			}
			if family == "registry_usage" {
				statement = `INSERT INTO scan_targets (org_id, type, ref, source_type, registry_id) SELECT org_id, 'image', 'registry.example.com/test:latest', 'registry', id FROM registries WHERE org_id=$1`
			}
			if _, err := fixture.d.Pool().Exec(context.Background(), statement, fixture.org); err != nil {
				t.Fatal(err)
			}
			fixture.call(fixture.h.MigrationRollback, http.MethodPost, preview.ImportID, http.StatusConflict)
			fixture.counts(2, 1)
		})
	}
}

func TestMigrationRemainingDuplicateNamesAreUnsupported(t *testing.T) {
	export := `{"vulnerability_profiles":[{"name":"same","entries":[{"name":"CVE-2026-1"}]},{"name":"same","entries":[{"name":"CVE-2026-2"}]}],"registries":[{"name":"same","registry_type":"harbor","registry":"https://first.example.com"},{"name":"same","registry_type":"harbor","registry":"https://second.example.com"}]}`
	profiles, registries, unsupported, err := NewEnterprise().convertMigrationRemaining(httptest.NewRequest(http.MethodPost, "/migration/preview", nil), Subject{}.OrgID, "neuvector", []byte(export), "")
	if err != nil || len(profiles) != 0 || len(registries) != 0 || len(unsupported) != 4 {
		t.Fatalf("ambiguous duplicate names were accepted: profiles=%v registries=%v unsupported=%v error=%v", profiles, registries, unsupported, err)
	}
}
