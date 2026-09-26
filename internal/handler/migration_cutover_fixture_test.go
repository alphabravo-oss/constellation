package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNeuVectorCutoverFixtureManifest(t *testing.T) {
	fixture := newMigrationRemainingFixture(t)
	ctx := context.Background()
	clusterID := uuid.New()
	if _, err := fixture.d.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, fixture.org, "cutover-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	export, err := os.ReadFile("../../scripts/fixtures/neuvector-cutover-export.json")
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile("../../scripts/fixtures/neuvector-cutover-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Source        string         `json:"source"`
		SourceObjects map[string]int `json:"source_objects"`
		Converted     map[string]int `json:"converted"`
		Unsupported   int            `json:"unsupported"`
		Applied       map[string]int `json:"applied"`
		RolledBack    map[string]int `json:"rolled_back"`
		Names         struct {
			Groups               []string          `json:"groups"`
			NetworkEdge          []string          `json:"network_edge"`
			VulnerabilityProfile string            `json:"vulnerability_profile"`
			DPIRules             map[string]string `json:"dpi_rules"`
			DPIBindings          map[string]string `json:"dpi_bindings"`
		} `json:"names"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	var source struct {
		Groups                []json.RawMessage `json:"groups"`
		NetworkRules          []json.RawMessage `json:"network_rules"`
		VulnerabilityProfiles []json.RawMessage `json:"vulnerability_profiles"`
		DLPSensors            []struct {
			Rules []json.RawMessage `json:"rules"`
		} `json:"dlp_sensors"`
		WAFSensors []struct {
			Rules []json.RawMessage `json:"rules"`
		} `json:"waf_sensors"`
		DLPGroups []json.RawMessage `json:"dlp_groups"`
		WAFGroups []json.RawMessage `json:"waf_groups"`
	}
	if err := json.Unmarshal(export, &source); err != nil {
		t.Fatal(err)
	}
	dpiRules := 0
	for _, sensor := range append(source.DLPSensors, source.WAFSensors...) {
		dpiRules += len(sensor.Rules)
	}
	dpiBindings := len(source.DLPGroups) + len(source.WAFGroups)
	if manifest.Source != "neuvector" || len(source.Groups) != manifest.SourceObjects["groups"] || len(source.NetworkRules) != manifest.SourceObjects["network_rules"] || len(source.VulnerabilityProfiles) != manifest.SourceObjects["vulnerability_profiles"] || dpiRules != manifest.SourceObjects["dpi_rules"] || dpiBindings != manifest.SourceObjects["dpi_bindings"] || len(source.Groups)+len(source.NetworkRules)+len(source.VulnerabilityProfiles)+dpiRules+dpiBindings != manifest.SourceObjects["total"] {
		t.Fatalf("source fixture and manifest disagree: %+v", manifest.SourceObjects)
	}
	body, err := json.Marshal(map[string]string{"source": manifest.Source, "cluster_id": clusterID.String(), "export": string(export)})
	if err != nil {
		t.Fatal(err)
	}
	previewRequest := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(body)))
	previewRequest = previewRequest.WithContext(WithSubject(previewRequest.Context(), Subject{OrgID: fixture.org, UserID: fixture.user}))
	previewResponse := httptest.NewRecorder()
	fixture.h.MigrationPreview(previewResponse, previewRequest)
	if previewResponse.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", previewResponse.Code, previewResponse.Body.String())
	}
	var preview migrationPreviewDTO
	if err := json.Unmarshal(previewResponse.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.ImportID == "" || preview.TargetClusterID != clusterID.String() || preview.Summary.SourceTotal != manifest.SourceObjects["total"] || preview.Summary.Total != manifest.Converted["total"] || preview.Summary.Create != manifest.Converted["total"] || preview.Summary.Groups != manifest.Converted["groups"] || preview.Summary.NetworkRules != manifest.Converted["network_rules"] || preview.Summary.VulnerabilityProfiles != manifest.Converted["vulnerability_profiles"] || preview.Summary.DPIRules != manifest.Converted["dpi_rules"] || preview.Summary.DPIBindings != manifest.Converted["dpi_bindings"] || preview.Summary.Unsupported != manifest.Unsupported {
		t.Fatalf("conversion differs from manifest: summary=%+v unsupported=%+v", preview.Summary, preview.Unsupported)
	}
	if len(manifest.Names.Groups) != 2 || len(manifest.Names.NetworkEdge) != 2 || len(manifest.Names.DPIRules) != 2 || len(manifest.Names.DPIBindings) != 2 {
		t.Fatal("manifest target names are incomplete")
	}
	for _, expected := range []struct {
		category string
		sensor   string
		pattern  string
		context  string
		applyDir int16
		severity int16
	}{
		{category: "dlp", sensor: "cutover-pii", pattern: "CUTOVER-ACCOUNT-[0-9]{4}", applyDir: 1, severity: 5},
		{category: "waf", sensor: "cutover-waf", pattern: "(?i)/cutover-probe", context: "uri", applyDir: 2, severity: 6},
	} {
		var ruleFound, bindingFound bool
		for _, rule := range preview.DPIRules {
			if rule.Name == manifest.Names.DPIRules[expected.category] && rule.Category == expected.category && rule.DiffAction == "create" && rule.ClusterID == clusterID.String() && rule.Mode == "monitor" && rule.SourceSensor == expected.sensor && rule.ApplyDir == expected.applyDir && rule.Severity == expected.severity && len(rule.Patterns) == 1 && rule.Patterns[0].Pattern == expected.pattern && rule.Patterns[0].Op == "regex" && rule.Patterns[0].Context == expected.context {
				ruleFound = true
			}
		}
		for _, binding := range preview.DPIBindings {
			if binding.SensorKind == expected.category && binding.SourceGroup == manifest.Names.DPIBindings[expected.category] && binding.TargetGroupName == manifest.Names.DPIBindings[expected.category] && binding.DiffAction == "create" && len(binding.SourceSensors) == 1 && binding.SourceSensors[0] == expected.sensor {
				bindingFound = true
			}
		}
		if !ruleFound || !bindingFound {
			t.Fatalf("missing converted %s rule or binding: rules=%+v bindings=%+v", expected.category, preview.DPIRules, preview.DPIBindings)
		}
	}
	applyRequest := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":apply", preview.ImportID, fixture.org, fixture.user)
	applyResponse := httptest.NewRecorder()
	fixture.h.MigrationApply(applyResponse, applyRequest)
	if applyResponse.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyResponse.Code, applyResponse.Body.String())
	}
	var applied struct {
		Status  string         `json:"status"`
		Applied map[string]int `json:"applied"`
	}
	if err := json.Unmarshal(applyResponse.Body.Bytes(), &applied); err != nil {
		t.Fatal(err)
	}
	if applied.Status != "applied" {
		t.Fatalf("apply status=%s", applied.Status)
	}
	for key, expected := range manifest.Applied {
		if applied.Applied[key] != expected {
			t.Fatalf("applied %s=%d, want %d", key, applied.Applied[key], expected)
		}
	}
	checkRows := func(wantGroups, wantEdges, wantProfiles, wantDPIRules, wantDPIBindings int) {
		t.Helper()
		var groups, edges, profiles, dpiRules, dpiBindings int
		if err := fixture.d.Pool().QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id=$1 AND cluster_id=$2 AND name=ANY($3)`, fixture.org, clusterID, manifest.Names.Groups).Scan(&groups); err != nil {
			t.Fatal(err)
		}
		if err := fixture.d.Pool().QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3 AND to_group=$4`, fixture.org, clusterID, manifest.Names.NetworkEdge[0], manifest.Names.NetworkEdge[1]).Scan(&edges); err != nil {
			t.Fatal(err)
		}
		if err := fixture.d.Pool().QueryRow(ctx, `SELECT count(*) FROM vuln_profiles WHERE org_id=$1 AND name=$2`, fixture.org, manifest.Names.VulnerabilityProfile).Scan(&profiles); err != nil {
			t.Fatal(err)
		}
		if err := fixture.d.Pool().QueryRow(ctx, `SELECT count(*) FROM runtime_dlp_rules WHERE org_id=$1 AND cluster_id=$2 AND ((category='dlp' AND name=$3) OR (category='waf' AND name=$4))`, fixture.org, clusterID, manifest.Names.DPIRules["dlp"], manifest.Names.DPIRules["waf"]).Scan(&dpiRules); err != nil {
			t.Fatal(err)
		}
		if err := fixture.d.Pool().QueryRow(ctx, `SELECT count(*) FROM group_dpi_sensor_bindings b JOIN groups g ON g.id=b.group_id WHERE b.org_id=$1 AND g.cluster_id=$2 AND ((b.sensor_kind='dlp' AND g.name=$3) OR (b.sensor_kind='waf' AND g.name=$4))`, fixture.org, clusterID, manifest.Names.DPIBindings["dlp"], manifest.Names.DPIBindings["waf"]).Scan(&dpiBindings); err != nil {
			t.Fatal(err)
		}
		if groups != wantGroups || edges != wantEdges || profiles != wantProfiles || dpiRules != wantDPIRules || dpiBindings != wantDPIBindings {
			t.Fatalf("rows groups=%d edges=%d profiles=%d dpi_rules=%d dpi_bindings=%d, want %d/%d/%d/%d/%d", groups, edges, profiles, dpiRules, dpiBindings, wantGroups, wantEdges, wantProfiles, wantDPIRules, wantDPIBindings)
		}
	}
	checkRows(2, 1, 1, 2, 2)
	for _, expected := range []struct {
		category string
		pattern  string
		applyDir int16
		severity int16
	}{
		{category: "dlp", pattern: "CUTOVER-ACCOUNT-[0-9]{4}", applyDir: 1, severity: 5},
		{category: "waf", pattern: "(?i)/cutover-probe", applyDir: 2, severity: 6},
	} {
		var mode, source string
		var applyDir, severity int16
		var patterns json.RawMessage
		if err := fixture.d.Pool().QueryRow(ctx, `SELECT mode, source, patterns, apply_dir, severity FROM runtime_dlp_rules WHERE org_id=$1 AND cluster_id=$2 AND category=$3 AND name=$4`, fixture.org, clusterID, expected.category, manifest.Names.DPIRules[expected.category]).Scan(&mode, &source, &patterns, &applyDir, &severity); err != nil {
			t.Fatal(err)
		}
		var parsed []migrationDPIPatternDTO
		if err := json.Unmarshal(patterns, &parsed); err != nil {
			t.Fatal(err)
		}
		if mode != "monitor" || source != "neuvector" || applyDir != expected.applyDir || severity != expected.severity || len(parsed) != 1 || parsed[0].Pattern != expected.pattern || parsed[0].Op != "regex" {
			t.Fatalf("%s rule lost migration semantics: mode=%s source=%s apply_dir=%d severity=%d patterns=%s", expected.category, mode, source, applyDir, severity, patterns)
		}
	}
	rollbackRequest := migrationActionRequest(http.MethodPost, "/api/v1/migration/imports/"+preview.ImportID+":rollback", preview.ImportID, fixture.org, fixture.user)
	rollbackResponse := httptest.NewRecorder()
	fixture.h.MigrationRollback(rollbackResponse, rollbackRequest)
	if rollbackResponse.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackResponse.Code, rollbackResponse.Body.String())
	}
	var rolledBack struct {
		Status   string `json:"status"`
		Deleted  int    `json:"deleted"`
		Restored int    `json:"restored"`
	}
	if err := json.Unmarshal(rollbackResponse.Body.Bytes(), &rolledBack); err != nil {
		t.Fatal(err)
	}
	if rolledBack.Status != "rolled_back" || rolledBack.Deleted != manifest.RolledBack["deleted"] || rolledBack.Restored != manifest.RolledBack["restored"] {
		t.Fatalf("rollback differs from manifest: %+v", rolledBack)
	}
	checkRows(0, 0, 0, 0, 0)
}
