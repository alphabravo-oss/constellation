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
			Groups               []string `json:"groups"`
			NetworkEdge          []string `json:"network_edge"`
			VulnerabilityProfile string   `json:"vulnerability_profile"`
		} `json:"names"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	var source struct {
		Groups                []json.RawMessage `json:"groups"`
		NetworkRules          []json.RawMessage `json:"network_rules"`
		VulnerabilityProfiles []json.RawMessage `json:"vulnerability_profiles"`
	}
	if err := json.Unmarshal(export, &source); err != nil {
		t.Fatal(err)
	}
	if manifest.Source != "neuvector" || len(source.Groups) != manifest.SourceObjects["groups"] || len(source.NetworkRules) != manifest.SourceObjects["network_rules"] || len(source.VulnerabilityProfiles) != manifest.SourceObjects["vulnerability_profiles"] || len(source.Groups)+len(source.NetworkRules)+len(source.VulnerabilityProfiles) != manifest.SourceObjects["total"] {
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
	if preview.ImportID == "" || preview.TargetClusterID != clusterID.String() || preview.Summary.SourceTotal != manifest.SourceObjects["total"] || preview.Summary.Total != manifest.Converted["total"] || preview.Summary.Create != manifest.Converted["total"] || preview.Summary.Groups != manifest.Converted["groups"] || preview.Summary.NetworkRules != manifest.Converted["network_rules"] || preview.Summary.VulnerabilityProfiles != manifest.Converted["vulnerability_profiles"] || preview.Summary.Unsupported != manifest.Unsupported {
		t.Fatalf("conversion differs from manifest: summary=%+v unsupported=%+v", preview.Summary, preview.Unsupported)
	}
	if len(manifest.Names.Groups) != 2 || len(manifest.Names.NetworkEdge) != 2 {
		t.Fatal("manifest target names are incomplete")
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
	checkRows := func(wantGroups, wantEdges, wantProfiles int) {
		t.Helper()
		var groups, edges, profiles int
		if err := fixture.d.Pool().QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id=$1 AND cluster_id=$2 AND name=ANY($3)`, fixture.org, clusterID, manifest.Names.Groups).Scan(&groups); err != nil {
			t.Fatal(err)
		}
		if err := fixture.d.Pool().QueryRow(ctx, `SELECT count(*) FROM group_rule_edges WHERE org_id=$1 AND cluster_id=$2 AND from_group=$3 AND to_group=$4`, fixture.org, clusterID, manifest.Names.NetworkEdge[0], manifest.Names.NetworkEdge[1]).Scan(&edges); err != nil {
			t.Fatal(err)
		}
		if err := fixture.d.Pool().QueryRow(ctx, `SELECT count(*) FROM vuln_profiles WHERE org_id=$1 AND name=$2`, fixture.org, manifest.Names.VulnerabilityProfile).Scan(&profiles); err != nil {
			t.Fatal(err)
		}
		if groups != wantGroups || edges != wantEdges || profiles != wantProfiles {
			t.Fatalf("rows groups=%d edges=%d profiles=%d, want %d/%d/%d", groups, edges, profiles, wantGroups, wantEdges, wantProfiles)
		}
	}
	checkRows(2, 1, 1)
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
	checkRows(0, 0, 0)
}
