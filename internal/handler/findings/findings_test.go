package findings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

func TestFindings_ListReturnsLifecycleCountsForKind(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	assetID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Finding Counts Test')`, orgID, "finding-counts-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', 'ghcr.io/test/counts', 'sha256:counts', '{}'::jsonb, 'high')`, assetID, orgID); err != nil {
		t.Fatalf("asset: %v", err)
	}
	for _, lifecycle := range []string{"open", "accepted", "suppressed"} {
		if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, asset_id, kind, external_id, title, description, severity, risk_score, lifecycle)
VALUES ($1, $2, 'vulnerability', $3, $4, $4, 'high', 70, $5)`,
			orgID, assetID, "CVE-2099-"+lifecycle, lifecycle+" finding", lifecycle); err != nil {
			t.Fatalf("finding %s: %v", lifecycle, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	req := httptest.NewRequest("GET", "/api/v1/findings?kind=vulnerability&lifecycle=open", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewFindings(d, nil, nil).List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
	var got struct {
		Findings        []findingDTO   `json:"findings"`
		LifecycleCounts map[string]int `json:"lifecycle_counts"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Findings) != 1 || got.LifecycleCounts["open"] != 1 || got.LifecycleCounts["accepted"] != 1 || got.LifecycleCounts["suppressed"] != 1 {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestFindings_ExposesScannerProvenanceAndReconciliation(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	assetID := uuid.New()
	findingID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Finding Provenance Test')`, orgID, "finding-provenance-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', 'ghcr.io/test/provenance', 'sha256:provenance', '{}'::jsonb, 'high')`, assetID, orgID); err != nil {
		t.Fatalf("asset: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	engines, _ := json.Marshal([]scanner.EngineProvenance{
		{Engine: "vulndb", Confidence: 0.95, Role: scanner.EngineRoleCanonical},
		{Engine: "trivy", Confidence: 0.85, Role: scanner.EngineRoleEvidence},
	})
	detail, _ := json.Marshal(map[string]any{
		"canonical_engine": "vulndb",
		"reconciliation": []scanner.ReconciliationSignal{{
			Engine:    "trivy",
			Field:     "severity",
			Canonical: "high",
			Evidence:  "critical",
		}},
		"package": map[string]any{
			"Ecosystem": "deb",
			"Name":      "openssl",
			"Version":   "3.0.13-0ubuntu3.2",
			"Purl":      "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.2?arch=amd64",
		},
		"fixed": "3.0.13-0ubuntu3.3",
		"vulndb_bundle": scanner.BundleMetadata{
			SchemaVersion: "v2",
			BundleVersion: "fixture-20260612",
			Producer:      "constellation-vulndb",
			PayloadHash:   "sha256:fixture",
			RecordCount:   42,
		},
		"affected_range": scanner.AffectedRange{
			Source:            "ubuntu",
			NamespaceKind:     "os",
			NamespaceName:     "ubuntu",
			NamespaceVersion:  "24.04",
			VersionScheme:     "deb",
			RangeType:         "introduced_fixed",
			IntroducedVersion: "0",
			FixedVersion:      "1.2.3",
			FixState:          "fixed",
		},
		"cvss_base":   "9.8",
		"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"kev":         true,
		"epss":        0.42,
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (id, org_id, asset_id, kind, external_id, title, description,
                      severity, risk_score, lifecycle, canonical_engine, engines, detail_json)
VALUES ($1, $2, $3, 'vulnerability', 'CVE-2099-0001', 'provenance finding',
        'scanner provenance fixture', 'high', 80, 'open', 'vulndb', $4::jsonb, $5::jsonb)`,
		findingID, orgID, assetID, string(engines), string(detail)); err != nil {
		t.Fatalf("finding: %v", err)
	}

	h := NewFindings(d, nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/findings?kind=vulnerability&q=canonical_engine:vulndb%20disagreement:true%20package:openssl", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	h.List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list status: %d body: %s", w.Code, w.Body.String())
	}
	var listed struct {
		Findings []findingDTO `json:"findings"`
	}
	if err := json.NewDecoder(w.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1: %+v", len(listed.Findings), listed.Findings)
	}
	got := listed.Findings[0]
	if got.CanonicalEngine != "vulndb" || got.ReconciliationCount != 1 || got.VulnDBBundle == nil || got.AffectedRange == nil {
		t.Fatalf("list provenance = %+v", got)
	}
	if got.AffectedRange.NamespaceName != "ubuntu" || got.AffectedRange.FixedVersion != "1.2.3" {
		t.Fatalf("list affected range = %+v", got.AffectedRange)
	}
	if got.PackageName != "openssl" || got.PackageVersion != "3.0.13-0ubuntu3.2" || got.PackageEcosystem != "deb" ||
		got.PackagePURL != "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.2?arch=amd64" || got.FixedVersion != "3.0.13-0ubuntu3.3" {
		t.Fatalf("list package fields = %+v", got)
	}
	if len(got.Engines) != 2 || got.Engines[0].Engine != "vulndb" || got.Engines[1].Role != scanner.EngineRoleEvidence {
		t.Fatalf("list engines = %+v", got.Engines)
	}
	if got.CVSS != 9.8 || got.CVSSBase != 9.8 ||
		got.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" ||
		!got.KEV || got.EPSS != 0.42 {
		t.Fatalf("list vulnerability enrichment = %+v", got)
	}

	req = httptest.NewRequest("GET", "/api/v1/findings/"+findingID.String(), nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", findingID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w = httptest.NewRecorder()
	h.Get(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get status: %d body: %s", w.Code, w.Body.String())
	}
	var detailGot struct {
		CanonicalEngine  string                         `json:"canonical_engine"`
		Engines          []scanner.EngineProvenance     `json:"engines"`
		Reconciliation   []scanner.ReconciliationSignal `json:"reconciliation"`
		PackageName      string                         `json:"package_name"`
		PackageVersion   string                         `json:"package_version"`
		PackageEcosystem string                         `json:"package_ecosystem"`
		PackagePURL      string                         `json:"package_purl"`
		FixedVersion     string                         `json:"fixed_version"`
		AffectedRange    scanner.AffectedRange          `json:"affected_range"`
		VulnDBBundle     scanner.BundleMetadata         `json:"vulndb_bundle"`
		CVSS             float64                        `json:"cvss"`
		CVSSBase         float64                        `json:"cvss_base"`
		CVSSVector       string                         `json:"cvss_vector"`
		KEV              bool                           `json:"kev"`
		EPSS             float64                        `json:"epss"`
	}
	if err := json.NewDecoder(w.Body).Decode(&detailGot); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if detailGot.CanonicalEngine != "vulndb" ||
		len(detailGot.Reconciliation) != 1 ||
		detailGot.Reconciliation[0].Field != "severity" ||
		detailGot.PackageName != "openssl" ||
		detailGot.PackageVersion != "3.0.13-0ubuntu3.2" ||
		detailGot.PackageEcosystem != "deb" ||
		detailGot.PackagePURL != "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.2?arch=amd64" ||
		detailGot.FixedVersion != "3.0.13-0ubuntu3.3" ||
		detailGot.AffectedRange.FixedVersion != "1.2.3" ||
		detailGot.VulnDBBundle.BundleVersion != "fixture-20260612" ||
		detailGot.CVSS != 9.8 ||
		detailGot.CVSSBase != 9.8 ||
		detailGot.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" ||
		!detailGot.KEV ||
		detailGot.EPSS != 0.42 {
		t.Fatalf("detail provenance = %+v", detailGot)
	}
}

func TestFindings_ByCVEExposesCVSSBaseAndVector(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	assetID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Finding CVE Rollup Test')`, orgID, "finding-cve-rollup-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', 'ghcr.io/test/cve-rollup', 'sha256:cverollup', '{}'::jsonb, 'high')`, assetID, orgID); err != nil {
		t.Fatalf("asset: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	if _, err := pool.Exec(ctx, `
INSERT INTO findings (org_id, asset_id, kind, external_id, title, description, severity, risk_score, lifecycle, target_type, target_ref, detail_json)
VALUES
  ($1, $2, 'vulnerability', 'CVE-2099-9001', 'rollup high', 'fixture', 'high', 91, 'open', 'image-workload', 'registry.example/app:1', '{"package_name":"openssl","fixed":"3.0.14","cvss_base":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","kev":true}'::jsonb),
  ($1, $2, 'vulnerability', 'CVE-2099-9001', 'rollup malformed cvss', 'fixture', 'medium', 50, 'open', 'image-workload', 'registry.example/app:2', '{"package_name":"openssl","cvss_base":"not-a-score","cvss_vector":"CVSS:3.1/AV:L","kev":false}'::jsonb)`,
		orgID, assetID); err != nil {
		t.Fatalf("findings: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/findings/by-cve?lifecycle=open", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewFindings(d, nil, nil).ByCVE(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
	var got struct {
		CVEs []struct {
			CVE        string  `json:"cve"`
			CVSS       float64 `json:"cvss"`
			CVSSBase   float64 `json:"cvss_base"`
			CVSSVector string  `json:"cvss_vector"`
			KEV        bool    `json:"kev"`
		} `json:"cves"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.CVEs) != 1 {
		t.Fatalf("cves = %+v", got.CVEs)
	}
	if got.CVEs[0].CVE != "CVE-2099-9001" ||
		got.CVEs[0].CVSS != 9.8 ||
		got.CVEs[0].CVSSBase != 9.8 ||
		got.CVEs[0].CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" ||
		!got.CVEs[0].KEV {
		t.Fatalf("rollup enrichment = %+v", got.CVEs[0])
	}
}
