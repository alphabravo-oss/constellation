package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestAssets_GetIncludesImageFindingsAndSBOMs(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.image_scan_artifacts')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: image_scan_artifacts migration not applied (%v)", err)
	}
	orgID := uuid.New()
	assetID := uuid.New()
	userID := uuid.New()
	_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, orgID)
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Asset Test')`, orgID, "asset-test-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', 'ghcr.io/test/api', 'sha256:test', '{"team":"platform"}'::jsonb, 'high')`, assetID, orgID); err != nil {
		t.Fatalf("asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO images (asset_id, registry, repository, tag, digest, layers, architectures, size_bytes, signed)
VALUES ($1, 'ghcr.io', 'test/api', '1.0.0', 'sha256:test',
        '[{"digest":"sha256:l1","size":10}]'::jsonb, '["linux/amd64"]'::jsonb, 10, true)`, assetID); err != nil {
		t.Fatalf("image: %v", err)
	}
	resultID := uuid.New()
	findingID := uuid.New()
	detail, _ := json.Marshal(map[string]any{
		"package": map[string]any{"ecosystem": "apk", "name": "openssl", "version": "3.0.0"},
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
    id, org_id, asset_id, image_ref, image_ref_normalized, image_repository,
    image_tag, image_digest, platform, scanner_profile, package_count, finding_count
) VALUES ($1, $2, $3, 'ghcr.io/test/api@sha256:test', 'ghcr.io/test/api@sha256:test', 'ghcr.io/test/api',
          '1.0.0', 'sha256:test', 'linux/amd64', 'default', 10, 1)`,
		resultID, orgID, assetID); err != nil {
		t.Fatalf("image scan result: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_findings (
    id, org_id, image_scan_result_id, finding_key, external_id, title, description,
    severity, risk_score, canonical_engine, engines, package_ecosystem, package_name,
    package_version, detail_json
) VALUES ($1, $2, $3, 'fixture:CVE-TEST', 'CVE-TEST', 'test vuln', 'test vuln',
          'high', 80, 'vulndb', '[]'::jsonb, 'apk', 'openssl', '3.0.0', $4::jsonb)`,
		findingID, orgID, resultID, detail); err != nil {
		t.Fatalf("image scan finding: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_artifacts (
    org_id, image_scan_result_id, artifact_type, format, payload, sha256, package_count
) VALUES ($1, $2, 'sbom', 'spdx-2.3', '{}'::jsonb, 'sha256:sbom', 10)`, orgID, resultID); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO sbom_documents (asset_id, format, document, sha256)
VALUES ($1, 'cyclonedx-1.6', '{}'::jsonb, 'sha256:legacy-sbom')`, assetID); err != nil {
		t.Fatalf("legacy sbom: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	r := httptest.NewRequest("GET", "/api/v1/assets/"+assetID.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", assetID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	r = r.WithContext(WithSubject(r.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewAssets(d).Get(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
	var got struct {
		Asset           assetDTO           `json:"asset"`
		Image           map[string]any     `json:"image"`
		ImageScanResult imageScanResultDTO `json:"image_scan_result"`
		Findings        []map[string]any   `json:"findings"`
		SBOMs           []map[string]any   `json:"sboms"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Asset.Name != "ghcr.io/test/api" || got.Image["registry"] != "ghcr.io" {
		t.Fatalf("bad asset/image: %+v", got)
	}
	if got.ImageScanResult.ID != resultID || got.ImageScanResult.HighCount != 1 {
		t.Fatalf("bad image scan result: %+v", got.ImageScanResult)
	}
	if len(got.Findings) != 1 || len(got.SBOMs) != 2 {
		t.Fatalf("expected finding and sbom: %+v", got)
	}
	if !hasSBOMFormat(got.SBOMs, "spdx-2.3") || !hasSBOMFormat(got.SBOMs, "cyclonedx-1.6") {
		t.Fatalf("missing merged sbom formats: %+v", got.SBOMs)
	}
}

func hasSBOMFormat(sboms []map[string]any, format string) bool {
	for _, sbom := range sboms {
		if sbom["format"] == format {
			return true
		}
	}
	return false
}

func TestAssets_ListIncludesRiskAndSupplyChainRollups(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.image_scan_artifacts')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: image_scan_artifacts migration not applied (%v)", err)
	}
	orgID := uuid.New()
	assetID := uuid.New()
	userID := uuid.New()
	_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, orgID)
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Asset List Test')`, orgID, "asset-list-test-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', 'ghcr.io/test/list-api', 'sha256:list', '{"team":"platform"}'::jsonb, 'critical')`, assetID, orgID); err != nil {
		t.Fatalf("asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO images (asset_id, registry, repository, tag, digest, layers, architectures, size_bytes, signed)
VALUES ($1, 'ghcr.io', 'test/list-api', '2.0.0', 'sha256:list',
        '[]'::jsonb, '["linux/amd64"]'::jsonb, 2048, false)`, assetID); err != nil {
		t.Fatalf("image: %v", err)
	}
	resultID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
    id, org_id, asset_id, image_ref, image_ref_normalized, image_repository,
    image_tag, image_digest, platform, scanner_profile, package_count, finding_count
) VALUES ($1, $2, $3, 'ghcr.io/test/list-api@sha256:list', 'ghcr.io/test/list-api@sha256:list', 'ghcr.io/test/list-api',
          '2.0.0', 'sha256:list', 'linux/amd64', 'default', 12, 2)`,
		resultID, orgID, assetID); err != nil {
		t.Fatalf("image scan result: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_findings (
    id, org_id, image_scan_result_id, finding_key, external_id, title, description,
    severity, risk_score, engines, detail_json
) VALUES
    ($1, $2, $3, 'fixture:CVE-LIST-1', 'CVE-LIST-1', 'critical list vuln', 'critical list vuln', 'critical', 95, '[]'::jsonb, '{}'::jsonb),
    ($4, $2, $3, 'fixture:CVE-LIST-2', 'CVE-LIST-2', 'high list vuln', 'high list vuln', 'high', 80, '[]'::jsonb, '{}'::jsonb)`,
		uuid.New(), orgID, resultID, uuid.New()); err != nil {
		t.Fatalf("image scan findings: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_artifacts (
    org_id, image_scan_result_id, artifact_type, format, payload, sha256, package_count
) VALUES ($1, $2, 'sbom', 'spdx-2.3', '{}'::jsonb, 'sha256:list-sbom', 12)`, orgID, resultID); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	r := httptest.NewRequest("GET", "/api/v1/assets?limit=10", nil)
	r = r.WithContext(WithSubject(r.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewAssets(d).List(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
	var got struct {
		Assets []assetDTO `json:"assets"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Assets) != 1 {
		t.Fatalf("expected one asset, got %+v", got)
	}
	asset := got.Assets[0]
	if asset.FindingCount != 2 || asset.CriticalFindings != 1 || asset.HighFindings != 1 || asset.OpenFindings != 2 {
		t.Fatalf("bad finding rollup: %+v", asset)
	}
	if asset.SBOMCount != 1 || asset.ImageSigned == nil || *asset.ImageSigned || asset.Registry != "ghcr.io" || asset.Repository != "test/list-api" || asset.Tag != "2.0.0" {
		t.Fatalf("bad supply-chain rollup: %+v", asset)
	}
}

func TestImageAcceptances_CreateListRevokeAndAssetDetail(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	assetID := uuid.New()
	userID := uuid.New()
	imageDigest := "sha256:" + uuid.NewString()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Image Acceptance Test')`, orgID, "image-acceptance-test-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Approver')`, userID, orgID, "approver-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality)
VALUES ($1, $2, 'image', 'ghcr.io/test/accepted', $3, '{}'::jsonb, 'high')`, assetID, orgID, imageDigest); err != nil {
		t.Fatalf("asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO images (asset_id, registry, repository, tag, digest, layers, architectures, size_bytes, signed)
VALUES ($1, 'ghcr.io', 'test/accepted', '1.0.0', $2,
        '[]'::jsonb, '["linux/amd64"]'::jsonb, 10, true)`, assetID, imageDigest); err != nil {
		t.Fatalf("image: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	h := NewImageAcceptances(d, audit.New(pool))
	acceptedUntil := time.Now().UTC().Add(14 * 24 * time.Hour).Format(time.RFC3339)
	createReq := acceptanceRequest("POST", "/api/v1/assets/"+assetID.String()+"/image-acceptances", assetID, "", userID, orgID,
		`{"rationale":"Compensating controls verified","accepted_until":"`+acceptedUntil+`"}`)
	createResp := httptest.NewRecorder()
	h.Create(createResp, createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status: %d body: %s", createResp.Code, createResp.Body.String())
	}
	var created struct {
		ID               uuid.UUID            `json:"id"`
		ImageAcceptances []imageAcceptanceDTO `json:"image_acceptances"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == uuid.Nil || len(created.ImageAcceptances) != 1 || created.ImageAcceptances[0].Status != "active" {
		t.Fatalf("bad create response: %+v", created)
	}

	listReq := acceptanceRequest("GET", "/api/v1/assets/"+assetID.String()+"/image-acceptances", assetID, "", userID, orgID, "")
	listResp := httptest.NewRecorder()
	h.List(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status: %d body: %s", listResp.Code, listResp.Body.String())
	}
	var listed struct {
		ImageAcceptances []imageAcceptanceDTO `json:"image_acceptances"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.ImageAcceptances) != 1 || listed.ImageAcceptances[0].ImageDigest != imageDigest {
		t.Fatalf("bad list response: %+v", listed)
	}

	assetReq := acceptanceRequest("GET", "/api/v1/assets/"+assetID.String(), assetID, "", userID, orgID, "")
	assetResp := httptest.NewRecorder()
	NewAssets(d).Get(assetResp, assetReq)
	if assetResp.Code != http.StatusOK {
		t.Fatalf("asset status: %d body: %s", assetResp.Code, assetResp.Body.String())
	}
	var assetGot struct {
		ImageAcceptances []imageAcceptanceDTO `json:"image_acceptances"`
	}
	if err := json.NewDecoder(assetResp.Body).Decode(&assetGot); err != nil {
		t.Fatalf("decode asset: %v", err)
	}
	if len(assetGot.ImageAcceptances) != 1 || assetGot.ImageAcceptances[0].Status != "active" {
		t.Fatalf("asset missing active acceptance: %+v", assetGot)
	}

	revokeReq := acceptanceRequest("POST", "/api/v1/assets/"+assetID.String()+"/image-acceptances/"+created.ID.String()+"/revoke", assetID, created.ID.String(), userID, orgID, "")
	revokeResp := httptest.NewRecorder()
	h.Revoke(revokeResp, revokeReq)
	if revokeResp.Code != http.StatusOK {
		t.Fatalf("revoke status: %d body: %s", revokeResp.Code, revokeResp.Body.String())
	}
	var revoked struct {
		ImageAcceptances []imageAcceptanceDTO `json:"image_acceptances"`
	}
	if err := json.NewDecoder(revokeResp.Body).Decode(&revoked); err != nil {
		t.Fatalf("decode revoke: %v", err)
	}
	if len(revoked.ImageAcceptances) != 1 || revoked.ImageAcceptances[0].Status != "revoked" {
		t.Fatalf("bad revoke response: %+v", revoked)
	}

	var auditEvents int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM audit_events
 WHERE org_id = $1 AND action IN ('image.accept-risk', 'image.accept-risk.revoke')`, orgID).Scan(&auditEvents); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if auditEvents != 2 {
		t.Fatalf("expected create and revoke audit events, got %d", auditEvents)
	}
}

func acceptanceRequest(method, target string, assetID uuid.UUID, acceptanceID string, userID uuid.UUID, orgID uuid.UUID, body string) *http.Request {
	var buf *bytes.Buffer
	if body == "" {
		buf = bytes.NewBuffer(nil)
	} else {
		buf = bytes.NewBufferString(body)
	}
	r := httptest.NewRequest(method, target, buf)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", assetID.String())
	if acceptanceID != "" {
		rctx.URLParams.Add("acceptanceID", acceptanceID)
	}
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	return r.WithContext(WithSubject(r.Context(), Subject{UserID: userID, OrgID: orgID}))
}
