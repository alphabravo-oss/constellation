package scanning

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestScanAttestations_RejectForeignTargetLinksAndHideMalformedRows(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := context.Background()
	pool := database.Pool()
	orgID, foreignOrgID, userID := uuid.New(), uuid.New(), uuid.New()
	ownedTargetID, foreignTargetID := uuid.New(), uuid.New()
	evidenceID, imageResultID := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{orgID, foreignOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, id, "attestation-scope-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgID, foreignOrgID)
	}()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Attestation Scope')`, userID, orgID, "attestation-scope-"+userID.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	imageDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	imageRef := "registry.example.test/attested@" + imageDigest
	if _, err := pool.Exec(ctx, `INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref, image_digest)
VALUES ($1, $2, 'image', $3, 'manual', $3, $4), ($5, $6, 'image', $7, 'manual', $7, $4)`,
		ownedTargetID, orgID, imageRef, imageDigest, foreignTargetID, foreignOrgID, "registry.example.test/foreign@"+imageDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_evidence
(id, org_id, scan_target_id, target_type, target_ref, source_type, evidence_type, inventory_hash, payload, observed_at)
VALUES ($1, $2, $3, 'image', $4, 'manual', 'package-inventory', $5, '{}'::jsonb, NOW())`,
		evidenceID, orgID, foreignTargetID, imageRef, "foreign-link-"+evidenceID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO image_scan_results
(id, org_id, scan_target_id, image_ref, image_ref_normalized, image_repository, image_digest)
VALUES ($1, $2, $3, $4, $4, $5, $6)`,
		imageResultID, orgID, foreignTargetID, imageRef, "registry.example.test/attested", imageDigest); err != nil {
		t.Fatal(err)
	}

	requestBody := map[string]any{
		"scan_target_id": ownedTargetID,
		"subject_kind":   "image",
		"subject_ref":    imageRef,
		"subject_digest": imageDigest,
		"predicate_type": "https://slsa.dev/provenance/v1",
		"payload": map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"predicateType": "https://slsa.dev/provenance/v1",
			"subject": []map[string]any{{
				"name":   imageRef,
				"digest": map[string]any{"sha256": imageDigest[len("sha256:"):]},
			}},
			"predicate": map[string]any{},
		},
	}
	handler := NewScanAttestations(database)
	request := func(method, path, routeID string, body any, endpoint http.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		if routeID != "" {
			route := chi.NewRouteContext()
			route.URLParams.Add("id", routeID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		}
		rec := httptest.NewRecorder()
		endpoint(rec, req)
		return rec
	}
	for name, link := range map[string]uuid.UUID{"scan_evidence_id": evidenceID, "image_scan_result_id": imageResultID} {
		body := cloneMap(requestBody)
		body[name] = link
		rec := request(http.MethodPost, "/api/v1/repository-scan-attestations:report", "", body, handler.Report)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
			t.Fatalf("%s report: status=%d body=%s", name, rec.Code, rec.Body.String())
		}
	}
	imageOnly := cloneMap(requestBody)
	delete(imageOnly, "scan_target_id")
	imageOnly["image_scan_result_id"] = imageResultID
	if rec := request(http.MethodPost, "/api/v1/repository-scan-attestations:report", "", imageOnly, handler.Report); rec.Code != http.StatusNotFound {
		t.Fatalf("image-derived target report: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_result_attestations WHERE org_id = $1`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid report wrote attestation: count=%d err=%v", count, err)
	}

	valid := reportAttestation(t, database, userID, orgID, requestBody)
	for name, link := range map[string]uuid.UUID{"scan_evidence_id": evidenceID, "image_scan_result_id": imageResultID} {
		body := cloneMap(requestBody)
		body[name] = link
		rec := request(http.MethodPost, "/api/v1/repository-scan-attestations:report", "", body, handler.Report)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
			t.Fatalf("%s upsert: status=%d body=%s", name, rec.Code, rec.Body.String())
		}
	}
	var storedTarget uuid.UUID
	var storedEvidence, storedImage *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT scan_target_id, scan_evidence_id, image_scan_result_id FROM scan_result_attestations WHERE id = $1`, valid.ID).Scan(&storedTarget, &storedEvidence, &storedImage); err != nil || storedTarget != ownedTargetID || storedEvidence != nil || storedImage != nil {
		t.Fatalf("invalid upsert changed attestation: target=%s evidence=%v image=%v err=%v", storedTarget, storedEvidence, storedImage, err)
	}
	policyID := createTrustPolicy(t, database, userID, orgID, map[string]any{
		"name": "Attestation scope policy", "auto_verify": true,
		"subject_kind": "image", "predicate_types": []string{"https://slsa.dev/provenance/v1"},
		"allowed_identities": []string{"repo:acme/attested:ref:refs/heads/main"},
		"allowed_issuers":    []string{"https://token.actions.githubusercontent.com"},
	})
	policy, err := handler.getTrustPolicy(ctx, orgID, policyID)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		column string
		id     uuid.UUID
	}{
		{"evidence", "scan_evidence_id", evidenceID},
		{"image result", "image_scan_result_id", imageResultID},
		{"target", "scan_target_id", foreignTargetID},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, `UPDATE scan_result_attestations SET scan_target_id = $1, scan_evidence_id = NULL, image_scan_result_id = NULL WHERE id = $2`, ownedTargetID, valid.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `UPDATE scan_result_attestations SET `+test.column+` = $1 WHERE id = $2`, test.id, valid.ID); err != nil {
				t.Fatal(err)
			}
			for name, endpoint := range map[string]http.HandlerFunc{
				"get": handler.Get, "export": handler.Export, "verifications": handler.ListVerifications,
			} {
				rec := request(http.MethodGet, "/api/v1/repository-scan-attestations/"+valid.ID.String()+"/"+name, valid.ID.String(), nil, endpoint)
				if rec.Code != http.StatusNotFound {
					t.Errorf("%s: status=%d body=%s", name, rec.Code, rec.Body.String())
				}
			}
			verify := request(http.MethodPost, "/api/v1/repository-scan-attestations/"+valid.ID.String()+":verify", valid.ID.String(), nil, handler.Verify)
			if verify.Code != http.StatusNotFound {
				t.Errorf("verify: status=%d body=%s", verify.Code, verify.Body.String())
			}
			staleVerifier := NewScanAttestationsWithVerifier(database, &fakeScanAttestationVerifier{})
			if _, _, _, _, err := staleVerifier.verifyAttestationWithPolicy(ctx, orgID, &userID, false, valid, policy); err == nil {
				t.Error("stale attestation verification wrote through invalid links")
			}
			list := request(http.MethodGet, "/api/v1/repository-scans/"+ownedTargetID.String()+"/attestations", ownedTargetID.String(), nil, handler.ListForRepositoryScan)
			var listed struct {
				Attestations []scanAttestationDTO `json:"attestations"`
			}
			if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &listed) != nil || len(listed.Attestations) != 0 {
				t.Errorf("list: status=%d body=%s", list.Code, list.Body.String())
			}
			if test.column == "image_scan_result_id" {
				list = request(http.MethodGet, "/api/v1/image-scan-results/"+imageResultID.String()+"/attestations", imageResultID.String(), nil, handler.ListForImageScanResult)
				if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &listed) != nil || len(listed.Attestations) != 0 {
					t.Errorf("image list: status=%d body=%s", list.Code, list.Body.String())
				}
			}
			pending := request(http.MethodPost, "/api/v1/repository-scan-attestation-trust-policies/"+policyID.String()+":verify-pending", policyID.String(), nil, handler.VerifyPendingForPolicy)
			var pendingResult struct {
				Verified int `json:"verified"`
			}
			if pending.Code != http.StatusOK || json.Unmarshal(pending.Body.Bytes(), &pendingResult) != nil || pendingResult.Verified != 0 {
				t.Errorf("verify pending: status=%d body=%s", pending.Code, pending.Body.String())
			}
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_attestation_verifications WHERE org_id = $1`, orgID).Scan(&count); err != nil || count != 0 {
				t.Errorf("malformed row verified: count=%d err=%v", count, err)
			}
		})
	}
}
