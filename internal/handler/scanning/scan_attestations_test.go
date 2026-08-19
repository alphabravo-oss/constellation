package scanning

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/sigverify"
)

func TestScanAttestationsReportLinksRepositoryScan(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"scan_targets", "scan_evidence", "scan_result_attestations", "scan_attestation_trust_policies", "scan_attestation_verifications", "audit_events"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scan Attestation Test')`, orgID, "attestation-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Attestation Reporter')`, userID, orgID, "attestation-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	repoRef := "github.com/acme/attested"
	commitSHA := "abcdef1234567890abcdef1234567890abcdef12"
	repoBody, _ := json.Marshal(handler.RepositoryPackagesPayload{
		RepositoryRef: repoRef,
		RepositoryURL: "https://github.com/acme/attested",
		SourceType:    "repository",
		CommitSHA:     commitSHA,
		Branch:        "main",
		Workflow:      "release",
		RunID:         "98765",
		PackageSource: "syft",
		Packages: []scanner.Package{{
			Ecosystem: "npm",
			Name:      "left-pad",
			Version:   "1.3.0",
			Purl:      "pkg:npm/left-pad@1.3.0",
		}},
	})
	repoReq := httptest.NewRequest(http.MethodPost, "/api/v1/repository-packages:report", bytes.NewReader(repoBody))
	repoReq = repoReq.WithContext(authctx.WithSubject(repoReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	repoRec := httptest.NewRecorder()
	handler.NewRepositoryPackages(d).Report(repoRec, repoReq)
	if repoRec.Code != http.StatusOK {
		t.Fatalf("repository report status: %d body: %s", repoRec.Code, repoRec.Body.String())
	}
	var repoReport struct {
		ScanTargetID   uuid.UUID `json:"scan_target_id"`
		ScanEvidenceID uuid.UUID `json:"scan_evidence_id"`
		ScanJobID      uuid.UUID `json:"scan_job_id"`
	}
	if err := json.NewDecoder(repoRec.Body).Decode(&repoReport); err != nil {
		t.Fatal(err)
	}
	if repoReport.ScanTargetID == uuid.Nil || repoReport.ScanEvidenceID == uuid.Nil || repoReport.ScanJobID == uuid.Nil {
		t.Fatalf("repository report = %+v", repoReport)
	}

	imageDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imageRef := "ghcr.io/acme/attested@" + imageDigest
	payload := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{{
			"name":   imageRef,
			"digest": map[string]any{"sha256": imageDigest[len("sha256:"):len(imageDigest)]},
		}},
		"predicate": map[string]any{"buildType": "github-actions", "invocation": map[string]any{"configSource": repoRef}},
	}
	reportBody := map[string]any{
		"scan_target_id":      repoReport.ScanTargetID,
		"scan_evidence_id":    repoReport.ScanEvidenceID,
		"scan_job_id":         repoReport.ScanJobID,
		"subject_kind":        "image",
		"subject_ref":         imageRef,
		"subject_digest":      imageDigest,
		"repository_ref":      repoRef,
		"repository_url":      "https://github.com/acme/attested",
		"commit_sha":          commitSHA,
		"branch":              "main",
		"workflow":            "release",
		"run_id":              "98765",
		"ci_provider":         "github-actions",
		"predicate_type":      "https://slsa.dev/provenance/v1",
		"format":              "in-toto-statement-v1",
		"payload":             payload,
		"envelope":            map[string]any{"payloadType": "application/vnd.in-toto+json"},
		"signature":           map[string]any{"scheme": "dsse"},
		"signer_identity":     "repo:acme/attested:ref:refs/heads/main",
		"signer_issuer":       "https://token.actions.githubusercontent.com",
		"observed_at":         time.Now().UTC().Format(time.RFC3339),
		"verification_status": "unverified",
	}
	first := reportAttestation(t, d, userID, orgID, reportBody)
	if first.ID == uuid.Nil ||
		first.ScanTargetID != repoReport.ScanTargetID ||
		first.ScanEvidenceID == nil || *first.ScanEvidenceID != repoReport.ScanEvidenceID ||
		first.ScanJobID == nil || *first.ScanJobID != repoReport.ScanJobID ||
		first.TargetType != "repository" ||
		first.SourceType != "repository" ||
		first.SubjectDigest != imageDigest ||
		first.PredicateType != "https://slsa.dev/provenance/v1" ||
		first.PayloadSHA256 == "" ||
		first.VerificationStatus != "unverified" ||
		first.Trusted {
		t.Fatalf("attestation = %+v", first)
	}
	if len(first.Payload) == 0 || len(first.Envelope) == 0 || len(first.Signature) == 0 {
		t.Fatalf("expected full attestation payloads: %+v", first)
	}

	policyID := createTrustPolicy(t, d, userID, orgID, map[string]any{
		"name":                    "GitHub release provenance",
		"description":             "Trust release attestations from the repository workflow",
		"source_types":            []string{"repository"},
		"repository_ref_patterns": []string{"github.com/acme/*"},
		"predicate_types":         []string{"https://slsa.dev/provenance/v1"},
		"allowed_identities":      []string{"repo:acme/attested:ref:refs/heads/main"},
		"allowed_issuers":         []string{"https://token.actions.githubusercontent.com"},
	})
	verifyBody, _ := json.Marshal(map[string]any{"policy_id": policyID})
	fakeVerifier := &fakeScanAttestationVerifier{result: &sigverify.AttestationResult{
		SubjectRef:    first.SubjectRef,
		PredicateType: first.PredicateType,
		PayloadSHA256: first.PayloadSHA256,
		Trusted:       true,
		Identity:      "repo:acme/attested:ref:refs/heads/main",
		Issuer:        "https://token.actions.githubusercontent.com",
		Reason:        "attestation trusted",
		Payload:       first.Payload,
	}}
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/repository-scan-attestations/"+first.ID.String()+":verify", bytes.NewReader(verifyBody))
	verifyReq = verifyReq.WithContext(authctx.WithSubject(verifyReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	verifyCtx := chi.NewRouteContext()
	verifyCtx.URLParams.Add("id", first.ID.String())
	verifyReq = verifyReq.WithContext(context.WithValue(verifyReq.Context(), chi.RouteCtxKey, verifyCtx))
	verifyRec := httptest.NewRecorder()
	NewScanAttestationsWithVerifierAndAudit(d, fakeVerifier, audit.New(pool)).Verify(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify attestation status: %d body: %s", verifyRec.Code, verifyRec.Body.String())
	}
	if fakeVerifier.subjectRef != first.SubjectRef ||
		len(fakeVerifier.policy.Identities) != 1 || fakeVerifier.policy.Identities[0] != "repo:acme/attested:ref:refs/heads/main" ||
		len(fakeVerifier.policy.RequireAttestations) != 1 || fakeVerifier.policy.RequireAttestations[0] != "https://slsa.dev/provenance/v1" {
		t.Fatalf("fake verifier saw subject=%q policy=%+v", fakeVerifier.subjectRef, fakeVerifier.policy)
	}
	var verified struct {
		OK          bool               `json:"ok"`
		Attestation scanAttestationDTO `json:"attestation"`
	}
	if err := json.NewDecoder(verifyRec.Body).Decode(&verified); err != nil {
		t.Fatal(err)
	}
	if !verified.OK ||
		verified.Attestation.VerificationStatus != "trusted" ||
		!verified.Attestation.Trusted ||
		verified.Attestation.SignerIdentity != "repo:acme/attested:ref:refs/heads/main" {
		t.Fatalf("verified response = %+v", verified)
	}
	if verified.Attestation.TrustPolicyID == nil || *verified.Attestation.TrustPolicyID != policyID || verified.Attestation.VerificationReason == "" {
		t.Fatalf("verified policy linkage = %+v", verified.Attestation)
	}

	historyReq := httptest.NewRequest(http.MethodGet, "/api/v1/repository-scan-attestations/"+first.ID.String()+"/verifications", nil)
	historyReq = historyReq.WithContext(authctx.WithSubject(historyReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	historyCtx := chi.NewRouteContext()
	historyCtx.URLParams.Add("id", first.ID.String())
	historyReq = historyReq.WithContext(context.WithValue(historyReq.Context(), chi.RouteCtxKey, historyCtx))
	historyRec := httptest.NewRecorder()
	NewScanAttestations(d).ListVerifications(historyRec, historyReq)
	if historyRec.Code != http.StatusOK {
		t.Fatalf("verification history status: %d body: %s", historyRec.Code, historyRec.Body.String())
	}
	var history struct {
		Verifications []scanAttestationVerificationDTO `json:"verifications"`
	}
	if err := json.NewDecoder(historyRec.Body).Decode(&history); err != nil {
		t.Fatal(err)
	}
	if len(history.Verifications) != 1 {
		t.Fatalf("verification history = %+v", history.Verifications)
	}
	verification := history.Verifications[0]
	if verification.ID == uuid.Nil ||
		verification.AttestationID != first.ID ||
		verification.TrustPolicyID == nil || *verification.TrustPolicyID != policyID ||
		verification.Status != "trusted" ||
		!verification.Trusted ||
		verification.VerifiedBy == nil || *verification.VerifiedBy != userID ||
		verification.AutoVerified ||
		verification.PayloadSHA256 != first.PayloadSHA256 ||
		verification.RequireRekor ||
		len(verification.PolicySnapshot) == 0 ||
		len(verification.VerifierMetadata) == 0 {
		t.Fatalf("verification row = %+v", verification)
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/api/v1/repository-scan-attestations/"+first.ID.String()+"/export", nil)
	exportReq = exportReq.WithContext(authctx.WithSubject(exportReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	exportCtx := chi.NewRouteContext()
	exportCtx.URLParams.Add("id", first.ID.String())
	exportReq = exportReq.WithContext(context.WithValue(exportReq.Context(), chi.RouteCtxKey, exportCtx))
	exportRec := httptest.NewRecorder()
	NewScanAttestations(d).Export(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("verification export status: %d body: %s", exportRec.Code, exportRec.Body.String())
	}
	if got := exportRec.Header().Get("Content-Disposition"); !strings.Contains(got, first.ID.String()) {
		t.Fatalf("export content disposition = %q", got)
	}
	var exported struct {
		Kind          string                           `json:"kind"`
		Attestation   scanAttestationDTO               `json:"attestation"`
		Verifications []scanAttestationVerificationDTO `json:"verifications"`
	}
	if err := json.NewDecoder(exportRec.Body).Decode(&exported); err != nil {
		t.Fatal(err)
	}
	if exported.Kind != "constellation-repository-attestation-export-v1" ||
		exported.Attestation.ID != first.ID ||
		len(exported.Attestation.Payload) == 0 ||
		len(exported.Attestation.Envelope) == 0 ||
		len(exported.Attestation.Signature) == 0 ||
		len(exported.Verifications) != 1 ||
		exported.Verifications[0].ID != verification.ID {
		t.Fatalf("exported attestation = %+v", exported)
	}

	var auditEvents int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*) FROM audit_events
 WHERE org_id = $1
   AND action IN ('attestation_trust_policy.create', 'attestation.verify')`, orgID).Scan(&auditEvents); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if auditEvents != 2 {
		t.Fatalf("audit events = %d want 2", auditEvents)
	}

	second := reportAttestation(t, d, userID, orgID, reportBody)
	if second.ID != first.ID || second.PayloadSHA256 != first.PayloadSHA256 || !second.Trusted || second.VerificationStatus != "trusted" {
		t.Fatalf("duplicate attestation = %+v want id/hash %s/%s trusted", second, first.ID, first.PayloadSHA256)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/repository-scan-attestations/"+first.ID.String(), nil)
	getReq = getReq.WithContext(authctx.WithSubject(getReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	getCtx := chi.NewRouteContext()
	getCtx.URLParams.Add("id", first.ID.String())
	getReq = getReq.WithContext(context.WithValue(getReq.Context(), chi.RouteCtxKey, getCtx))
	getRec := httptest.NewRecorder()
	NewScanAttestations(d).Get(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get attestation status: %d body: %s", getRec.Code, getRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/repository-scans/"+repoReport.ScanTargetID.String()+"/attestations", nil)
	listReq = listReq.WithContext(authctx.WithSubject(listReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	listCtx := chi.NewRouteContext()
	listCtx.URLParams.Add("id", repoReport.ScanTargetID.String())
	listReq = listReq.WithContext(context.WithValue(listReq.Context(), chi.RouteCtxKey, listCtx))
	listRec := httptest.NewRecorder()
	NewScanAttestations(d).ListForRepositoryScan(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list attestation status: %d body: %s", listRec.Code, listRec.Body.String())
	}
	var listed struct {
		Attestations []scanAttestationDTO `json:"attestations"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Attestations) != 1 || listed.Attestations[0].ID != first.ID || len(listed.Attestations[0].Payload) != 0 {
		t.Fatalf("listed attestations = %+v", listed.Attestations)
	}

	inventoryReq := httptest.NewRequest(http.MethodGet, "/api/v1/repository-scans/"+repoReport.ScanTargetID.String(), nil)
	inventoryReq = inventoryReq.WithContext(authctx.WithSubject(inventoryReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	inventoryCtx := chi.NewRouteContext()
	inventoryCtx.URLParams.Add("id", repoReport.ScanTargetID.String())
	inventoryReq = inventoryReq.WithContext(context.WithValue(inventoryReq.Context(), chi.RouteCtxKey, inventoryCtx))
	inventoryRec := httptest.NewRecorder()
	handler.NewRepositoryInventory(d).Get(inventoryRec, inventoryReq)
	if inventoryRec.Code != http.StatusOK {
		t.Fatalf("repository inventory status: %d body: %s", inventoryRec.Code, inventoryRec.Body.String())
	}
	var inventory struct {
		RepositoryScan handler.RepositoryScanDTO `json:"repository_scan"`
	}
	if err := json.NewDecoder(inventoryRec.Body).Decode(&inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.RepositoryScan.LatestAttestation == nil ||
		inventory.RepositoryScan.LatestAttestation.ID != first.ID ||
		inventory.RepositoryScan.LatestAttestation.PayloadSHA256 != first.PayloadSHA256 ||
		!inventory.RepositoryScan.LatestAttestation.Trusted ||
		inventory.RepositoryScan.LatestAttestation.VerificationStatus != "trusted" {
		t.Fatalf("repository latest attestation = %+v", inventory.RepositoryScan.LatestAttestation)
	}

	trustedBody := cloneMap(reportBody)
	trustedBody["trusted"] = true
	trustedBody["verification_status"] = "trusted"
	raw, _ := json.Marshal(trustedBody)
	trustedReq := httptest.NewRequest(http.MethodPost, "/api/v1/repository-scan-attestations:report", bytes.NewReader(raw))
	trustedReq = trustedReq.WithContext(authctx.WithSubject(trustedReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	trustedRec := httptest.NewRecorder()
	NewScanAttestations(d).Report(trustedRec, trustedReq)
	if trustedRec.Code != http.StatusBadRequest || !bytes.Contains(trustedRec.Body.Bytes(), []byte("server-side verification")) {
		t.Fatalf("trusted status: %d body: %s", trustedRec.Code, trustedRec.Body.String())
	}

	autoDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	autoRef := "ghcr.io/acme/attested@" + autoDigest
	autoPayload := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{{
			"name":   autoRef,
			"digest": map[string]any{"sha256": autoDigest[len("sha256:"):len(autoDigest)]},
		}},
		"predicate": map[string]any{"buildType": "github-actions"},
	}
	autoPayloadRaw, _ := json.Marshal(autoPayload)
	autoPayloadCanonical, autoPayloadHash, err := canonicalAttestationJSON(autoPayloadRaw, true)
	if err != nil {
		t.Fatal(err)
	}
	autoBody := cloneMap(reportBody)
	autoBody["subject_ref"] = autoRef
	autoBody["subject_digest"] = autoDigest
	autoBody["payload"] = autoPayload
	autoVerifier := &fakeScanAttestationVerifier{result: &sigverify.AttestationResult{
		SubjectRef:    autoRef,
		PredicateType: "https://slsa.dev/provenance/v1",
		PayloadSHA256: autoPayloadHash,
		Trusted:       true,
		Identity:      "repo:acme/attested:ref:refs/heads/main",
		Issuer:        "https://token.actions.githubusercontent.com",
		Reason:        "attestation trusted",
		Payload:       autoPayloadCanonical,
	}}
	autoRaw, _ := json.Marshal(autoBody)
	autoReq := httptest.NewRequest(http.MethodPost, "/api/v1/repository-scan-attestations:report", bytes.NewReader(autoRaw))
	autoReq = autoReq.WithContext(authctx.WithSubject(autoReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	autoRec := httptest.NewRecorder()
	NewScanAttestationsWithVerifierAndAudit(d, autoVerifier, audit.New(pool)).Report(autoRec, autoReq)
	if autoRec.Code != http.StatusOK {
		t.Fatalf("auto attestation report status: %d body: %s", autoRec.Code, autoRec.Body.String())
	}
	var autoOut struct {
		Attestation scanAttestationDTO `json:"attestation"`
	}
	if err := json.NewDecoder(autoRec.Body).Decode(&autoOut); err != nil {
		t.Fatal(err)
	}
	if !autoOut.Attestation.Trusted || autoOut.Attestation.TrustPolicyID == nil || *autoOut.Attestation.TrustPolicyID != policyID {
		t.Fatalf("auto verified attestation = %+v", autoOut.Attestation)
	}

	autoHistoryReq := httptest.NewRequest(http.MethodGet, "/api/v1/repository-scan-attestations/"+autoOut.Attestation.ID.String()+"/verifications", nil)
	autoHistoryReq = autoHistoryReq.WithContext(authctx.WithSubject(autoHistoryReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	autoHistoryCtx := chi.NewRouteContext()
	autoHistoryCtx.URLParams.Add("id", autoOut.Attestation.ID.String())
	autoHistoryReq = autoHistoryReq.WithContext(context.WithValue(autoHistoryReq.Context(), chi.RouteCtxKey, autoHistoryCtx))
	autoHistoryRec := httptest.NewRecorder()
	NewScanAttestations(d).ListVerifications(autoHistoryRec, autoHistoryReq)
	if autoHistoryRec.Code != http.StatusOK {
		t.Fatalf("auto verification history status: %d body: %s", autoHistoryRec.Code, autoHistoryRec.Body.String())
	}
	var autoHistory struct {
		Verifications []scanAttestationVerificationDTO `json:"verifications"`
	}
	if err := json.NewDecoder(autoHistoryRec.Body).Decode(&autoHistory); err != nil {
		t.Fatal(err)
	}
	if len(autoHistory.Verifications) != 1 || !autoHistory.Verifications[0].AutoVerified || !autoHistory.Verifications[0].Trusted {
		t.Fatalf("auto verification history = %+v", autoHistory.Verifications)
	}
}

func TestScanAttestationTrustPolicyPublicKeyMode(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"scan_attestation_trust_policies", "audit_events"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}
	var verifierMode string
	if err := pool.QueryRow(ctx, `
SELECT COALESCE(
  (SELECT data_type FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'scan_attestation_trust_policies'
      AND column_name = 'verifier_mode'),
  '')`).Scan(&verifierMode); err != nil || verifierMode == "" {
		t.Skipf("skipping: attestation verifier mode migration not applied (%v)", err)
	}

	orgID := uuid.New()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scan Attestation Public Key Test')`, orgID, "attestation-key-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Attestation Key Reporter')`, userID, orgID, "attestation-key-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	publicKey := "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----"
	raw, _ := json.Marshal(map[string]any{
		"name":            "Keyed release provenance",
		"verifier_mode":   "public-key",
		"source_types":    []string{"repository"},
		"predicate_types": []string{"https://slsa.dev/provenance/v1"},
		"public_key_pem":  publicKey,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/repository-scan-attestation-trust-policies", bytes.NewReader(raw))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewScanAttestationsWithAudit(d, audit.New(pool)).CreateTrustPolicy(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("public-key trust policy create status: %d body: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Policy scanAttestationTrustPolicyDTO `json:"policy"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Policy.VerifierMode != "public-key" ||
		out.Policy.PublicKeyPEM != publicKey ||
		len(out.Policy.AllowedIdentities) != 0 ||
		len(out.Policy.AllowedIssuers) != 0 {
		t.Fatalf("public-key trust policy = %+v", out.Policy)
	}
}

func createTrustPolicy(t *testing.T, d *db.DB, userID, orgID uuid.UUID, body map[string]any) uuid.UUID {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/repository-scan-attestation-trust-policies", bytes.NewReader(raw))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewScanAttestationsWithAudit(d, audit.New(d.Pool())).CreateTrustPolicy(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("trust policy create status: %d body: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Policy scanAttestationTrustPolicyDTO `json:"policy"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Policy.ID == uuid.Nil || !out.Policy.Enabled || len(out.Policy.PredicateTypes) != 1 {
		t.Fatalf("trust policy create response = %+v", out.Policy)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/repository-scan-attestation-trust-policies", nil)
	listReq = listReq.WithContext(authctx.WithSubject(listReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	listRec := httptest.NewRecorder()
	NewScanAttestations(d).ListTrustPolicies(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("trust policy list status: %d body: %s", listRec.Code, listRec.Body.String())
	}
	var listed struct {
		Policies []scanAttestationTrustPolicyDTO `json:"policies"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Policies) == 0 {
		t.Fatalf("trust policy list = %+v", listed.Policies)
	}
	return out.Policy.ID
}

func reportAttestation(t *testing.T, d *db.DB, userID, orgID uuid.UUID, body map[string]any) scanAttestationDTO {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/repository-scan-attestations:report", bytes.NewReader(raw))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewScanAttestations(d).Report(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("attestation report status: %d body: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		OK          bool               `json:"ok"`
		Attestation scanAttestationDTO `json:"attestation"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.OK {
		t.Fatalf("attestation response = %+v", out)
	}
	return out.Attestation
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type fakeScanAttestationVerifier struct {
	result     *sigverify.AttestationResult
	err        error
	subjectRef string
	policy     sigverify.TrustPolicy
}

func (f *fakeScanAttestationVerifier) VerifyAttestation(_ context.Context, subjectRef string, policy sigverify.TrustPolicy) (*sigverify.AttestationResult, error) {
	f.subjectRef = subjectRef
	f.policy = policy
	return f.result, f.err
}
