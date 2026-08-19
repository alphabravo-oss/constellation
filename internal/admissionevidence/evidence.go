package admissionevidence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	corev1 "k8s.io/api/core/v1"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

type Source struct {
	pool      *pgxpool.Pool
	orgID     uuid.UUID
	clusterID uuid.UUID
}

var _ admission.EvidenceSource = (*Source)(nil)
var _ admission.DetailedEvidenceSource = (*Source)(nil)

func New(pool *pgxpool.Pool, orgID uuid.UUID) *Source {
	return &Source{pool: pool, orgID: orgID}
}

type admissionEvidenceImage struct {
	Container  string
	Role       string
	Raw        string
	Digest     string
	Candidates []string
}

type admissionEvidenceHit struct {
	ImageScanResultID uuid.UUID
	ImageRef          string
	Digest            string
	SourceType        string
	SourceRef         string
	LastScannedAt     time.Time
	BundleVersion     string
	BundleHash        string
	PackageCount      int
	FindingCount      int
	FindingID         string
	FindingKey        string
	ExternalID        string
	Title             string
	Severity          string
	RiskScore         int
	CanonicalEngine   string
	PackageEcosystem  string
	PackageName       string
	PackageVersion    string
	PackagePURL       string
	FixedVersion      string
	Kind              string
	ArtifactID        uuid.UUID
	Path              string
	Status            string
	Identity          string
	ArtifactType      string
	ArtifactFormat    string
	RiskTypes         []string
	Count             int
}

type admissionEvidenceScanResult struct {
	ID                  uuid.UUID
	ImageRef            string
	Digest              string
	SourceType          string
	SourceRef           string
	LastScannedAt       time.Time
	VulnDBBundleVersion string
	VulnDBBundleHash    string
	PackageCount        int
	FindingCount        int
}

type Detail = admission.EvidenceDetail
type ImageDetail = admission.EvidenceImageDetail
type ScanResultDetail = admission.EvidenceScanResultDetail
type FindingDetail = admission.EvidenceFindingDetail
type ArtifactDetail = admission.EvidenceArtifactDetail

func NewForCluster(ctx context.Context, pool *pgxpool.Pool, clusterID uuid.UUID) (*Source, uuid.UUID, error) {
	orgID, err := lookupClusterOrgID(ctx, pool, clusterID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return &Source{pool: pool, orgID: orgID, clusterID: clusterID}, orgID, nil
}

func lookupClusterOrgID(ctx context.Context, pool *pgxpool.Pool, clusterID uuid.UUID) (uuid.UUID, error) {
	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT org_id FROM clusters WHERE id = $1`, clusterID).Scan(&orgID); err != nil {
		return uuid.Nil, fmt.Errorf("lookup org for cluster %s: %w", clusterID, err)
	}
	return orgID, nil
}

func (s *Source) EvaluateAdmissionEvidence(ctx context.Context, rule admission.Rule, pod *corev1.Pod) (string, bool, error) {
	reason, hit, _, err := s.EvaluateAdmissionEvidenceWithDetails(ctx, rule, pod)
	return reason, hit, err
}

func (s *Source) EvaluateAdmissionEvidenceWithDetails(ctx context.Context, rule admission.Rule, pod *corev1.Pod) (string, bool, []Detail, error) {
	images := admissionEvidenceImages(pod)
	if len(images) == 0 {
		return "", false, nil, nil
	}
	for _, gate := range rule.Conditions.EvidenceGates {
		for _, image := range images {
			if reason, blocked, result, hasResult, err := s.evaluateScanEvidenceGate(ctx, gate, image); err != nil {
				return "", false, nil, err
			} else if blocked {
				if hasResult {
					return reason, true, []Detail{scanResultDetail(image, result)}, nil
				}
				return reason, true, []Detail{missingScanResultDetail(image)}, nil
			}
			if gate.Type == "artifact" {
				hit, found, err := s.findArtifactHit(ctx, gate, image)
				if err != nil {
					return "", false, nil, err
				}
				if found {
					return formatAdmissionEvidenceHit(rule, gate, image, hit), true, []Detail{hitDetail(image, hit)}, nil
				}
				continue
			}
			if artifactGate, ok := artifactGateFromFindingGate(gate); ok {
				hit, found, err := s.findArtifactHit(ctx, artifactGate, image)
				if err != nil {
					return "", false, nil, err
				}
				if found {
					return formatAdmissionEvidenceHit(rule, artifactGate, image, hit), true, []Detail{hitDetail(image, hit)}, nil
				}
			}
			// Named-CVE deny list (A3): deny if any explicitly-denied CVE id is
			// present on the image, regardless of severity or count. Mirrors
			// NeuVector CriteriaKeyCVENames. Runs before the count/score paths so
			// a blocked CVE is reported by id.
			if gate.Type == "vulnerability" && len(gate.DeniedCVEs) > 0 {
				reason, denied, err := s.findDeniedCVEHit(ctx, gate, image)
				if err != nil {
					return "", false, nil, err
				}
				if denied {
					return reason, true, []Detail{vulnCountDetail(image, "image-finding-denied-cve", reason)}, nil
				}
			}
			// Count-based vulnerability gate (deny if distinct critical/high CVE
			// counts exceed the thresholds), independent of the any-above-severity
			// path below.
			if gate.Type == "vulnerability" && (gate.MaxCriticalCVEs != nil || gate.MaxHighCVEs != nil) {
				reason, denied, err := s.findVulnCountHit(ctx, gate, image)
				if err != nil {
					return "", false, nil, err
				}
				if denied {
					return reason, true, []Detail{vulnCountDetail(image, "image-finding-count", reason)}, nil
				}
			}
			// CVE-score gate (deny if distinct CVEs with CVSS base score >= the
			// threshold exceed the allowed count), mirroring NeuVector's
			// CriteriaKeyCVEScoreCount. Independent of the count and severity paths.
			if gate.Type == "vulnerability" && gate.MaxCVEsAtOrAboveScore != nil {
				reason, denied, err := s.findVulnScoreCountHit(ctx, gate, image)
				if err != nil {
					return "", false, nil, err
				}
				if denied {
					return reason, true, []Detail{vulnCountDetail(image, "image-finding-cve-score", reason)}, nil
				}
			}
			// Skip the any-above-severity hit for count-only vulnerability gates
			// (no maxAllowedSeverity), whose intent is "allow up to N", not
			// "deny any at this severity".
			if gate.Type == "vulnerability" && gate.MaxAllowedSeverity == "" {
				continue
			}
			hit, found, err := s.findEvidenceHit(ctx, gate, image)
			if err != nil {
				return "", false, nil, err
			}
			if found {
				return formatAdmissionEvidenceHit(rule, gate, image, hit), true, []Detail{hitDetail(image, hit)}, nil
			}
		}
	}
	return "", false, nil, nil
}

func (s *Source) evaluateScanEvidenceGate(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (string, bool, admissionEvidenceScanResult, bool, error) {
	if !scanEvidenceGateRequiresResult(gate) {
		return "", false, admissionEvidenceScanResult{}, false, nil
	}
	if gate.RequireDigestMatch && strings.TrimSpace(image.Digest) == "" {
		return fmt.Sprintf("container %q image %q is not digest-pinned for admission scan evidence", image.Container, image.Raw), true, admissionEvidenceScanResult{}, false, nil
	}
	sourceTypes := normalizeAdmissionStrings(gate.AllowedSourceTypes)
	result, found, err := s.latestImageScanResult(ctx, gate, image)
	if err != nil {
		return "", false, admissionEvidenceScanResult{}, false, err
	}
	if !found {
		if len(sourceTypes) > 0 {
			return fmt.Sprintf("container %q image %q has no known Constellation scan result from allowed source types: %s",
				image.Container, image.Raw, strings.Join(sourceTypes, ", ")), true, admissionEvidenceScanResult{}, false, nil
		}
		return fmt.Sprintf("container %q image %q has no known Constellation scan result", image.Container, image.Raw), true, admissionEvidenceScanResult{}, false, nil
	}
	if gate.RequireDigestMatch && strings.TrimSpace(result.Digest) != strings.TrimSpace(image.Digest) {
		return fmt.Sprintf("container %q image %q scan result digest %q does not match admitted digest %q",
			image.Container, image.Raw, result.Digest, image.Digest), true, result, true, nil
	}
	if gate.MaxScanAgeSeconds > 0 {
		maxAge := time.Duration(gate.MaxScanAgeSeconds) * time.Second
		age := time.Since(result.LastScannedAt)
		if age > maxAge {
			return fmt.Sprintf("container %q image %q scan result is stale: last scanned %s ago, max age %s",
				image.Container, image.Raw, age.Truncate(time.Second), maxAge), true, result, true, nil
		}
	}
	if gate.RequireVulnDBBundle && (strings.TrimSpace(result.VulnDBBundleVersion) == "" || strings.TrimSpace(result.VulnDBBundleHash) == "") {
		return fmt.Sprintf("container %q image %q scan result has no VulnDB bundle provenance", image.Container, image.Raw), true, result, true, nil
	}
	if gate.RequireTrustedAttestation || len(gate.AttestationPredicateTypes) > 0 || len(gate.AllowedAttestationIdentities) > 0 || len(gate.AllowedAttestationIssuers) > 0 {
		found, err := s.hasTrustedAttestation(ctx, gate, result)
		if err != nil {
			return "", false, admissionEvidenceScanResult{}, false, err
		}
		if !found {
			return fmt.Sprintf("container %q image %q scan result has no trusted repository/CI attestation matching admission policy",
				image.Container, image.Raw), true, result, true, nil
		}
	}
	return "", false, result, true, nil
}

func scanEvidenceGateRequiresResult(gate admission.EvidenceGate) bool {
	return gate.RequireKnownScanResult ||
		gate.MaxScanAgeSeconds > 0 ||
		gate.RequireVulnDBBundle ||
		len(gate.AllowedSourceTypes) > 0 ||
		gate.RequireDigestMatch ||
		gate.RequireTrustedAttestation ||
		len(gate.AttestationPredicateTypes) > 0 ||
		len(gate.AllowedAttestationIdentities) > 0 ||
		len(gate.AllowedAttestationIssuers) > 0
}

func missingScanResultDetail(image admissionEvidenceImage) Detail {
	return Detail{
		Kind:  "missing-image-scan-result",
		Label: "Missing image scan result",
		Image: imageDetail(image, "", ""),
	}
}

// vulnCountDetail is the structured detail for count/score vulnerability denials.
// The deny fires because scan findings exist and exceed a threshold, so the kind
// reflects the CVE-count/score reason rather than the missing-scan detail. The
// human-readable reason (which carries the offending count) is used as the label.
func vulnCountDetail(image admissionEvidenceImage, kind, reason string) Detail {
	return Detail{
		Kind:  kind,
		Label: reason,
		Image: imageDetail(image, "", ""),
	}
}

func scanResultDetail(image admissionEvidenceImage, result admissionEvidenceScanResult) Detail {
	return Detail{
		Kind:  "image-scan-result",
		Label: "Image scan result",
		Image: imageDetail(image, result.ImageRef, result.Digest),
		ScanResult: &ScanResultDetail{
			ID:                  result.ID.String(),
			ImageRef:            firstNonEmpty(result.ImageRef, image.Raw),
			ImageDigest:         firstNonEmpty(result.Digest, image.Digest),
			SourceType:          result.SourceType,
			SourceRef:           result.SourceRef,
			LastScannedAt:       result.LastScannedAt,
			VulnDBBundleVersion: result.VulnDBBundleVersion,
			VulnDBBundleHash:    result.VulnDBBundleHash,
			PackageCount:        result.PackageCount,
			FindingCount:        result.FindingCount,
		},
	}
}

func hitDetail(image admissionEvidenceImage, hit admissionEvidenceHit) Detail {
	detail := Detail{
		Kind:  "image-scan-result",
		Label: "Image scan result",
		Image: imageDetail(image, hit.ImageRef, hit.Digest),
		ScanResult: &ScanResultDetail{
			ID:                  hit.ImageScanResultID.String(),
			ImageRef:            firstNonEmpty(hit.ImageRef, image.Raw),
			ImageDigest:         firstNonEmpty(hit.Digest, image.Digest),
			SourceType:          hit.SourceType,
			SourceRef:           hit.SourceRef,
			LastScannedAt:       hit.LastScannedAt,
			VulnDBBundleVersion: hit.BundleVersion,
			VulnDBBundleHash:    hit.BundleHash,
			PackageCount:        hit.PackageCount,
			FindingCount:        hit.FindingCount,
		},
	}
	switch hit.Kind {
	case "vulnerability":
		detail.Kind = "image-finding"
		detail.Label = firstNonEmpty(hit.ExternalID, hit.FindingID, "Vulnerability finding")
		detail.Finding = &FindingDetail{
			ID:               hit.FindingID,
			Key:              hit.FindingKey,
			ExternalID:       hit.ExternalID,
			Title:            hit.Title,
			Severity:         hit.Severity,
			RiskScore:        hit.RiskScore,
			CanonicalEngine:  hit.CanonicalEngine,
			PackageEcosystem: hit.PackageEcosystem,
			PackageName:      hit.PackageName,
			PackageVersion:   hit.PackageVersion,
			PackagePURL:      hit.PackagePURL,
			FixedVersion:     hit.FixedVersion,
		}
	case "secret":
		detail.Kind = "image-artifact"
		detail.Label = firstNonEmpty(hit.ExternalID, "Secret evidence")
		detail.Artifact = artifactDetail(hit)
	case "file-risk":
		detail.Kind = "image-artifact"
		detail.Label = firstNonEmpty(hit.Path, hit.ExternalID, "File risk evidence")
		detail.Artifact = artifactDetail(hit)
	case "signature":
		detail.Kind = "image-artifact"
		detail.Label = firstNonEmpty(hit.Identity, hit.Status, "Signature evidence")
		detail.Artifact = artifactDetail(hit)
	default:
		detail.Label = firstNonEmpty(hit.ExternalID, hit.Title, detail.Label)
	}
	return detail
}

func imageDetail(image admissionEvidenceImage, ref, digest string) ImageDetail {
	return ImageDetail{
		Container: image.Container,
		Role:      image.Role,
		Ref:       firstNonEmpty(ref, image.Raw),
		Digest:    firstNonEmpty(digest, image.Digest),
	}
}

func artifactDetail(hit admissionEvidenceHit) *ArtifactDetail {
	detail := &ArtifactDetail{
		Type:      hit.ArtifactType,
		Format:    hit.ArtifactFormat,
		Status:    hit.Status,
		Identity:  hit.Identity,
		Path:      hit.Path,
		Severity:  hit.Severity,
		Title:     hit.Title,
		RuleID:    hit.ExternalID,
		RiskTypes: append([]string(nil), hit.RiskTypes...),
		Count:     hit.Count,
	}
	if hit.ArtifactID != uuid.Nil {
		detail.ID = hit.ArtifactID.String()
	}
	return detail
}

func (s *Source) latestImageScanResult(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (admissionEvidenceScanResult, bool, error) {
	sourceTypes := normalizeAdmissionStrings(gate.AllowedSourceTypes)
	row := s.pool.QueryRow(ctx, `
SELECT r.id,
       r.image_ref,
       r.image_digest,
       COALESCE(NULLIF(r.source_type, ''), st.source_type, ''),
       COALESCE(NULLIF(r.source_ref, ''), st.source_ref, ''),
       r.last_scanned_at,
       r.vulndb_bundle_version,
       r.vulndb_bundle_hash,
       r.package_count,
       r.finding_count
  FROM image_scan_results r
  LEFT JOIN scan_targets st ON st.id = r.scan_target_id
 WHERE r.org_id = $1
   AND (
        r.image_ref = ANY($2::text[])
     OR r.image_ref_normalized = ANY($2::text[])
     OR ($3::text <> '' AND r.image_digest = $3)
   )
   AND (cardinality($4::text[]) = 0 OR COALESCE(NULLIF(r.source_type, ''), st.source_type, '') = ANY($4::text[]))
   AND (NOT $5::bool OR ($3::text <> '' AND r.image_digest = $3))
 ORDER BY CASE WHEN ($3::text <> '' AND r.image_digest = $3) THEN 0 ELSE 1 END,
          r.last_scanned_at DESC, r.updated_at DESC
 LIMIT 1`, s.orgID, image.Candidates, image.Digest, sourceTypes, gate.RequireDigestMatch)
	var result admissionEvidenceScanResult
	if err := row.Scan(
		&result.ID,
		&result.ImageRef,
		&result.Digest,
		&result.SourceType,
		&result.SourceRef,
		&result.LastScannedAt,
		&result.VulnDBBundleVersion,
		&result.VulnDBBundleHash,
		&result.PackageCount,
		&result.FindingCount,
	); err != nil {
		if err == pgx.ErrNoRows {
			return admissionEvidenceScanResult{}, false, nil
		}
		return admissionEvidenceScanResult{}, false, err
	}
	return result, true, nil
}

func (s *Source) hasTrustedAttestation(ctx context.Context, gate admission.EvidenceGate, result admissionEvidenceScanResult) (bool, error) {
	predicateTypes := normalizeAdmissionStrings(gate.AttestationPredicateTypes)
	identities := normalizeAdmissionStrings(gate.AllowedAttestationIdentities)
	issuers := normalizeAdmissionStrings(gate.AllowedAttestationIssuers)
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
SELECT a.id
  FROM scan_result_attestations a
  JOIN scan_attestation_trust_policies p
    ON p.org_id = a.org_id
   AND p.id = a.trust_policy_id
   AND p.enabled
 WHERE a.org_id = $1
   AND a.subject_kind = 'image'
   AND a.trusted
   AND a.verification_status = 'trusted'
   AND (a.expires_at IS NULL OR a.expires_at > NOW())
   AND (
        a.image_scan_result_id = $2
     OR a.subject_digest = $3
   )
   AND (cardinality($4::text[]) = 0 OR a.predicate_type = ANY($4::text[]))
   AND (cardinality($5::text[]) = 0 OR a.signer_identity = ANY($5::text[]))
   AND (cardinality($6::text[]) = 0 OR a.signer_issuer = ANY($6::text[]))
 ORDER BY a.observed_at DESC, a.created_at DESC
 LIMIT 1`, s.orgID, result.ID, result.Digest, predicateTypes, identities, issuers).Scan(&id)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return id != uuid.Nil, nil
}

// findVulnCountHit denies when the image's distinct critical/high CVE counts
// exceed the gate thresholds (NeuVector-style cveCriticalCount/cveHighCount).
// Distinct CVE ids are counted so the same CVE reported by multiple scanner
// engines is not double-counted. Honors active image acceptances when the gate
// opts in. Returns (reason, denied, err).
func (s *Source) findVulnCountHit(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (string, bool, error) {
	if gate.MaxCriticalCVEs == nil && gate.MaxHighCVEs == nil {
		return "", false, nil
	}
	var crit, high int
	err := s.pool.QueryRow(ctx, `
SELECT
  COUNT(DISTINCT f.external_id) FILTER (WHERE lower(f.severity)='critical' AND COALESCE(f.external_id,'')<>'' AND `+cveGraceKeepClause("$5")+`),
  COUNT(DISTINCT f.external_id) FILTER (WHERE lower(f.severity)='high'     AND COALESCE(f.external_id,'')<>'' AND `+cveGraceKeepClause("$5")+`)
  FROM image_scan_results r
  JOIN image_scan_findings f ON f.org_id = r.org_id AND f.image_scan_result_id = r.id
 WHERE r.org_id = $1
   AND (r.image_ref = ANY($2::text[]) OR r.image_ref_normalized = ANY($2::text[]) OR ($3::text <> '' AND r.image_digest = $3))
   AND (NOT $4::boolean OR NOT EXISTS (
        SELECT 1 FROM image_acceptances ia
         WHERE ia.org_id = r.org_id AND ia.image_digest = r.image_digest
           AND ia.revoked_at IS NULL AND ia.accepted_until > NOW()))`,
		s.orgID, image.Candidates, image.Digest, gate.HonorActiveExceptions, graceDaysArg(gate)).Scan(&crit, &high)
	if err != nil {
		return "", false, err
	}
	if gate.MaxCriticalCVEs != nil && crit > *gate.MaxCriticalCVEs {
		return fmt.Sprintf("image %q has %d critical CVEs (policy allows at most %d)", image.Raw, crit, *gate.MaxCriticalCVEs), true, nil
	}
	if gate.MaxHighCVEs != nil && high > *gate.MaxHighCVEs {
		return fmt.Sprintf("image %q has %d high CVEs (policy allows at most %d)", image.Raw, high, *gate.MaxHighCVEs), true, nil
	}
	return "", false, nil
}

// findVulnScoreCountHit denies when the count of distinct CVEs whose CVSS base
// score is at or above gate.MinCVEScore exceeds gate.MaxCVEsAtOrAboveScore
// (NeuVector-style CriteriaKeyCVEScoreCount). The CVSS base score lives on the
// finding's detail_json->'cvss_base' (a JSON number; same convention the
// discoverer reads). Distinct external_ids are counted so the same CVE reported
// by multiple engines is not double-counted; findings without a parseable score
// or a CVE id are ignored. Honors active image acceptances when the gate opts
// in. Returns (reason, denied, err).
func (s *Source) findVulnScoreCountHit(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (string, bool, error) {
	if gate.MaxCVEsAtOrAboveScore == nil {
		return "", false, nil
	}
	var count int
	err := s.pool.QueryRow(ctx, `
SELECT COUNT(DISTINCT f.external_id)
  FROM image_scan_results r
  JOIN image_scan_findings f ON f.org_id = r.org_id AND f.image_scan_result_id = r.id
 WHERE r.org_id = $1
   AND (r.image_ref = ANY($2::text[]) OR r.image_ref_normalized = ANY($2::text[]) OR ($3::text <> '' AND r.image_digest = $3))
   AND COALESCE(f.external_id,'') <> ''
   AND jsonb_typeof(f.detail_json->'cvss_base') = 'number'
   AND (f.detail_json->>'cvss_base')::numeric >= $5
   AND `+cveGraceKeepClause("$6")+`
   AND (NOT $4::boolean OR NOT EXISTS (
        SELECT 1 FROM image_acceptances ia
         WHERE ia.org_id = r.org_id AND ia.image_digest = r.image_digest
           AND ia.revoked_at IS NULL AND ia.accepted_until > NOW()))`,
		s.orgID, image.Candidates, image.Digest, gate.HonorActiveExceptions, gate.MinCVEScore, graceDaysArg(gate)).Scan(&count)
	if err != nil {
		return "", false, err
	}
	if count > *gate.MaxCVEsAtOrAboveScore {
		return fmt.Sprintf("image %q has %d CVEs with CVSS score >= %g (policy allows at most %d)",
			image.Raw, count, gate.MinCVEScore, *gate.MaxCVEsAtOrAboveScore), true, nil
	}
	return "", false, nil
}

// findDeniedCVEHit denies when any of the gate's explicitly-denied CVE ids is
// present on the image (NeuVector CriteriaKeyCVENames, A3). Matching is
// case-insensitive (both sides upper-cased). The publish-age grace window (A4)
// is applied so a freshly-disclosed denied CVE inside the grace window does not
// yet block. Honors active image acceptances when the gate opts in. Returns
// (reason, denied, err).
func (s *Source) findDeniedCVEHit(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (string, bool, error) {
	if len(gate.DeniedCVEs) == 0 {
		return "", false, nil
	}
	var matched string
	err := s.pool.QueryRow(ctx, `
SELECT upper(f.external_id)
  FROM image_scan_results r
  JOIN image_scan_findings f ON f.org_id = r.org_id AND f.image_scan_result_id = r.id
 WHERE r.org_id = $1
   AND (r.image_ref = ANY($2::text[]) OR r.image_ref_normalized = ANY($2::text[]) OR ($3::text <> '' AND r.image_digest = $3))
   AND upper(COALESCE(f.external_id,'')) = ANY($4::text[])
   AND `+cveGraceKeepClause("$5")+`
   AND (NOT $6::boolean OR NOT EXISTS (
        SELECT 1 FROM image_acceptances ia
         WHERE ia.org_id = r.org_id AND ia.image_digest = r.image_digest
           AND ia.revoked_at IS NULL AND ia.accepted_until > NOW()))
 LIMIT 1`,
		s.orgID, image.Candidates, image.Digest, upperStrings(gate.DeniedCVEs), graceDaysArg(gate), gate.HonorActiveExceptions).Scan(&matched)
	if err == pgx.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return fmt.Sprintf("image %q contains denied CVE %s", image.Raw, matched), true, nil
}

// cveGraceKeepClause returns a SQL boolean fragment (referencing finding alias
// f) that is TRUE for findings that should still be counted/denied under the
// publish-age grace window (A4): the window is disabled, the finding has no
// parseable publish date, or it was published before the grace cutoff. The
// param placeholder must bind the grace-days integer (0 = disabled). A finding
// published within the last <graceDays> days is excluded so freshly-disclosed
// CVEs do not instantly break deploys (NeuVector SubCriteriaPublishDays).
//
// TODO(matrix): image_scan_findings.detail_json does not yet carry a CVE
// 'published' date; the scanner/aggregator (scannerFindingDetail) must populate
// it from NVD/OSV publish metadata for the grace window to exclude anything.
// Until then every finding is treated as "publish date unknown" and counted, so
// the gate stays safe-by-default (it never silently drops a CVE).
func cveGraceKeepClause(param string) string {
	return `(` + param + `::int <= 0 OR CASE
      WHEN f.detail_json->>'published' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
        THEN (f.detail_json->>'published')::timestamptz < NOW() - make_interval(days => ` + param + `::int)
      ELSE true
    END)`
}

// graceDaysArg returns the positive grace-window day count for a gate, or 0 when
// the window is unset/non-positive.
func graceDaysArg(gate admission.EvidenceGate) int {
	if gate.CVEGraceDays != nil && *gate.CVEGraceDays > 0 {
		return *gate.CVEGraceDays
	}
	return 0
}

func upperStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (s *Source) findEvidenceHit(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (admissionEvidenceHit, bool, error) {
	kinds := findingKindsForGate(gate)
	if len(kinds) == 0 {
		return admissionEvidenceHit{}, false, nil
	}
	// ponytail: image_scan_findings has no per-finding kind/category column, so
	// this query can only surface vulnerability findings ('vulnerability' AS
	// kind). Any gate asking for a non-vulnerability finding kind
	// (misconfiguration/iac/cloud-config/compliance) cannot be evaluated here.
	// Fail closed (return an error, which the caller turns into a deny) instead
	// of silently matching zero rows and admitting the pod (fail open).
	// Ceiling: persist a finding kind column on image_scan_findings + backfill,
	// then filter it against $6 instead of hardcoding 'vulnerability'.
	for _, kind := range kinds {
		if kind != "vulnerability" {
			return admissionEvidenceHit{}, false, fmt.Errorf(
				"evidence gate finding kind %q cannot be evaluated: image scan findings do not persist a finding kind", kind)
		}
	}
	sourceTypes := normalizeAdmissionStrings(gate.AllowedSourceTypes)
	minSeverityRank := minimumSeverityRankForGate(gate)
	minConfidenceRank := confidenceRank(gate.MinimumConfidence)
	rows, err := s.pool.Query(ctx, `
SELECT r.id,
       r.image_ref,
       r.image_digest,
       COALESCE(NULLIF(r.source_type, ''), st.source_type, ''),
       COALESCE(NULLIF(r.source_ref, ''), st.source_ref, ''),
       r.last_scanned_at,
       r.vulndb_bundle_version,
       r.vulndb_bundle_hash,
       r.package_count,
       r.finding_count,
       f.id::text,
       f.finding_key,
       COALESCE(f.external_id, ''),
       f.title,
       f.severity,
       f.risk_score,
       COALESCE(f.canonical_engine, ''),
       COALESCE(f.package_ecosystem, ''),
       COALESCE(f.package_name, ''),
       COALESCE(f.package_version, ''),
       COALESCE(f.package_purl, ''),
       COALESCE(f.fixed_version, ''),
       'vulnerability' AS kind
  FROM image_scan_results r
  LEFT JOIN scan_targets st ON st.id = r.scan_target_id
  JOIN image_scan_findings f
    ON f.org_id = r.org_id
   AND f.image_scan_result_id = r.id
 WHERE r.org_id = $1
   AND (
        r.image_ref = ANY($2::text[])
     OR r.image_ref_normalized = ANY($2::text[])
     OR ($3::text <> '' AND r.image_digest = $3)
   )
   AND (cardinality($4::text[]) = 0 OR COALESCE(NULLIF(r.source_type, ''), st.source_type, '') = ANY($4::text[]))
   AND (NOT $5::bool OR ($3::text <> '' AND r.image_digest = $3))
   AND 'vulnerability' = ANY($6::text[])
   AND CASE lower(f.severity)
         WHEN 'critical' THEN 4
         WHEN 'high' THEN 3
         WHEN 'medium' THEN 2
         WHEN 'low' THEN 1
         ELSE 0
       END >= $7
   AND ($9 = 0 OR CASE lower(COALESCE(f.detail_json->>'confidence', 'high'))
         WHEN 'critical' THEN 4
         WHEN 'high' THEN 3
         WHEN 'medium' THEN 2
         WHEN 'low' THEN 1
         ELSE 0
       END >= $9)
   AND (NOT $8::boolean OR NOT EXISTS (
       SELECT 1
         FROM image_acceptances ia
        WHERE ia.org_id = r.org_id
          AND ia.image_digest = r.image_digest
          AND ia.revoked_at IS NULL
          AND ia.accepted_until > NOW()
   ))
   AND (
        cardinality($10::text[]) = 0
     OR lower(COALESCE(f.canonical_engine, '')) = ANY($10::text[])
   )
   AND (NOT $11::boolean OR NULLIF(f.fixed_version, '') IS NOT NULL)
   AND `+cveGraceKeepClause("$12")+`
 ORDER BY CASE lower(f.severity)
            WHEN 'critical' THEN 4
            WHEN 'high' THEN 3
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 1
            ELSE 0
          END DESC,
          f.risk_score DESC,
          f.last_seen_at DESC
 LIMIT 1`, s.orgID, image.Candidates, image.Digest, sourceTypes, gate.RequireDigestMatch, kinds, minSeverityRank, gate.HonorActiveExceptions, minConfidenceRank, normalizeAdmissionStrings(gate.AllowedCanonicalEngines), gate.RequireFixAvailable, graceDaysArg(gate))
	if err != nil {
		return admissionEvidenceHit{}, false, err
	}
	defer rows.Close()
	var hit admissionEvidenceHit
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return admissionEvidenceHit{}, false, err
		}
		return admissionEvidenceHit{}, false, nil
	}
	if err := rows.Scan(
		&hit.ImageScanResultID,
		&hit.ImageRef,
		&hit.Digest,
		&hit.SourceType,
		&hit.SourceRef,
		&hit.LastScannedAt,
		&hit.BundleVersion,
		&hit.BundleHash,
		&hit.PackageCount,
		&hit.FindingCount,
		&hit.FindingID,
		&hit.FindingKey,
		&hit.ExternalID,
		&hit.Title,
		&hit.Severity,
		&hit.RiskScore,
		&hit.CanonicalEngine,
		&hit.PackageEcosystem,
		&hit.PackageName,
		&hit.PackageVersion,
		&hit.PackagePURL,
		&hit.FixedVersion,
		&hit.Kind,
	); err != nil {
		return admissionEvidenceHit{}, false, err
	}
	return hit, true, rows.Err()
}

func (s *Source) findArtifactHit(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (admissionEvidenceHit, bool, error) {
	switch strings.ToLower(strings.TrimSpace(gate.Artifact)) {
	case "secret", "secrets":
		return s.findSecretArtifactHit(ctx, gate, image)
	case "file-risk", "file-risks", "file_risk", "file_risks":
		return s.findFileRiskArtifactHit(ctx, gate, image)
	case "signature", "signature-scan", "image-signature":
		return s.findSignatureArtifactHit(ctx, gate, image)
	default:
		return admissionEvidenceHit{}, false, nil
	}
}

func (s *Source) findSecretArtifactHit(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (admissionEvidenceHit, bool, error) {
	minSeverityRank := minimumSeverityRankForGate(gate)
	sourceTypes := normalizeAdmissionStrings(gate.AllowedSourceTypes)
	row := s.pool.QueryRow(ctx, `
WITH latest AS (
  SELECT r.id,
         r.image_ref,
         r.image_digest,
         COALESCE(NULLIF(r.source_type, ''), st.source_type, '') AS source_type,
         COALESCE(NULLIF(r.source_ref, ''), st.source_ref, '') AS source_ref,
         r.last_scanned_at,
         r.vulndb_bundle_version,
         r.vulndb_bundle_hash,
         r.package_count,
         r.finding_count,
         r.updated_at
    FROM image_scan_results r
    LEFT JOIN scan_targets st ON st.id = r.scan_target_id
   WHERE r.org_id = $1
     AND (
          r.image_ref = ANY($2::text[])
       OR r.image_ref_normalized = ANY($2::text[])
       OR ($3::text <> '' AND r.image_digest = $3)
     )
     AND (cardinality($4::text[]) = 0 OR COALESCE(NULLIF(r.source_type, ''), st.source_type, '') = ANY($4::text[]))
     AND (NOT $5::bool OR ($3::text <> '' AND r.image_digest = $3))
   ORDER BY r.last_scanned_at DESC, r.updated_at DESC
   LIMIT 1
), hits AS (
  SELECT l.id,
         l.image_ref,
         l.image_digest,
         l.source_type,
         l.source_ref,
         l.last_scanned_at,
         l.vulndb_bundle_version,
         l.vulndb_bundle_hash,
         l.package_count,
         l.finding_count,
         a.id AS artifact_id,
         COALESCE(secret.value->>'rule_id', '') AS external_id,
         COALESCE(secret.value->>'title', 'secret detected') AS title,
         COALESCE(NULLIF(LOWER(secret.value->>'severity'), ''), 'info') AS severity,
         COALESCE(NULLIF(secret.value->>'path', ''), secret.value->>'target', '') AS path
    FROM latest l
    JOIN image_scan_artifacts a
      ON a.org_id = $1
     AND a.image_scan_result_id = l.id
     AND a.artifact_type = 'secret-scan'
     AND a.format = 'constellation-image-secrets-v1'
   CROSS JOIN LATERAL jsonb_array_elements(COALESCE(a.payload->'secrets', '[]'::jsonb)) AS secret(value)
   WHERE CASE COALESCE(NULLIF(LOWER(secret.value->>'severity'), ''), 'info')
           WHEN 'critical' THEN 4
           WHEN 'high' THEN 3
           WHEN 'medium' THEN 2
           WHEN 'low' THEN 1
           ELSE 0
         END >= $6
)
SELECT id,
       image_ref,
       image_digest,
       source_type,
       source_ref,
       last_scanned_at,
       vulndb_bundle_version,
       vulndb_bundle_hash,
       package_count,
       finding_count,
       artifact_id,
       external_id,
       title,
       severity,
       path,
       COUNT(*) OVER()::int AS hit_count
  FROM hits
 ORDER BY CASE severity
            WHEN 'critical' THEN 4
            WHEN 'high' THEN 3
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 1
            ELSE 0
          END DESC,
          path ASC
 LIMIT 1`, s.orgID, image.Candidates, image.Digest, sourceTypes, gate.RequireDigestMatch, minSeverityRank)
	var hit admissionEvidenceHit
	if err := row.Scan(
		&hit.ImageScanResultID,
		&hit.ImageRef,
		&hit.Digest,
		&hit.SourceType,
		&hit.SourceRef,
		&hit.LastScannedAt,
		&hit.BundleVersion,
		&hit.BundleHash,
		&hit.PackageCount,
		&hit.FindingCount,
		&hit.ArtifactID,
		&hit.ExternalID,
		&hit.Title,
		&hit.Severity,
		&hit.Path,
		&hit.Count,
	); err != nil {
		if err == pgx.ErrNoRows {
			return admissionEvidenceHit{}, false, nil
		}
		return admissionEvidenceHit{}, false, err
	}
	hit.Kind = "secret"
	hit.ArtifactType = "secret-scan"
	hit.ArtifactFormat = "constellation-image-secrets-v1"
	if hit.Count <= gate.MaxAllowedCount {
		return admissionEvidenceHit{}, false, nil
	}
	return hit, true, nil
}

func (s *Source) findFileRiskArtifactHit(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (admissionEvidenceHit, bool, error) {
	minSeverityRank := minimumSeverityRankForGate(gate)
	riskTypes := normalizeAdmissionStrings(gate.RiskTypes)
	sourceTypes := normalizeAdmissionStrings(gate.AllowedSourceTypes)
	row := s.pool.QueryRow(ctx, `
WITH latest AS (
  SELECT r.id,
         r.image_ref,
         r.image_digest,
         COALESCE(NULLIF(r.source_type, ''), st.source_type, '') AS source_type,
         COALESCE(NULLIF(r.source_ref, ''), st.source_ref, '') AS source_ref,
         r.last_scanned_at,
         r.vulndb_bundle_version,
         r.vulndb_bundle_hash,
         r.package_count,
         r.finding_count,
         r.updated_at
    FROM image_scan_results r
    LEFT JOIN scan_targets st ON st.id = r.scan_target_id
   WHERE r.org_id = $1
     AND (
          r.image_ref = ANY($2::text[])
       OR r.image_ref_normalized = ANY($2::text[])
       OR ($3::text <> '' AND r.image_digest = $3)
     )
     AND (cardinality($4::text[]) = 0 OR COALESCE(NULLIF(r.source_type, ''), st.source_type, '') = ANY($4::text[]))
     AND (NOT $5::bool OR ($3::text <> '' AND r.image_digest = $3))
   ORDER BY r.last_scanned_at DESC, r.updated_at DESC
   LIMIT 1
), hits AS (
  SELECT l.id,
         l.image_ref,
         l.image_digest,
         l.source_type,
         l.source_ref,
         l.last_scanned_at,
         l.vulndb_bundle_version,
         l.vulndb_bundle_hash,
         l.package_count,
         l.finding_count,
         a.id AS artifact_id,
         COALESCE(finding.value->>'path', '') AS path,
         COALESCE(finding.value->>'reason', 'image filesystem risk') AS title,
         COALESCE(NULLIF(LOWER(finding.value->>'severity'), ''), 'info') AS severity,
         COALESCE((
           SELECT string_agg(rt.value, ',')
             FROM jsonb_array_elements_text(COALESCE(finding.value->'risk_types', '[]'::jsonb)) AS rt(value)
         ), '') AS risk_types
    FROM latest l
    JOIN image_scan_artifacts a
      ON a.org_id = $1
     AND a.image_scan_result_id = l.id
     AND a.artifact_type = 'file-risk'
     AND a.format = 'constellation-image-file-risk-v1'
   CROSS JOIN LATERAL jsonb_array_elements(COALESCE(a.payload->'findings', '[]'::jsonb)) AS finding(value)
   WHERE CASE COALESCE(NULLIF(LOWER(finding.value->>'severity'), ''), 'info')
           WHEN 'critical' THEN 4
           WHEN 'high' THEN 3
           WHEN 'medium' THEN 2
           WHEN 'low' THEN 1
           ELSE 0
         END >= $6
     AND (
          cardinality($7::text[]) = 0
       OR EXISTS (
          SELECT 1
            FROM jsonb_array_elements_text(COALESCE(finding.value->'risk_types', '[]'::jsonb)) AS rt(value)
           WHERE LOWER(rt.value) = ANY($7::text[])
       )
     )
)
SELECT id,
       image_ref,
       image_digest,
       source_type,
       source_ref,
       last_scanned_at,
       vulndb_bundle_version,
       vulndb_bundle_hash,
       package_count,
       finding_count,
       artifact_id,
       path,
       title,
       severity,
       risk_types,
       COUNT(*) OVER()::int AS hit_count
  FROM hits
 ORDER BY CASE severity
            WHEN 'critical' THEN 4
            WHEN 'high' THEN 3
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 1
            ELSE 0
          END DESC,
          path ASC
 LIMIT 1`, s.orgID, image.Candidates, image.Digest, sourceTypes, gate.RequireDigestMatch, minSeverityRank, riskTypes)
	var riskTypeCSV string
	var hit admissionEvidenceHit
	if err := row.Scan(
		&hit.ImageScanResultID,
		&hit.ImageRef,
		&hit.Digest,
		&hit.SourceType,
		&hit.SourceRef,
		&hit.LastScannedAt,
		&hit.BundleVersion,
		&hit.BundleHash,
		&hit.PackageCount,
		&hit.FindingCount,
		&hit.ArtifactID,
		&hit.Path,
		&hit.Title,
		&hit.Severity,
		&riskTypeCSV,
		&hit.Count,
	); err != nil {
		if err == pgx.ErrNoRows {
			return admissionEvidenceHit{}, false, nil
		}
		return admissionEvidenceHit{}, false, err
	}
	hit.Kind = "file-risk"
	hit.ExternalID = strings.TrimSpace(riskTypeCSV)
	hit.ArtifactType = "file-risk"
	hit.ArtifactFormat = "constellation-image-file-risk-v1"
	hit.RiskTypes = splitCSV(riskTypeCSV)
	if hit.Count <= gate.MaxAllowedCount {
		return admissionEvidenceHit{}, false, nil
	}
	return hit, true, nil
}

func (s *Source) findSignatureArtifactHit(ctx context.Context, gate admission.EvidenceGate, image admissionEvidenceImage) (admissionEvidenceHit, bool, error) {
	sourceTypes := normalizeAdmissionStrings(gate.AllowedSourceTypes)
	row := s.pool.QueryRow(ctx, `
WITH latest AS (
  SELECT r.id,
         r.image_ref,
         r.image_digest,
         COALESCE(NULLIF(r.source_type, ''), st.source_type, '') AS source_type,
         COALESCE(NULLIF(r.source_ref, ''), st.source_ref, '') AS source_ref,
         r.last_scanned_at,
         r.vulndb_bundle_version,
         r.vulndb_bundle_hash,
         r.package_count,
         r.finding_count,
         r.updated_at
    FROM image_scan_results r
    LEFT JOIN scan_targets st ON st.id = r.scan_target_id
   WHERE r.org_id = $1
     AND (
          r.image_ref = ANY($2::text[])
       OR r.image_ref_normalized = ANY($2::text[])
       OR ($3::text <> '' AND r.image_digest = $3)
     )
     AND (cardinality($4::text[]) = 0 OR COALESCE(NULLIF(r.source_type, ''), st.source_type, '') = ANY($4::text[]))
     AND (NOT $5::bool OR ($3::text <> '' AND r.image_digest = $3))
   ORDER BY r.last_scanned_at DESC, r.updated_at DESC
   LIMIT 1
)
SELECT l.id,
       l.image_ref,
       l.image_digest,
       l.source_type,
       l.source_ref,
       l.last_scanned_at,
       l.vulndb_bundle_version,
       l.vulndb_bundle_hash,
       l.package_count,
       l.finding_count,
       COALESCE(a.id, '00000000-0000-0000-0000-000000000000'::uuid) AS artifact_id,
       a.id IS NOT NULL AS has_artifact,
       COALESCE(NULLIF(LOWER(a.payload->>'status'), ''), 'missing') AS status,
       CASE LOWER(COALESCE(a.payload->>'signed', 'false')) WHEN 'true' THEN true ELSE false END AS signed,
       CASE LOWER(COALESCE(a.payload->>'trusted', 'false')) WHEN 'true' THEN true ELSE false END AS trusted,
       COALESCE(a.payload#>>'{signature,identity}', a.payload->>'identity', '') AS identity,
       COALESCE(a.payload#>>'{signature,reason}', a.payload->>'reason', '') AS reason
  FROM latest l
  LEFT JOIN image_scan_artifacts a
    ON a.org_id = $1
   AND a.image_scan_result_id = l.id
   AND a.artifact_type = 'signature-scan'
   AND a.format = 'constellation-image-signature-v1'
 LIMIT 1`, s.orgID, image.Candidates, image.Digest, sourceTypes, gate.RequireDigestMatch)
	var hit admissionEvidenceHit
	var hasArtifact, signed, trusted bool
	var identity, reason string
	if err := row.Scan(
		&hit.ImageScanResultID,
		&hit.ImageRef,
		&hit.Digest,
		&hit.SourceType,
		&hit.SourceRef,
		&hit.LastScannedAt,
		&hit.BundleVersion,
		&hit.BundleHash,
		&hit.PackageCount,
		&hit.FindingCount,
		&hit.ArtifactID,
		&hasArtifact,
		&hit.Status,
		&signed,
		&trusted,
		&identity,
		&reason,
	); err != nil {
		if err == pgx.ErrNoRows {
			return admissionEvidenceHit{}, false, nil
		}
		return admissionEvidenceHit{}, false, err
	}
	hit.Kind = "signature"
	hit.Severity = "high"
	hit.ArtifactType = "signature-scan"
	hit.ArtifactFormat = "constellation-image-signature-v1"
	hit.Identity = strings.TrimSpace(identity)
	hit.Title = firstNonEmpty(identity, reason, "image signature evidence")
	if !hasArtifact {
		if gate.RequireTrustedSignature || gate.RequireVerifierIdentity || len(gate.AllowedSignatureStatuses) > 0 || len(gate.AllowedVerifierIdentities) > 0 {
			hit.Status = "missing"
			hit.Title = "missing image signature scan evidence"
			return hit, true, nil
		}
		return admissionEvidenceHit{}, false, nil
	}
	allowedStatuses := normalizeAdmissionStrings(gate.AllowedSignatureStatuses)
	if len(allowedStatuses) == 0 && gate.RequireTrustedSignature {
		allowedStatuses = []string{"trusted"}
	}
	if len(allowedStatuses) > 0 && !stringIn(hit.Status, allowedStatuses) {
		return hit, true, nil
	}
	if gate.RequireTrustedSignature && !trusted {
		return hit, true, nil
	}
	if gate.RequireVerifierIdentity && hit.Identity == "" {
		hit.Status = "missing-identity"
		hit.Title = "missing signature verifier identity"
		return hit, true, nil
	}
	if len(gate.AllowedVerifierIdentities) > 0 && !stringIn(hit.Identity, gate.AllowedVerifierIdentities) {
		hit.Status = "identity-not-allowed"
		hit.Title = firstNonEmpty(hit.Identity, "missing signature verifier identity")
		return hit, true, nil
	}
	_ = signed
	return admissionEvidenceHit{}, false, nil
}

func admissionEvidenceImages(pod *corev1.Pod) []admissionEvidenceImage {
	if pod == nil {
		return nil
	}
	out := make([]admissionEvidenceImage, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers)+len(pod.Spec.EphemeralContainers))
	for _, c := range pod.Spec.InitContainers {
		out = append(out, admissionEvidenceImageFor(c.Name, "init", c.Image))
	}
	for _, c := range pod.Spec.Containers {
		out = append(out, admissionEvidenceImageFor(c.Name, "container", c.Image))
	}
	for _, c := range pod.Spec.EphemeralContainers {
		out = append(out, admissionEvidenceImageFor(c.Name, "ephemeral", c.EphemeralContainerCommon.Image))
	}
	return out
}

func admissionEvidenceImageFor(container, role, raw string) admissionEvidenceImage {
	parsed := admission.ParseReqImageName(raw)
	return admissionEvidenceImage{
		Container:  container,
		Role:       role,
		Raw:        raw,
		Digest:     parsed.Digest,
		Candidates: imageRefCandidates(parsed),
	}
}

func imageRefCandidates(ref admission.ImageRef) []string {
	candidates := []string{strings.TrimSpace(ref.Raw)}
	registry := strings.TrimSuffix(strings.TrimPrefix(ref.Registry, "https://"), "/")
	repo := strings.TrimSpace(ref.Repo)
	tag := strings.TrimSpace(ref.Tag)
	digest := strings.TrimSpace(ref.Digest)
	if registry != "" && repo != "" {
		base := registry + "/" + repo
		if digest != "" {
			candidates = append(candidates, base+"@"+digest)
		}
		if tag != "" {
			candidates = append(candidates, base+":"+tag)
		}
		if registry == "docker.io" && strings.HasPrefix(repo, "library/") {
			shortRepo := strings.TrimPrefix(repo, "library/")
			if digest != "" {
				candidates = append(candidates, shortRepo+"@"+digest, "docker.io/"+shortRepo+"@"+digest)
			}
			if tag != "" {
				candidates = append(candidates, shortRepo+":"+tag, "docker.io/"+shortRepo+":"+tag)
			}
		}
	}
	return uniqueNonEmpty(candidates)
}

func findingKindsForGate(gate admission.EvidenceGate) []string {
	if gate.Type == "vulnerability" {
		return []string{"vulnerability"}
	}
	out := []string{}
	for _, kind := range gate.FindingKinds {
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "":
			continue
		case "misconfiguration":
			out = append(out, "misconfiguration", "iac", "cloud-config", "compliance")
		default:
			out = append(out, strings.ToLower(strings.TrimSpace(kind)))
		}
	}
	return uniqueNonEmpty(out)
}

func artifactGateFromFindingGate(gate admission.EvidenceGate) (admission.EvidenceGate, bool) {
	kinds := normalizeAdmissionStrings(gate.FindingKinds)
	if len(kinds) == 0 {
		return admission.EvidenceGate{}, false
	}
	switch {
	case containsAny(kinds, "secret", "secrets"):
		gate.Type = "artifact"
		gate.Artifact = "secret"
		if gate.MinimumSeverity == "" && gate.MinimumConfidence != "" {
			gate.MinimumSeverity = gate.MinimumConfidence
		}
		return gate, true
	case containsAny(kinds, "file-risk", "file-risks", "file_risk", "file_risks", "setuid", "setgid", "world-writable-file", "world-writable-directory", "device-node", "fifo"):
		gate.Type = "artifact"
		gate.Artifact = "file-risk"
		riskTypes := make([]string, 0, len(kinds))
		for _, kind := range kinds {
			switch kind {
			case "file-risk", "file-risks", "file_risk", "file_risks":
				continue
			default:
				riskTypes = append(riskTypes, kind)
			}
		}
		gate.RiskTypes = riskTypes
		return gate, true
	case containsAny(kinds, "signature", "image-signature", "unsigned-image", "untrusted-signature"):
		gate.Type = "artifact"
		gate.Artifact = "signature"
		if containsAny(kinds, "signature", "image-signature") {
			gate.RequireTrustedSignature = true
		}
		if containsAny(kinds, "unsigned-image") {
			gate.AllowedSignatureStatuses = []string{"trusted", "untrusted"}
		}
		if containsAny(kinds, "untrusted-signature") {
			gate.RequireTrustedSignature = true
		}
		return gate, true
	default:
		return admission.EvidenceGate{}, false
	}
}

func minimumSeverityRankForGate(gate admission.EvidenceGate) int {
	if gate.Type == "vulnerability" {
		rank := severityRank(gate.MaxAllowedSeverity)
		if rank < 0 {
			return severityRank("critical")
		}
		return rank + 1
	}
	rank := severityRank(gate.MinimumSeverity)
	if rank < 0 {
		return 0
	}
	return rank
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info", "informational", "negligible", "unknown", "":
		return 0
	default:
		return -1
	}
}

func confidenceRank(confidence string) int {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func formatAdmissionEvidenceHit(rule admission.Rule, gate admission.EvidenceGate, image admissionEvidenceImage, hit admissionEvidenceHit) string {
	external := hit.ExternalID
	if external == "" {
		external = hit.FindingID
	}
	title := strings.TrimSpace(hit.Title)
	if title == "" {
		title = hit.Kind
	}
	if gate.Type == "vulnerability" {
		return fmt.Sprintf("container %q image %q has %s vulnerability %s (%s)", image.Container, image.Raw, hit.Severity, external, title)
	}
	if gate.Type == "artifact" {
		switch hit.Kind {
		case "secret":
			path := hit.Path
			if path == "" {
				path = "image filesystem"
			}
			return fmt.Sprintf("container %q image %q has %d secret finding(s) above policy threshold; highest is %s %s at %s (%s)",
				image.Container, image.Raw, hit.Count, hit.Severity, external, path, title)
		case "file-risk":
			path := hit.Path
			if path == "" {
				path = "image filesystem"
			}
			return fmt.Sprintf("container %q image %q has %d file-risk finding(s) above policy threshold; highest is %s at %s (%s)",
				image.Container, image.Raw, hit.Count, hit.Severity, path, title)
		case "signature":
			if hit.Status == "missing-identity" || hit.Status == "identity-not-allowed" {
				return fmt.Sprintf("container %q image %q has unacceptable signature verifier identity %q (%s)",
					image.Container, image.Raw, firstNonEmpty(hit.Identity, "missing"), title)
			}
			return fmt.Sprintf("container %q image %q has unacceptable signature status %q (%s)",
				image.Container, image.Raw, firstNonEmpty(hit.Status, "missing"), title)
		}
	}
	return fmt.Sprintf("container %q image %q has %s %s finding %s (%s)", image.Container, image.Raw, hit.Severity, hit.Kind, external, title)
}

func uniqueNonEmpty(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return uniqueNonEmpty(strings.Split(value, ","))
}

func normalizeAdmissionStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func containsAny(values []string, candidates ...string) bool {
	for _, value := range values {
		for _, candidate := range candidates {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func stringIn(value string, allowed []string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, candidate := range allowed {
		if value == strings.ToLower(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
