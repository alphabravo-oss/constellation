// store_matrix.go extends the operator policy store (store.go) with the B7 "broader CRD
// coverage" domains: DPI/WAF signatures (runtime_dlp_rules, category='signature') and
// vulnerability exception profiles (vuln_profiles). (The DLP-sensor domain was removed in
// P0-01 — dlp_sensors never reached the dataplane, so its CRD/store surface was an orphan.)
//
// OWNERSHIP GUARD — created_by IS NULL.
//
// store.go guards the policies/response_rules upserts on source='declarative' (migrations
// 027/108). The tables here predate that column and — per the operator-crds subsystem's
// "no app migration" scope — are not altered, so the operator keys ownership on created_by
// instead: every REST handler that writes these tables stamps created_by = the authenticated
// user (internal/handler/findings/vuln_profiles.go, internal/handler/runtime/runtime_dlp.go),
// and the operator has no user identity, so a NULL
// created_by unambiguously marks an operator-authored (declarative) row. The upsert conflict
// path is guarded (DO UPDATE ... WHERE created_by IS NULL) so a REST/UI-authored row that shares
// the (org, name) identity is never clobbered or adopted — the upsert affects zero rows and
// returns ErrImperativeConflict, exactly mirroring store.go's source guard. Deletes are guarded
// the same way, so a finalizer never orphans nor clobbers an imperative row.
//
// TODO(matrix): a dedicated source column on these three tables (like migration 108 added to
// response_rules) would be the more robust long-term ownership marker — created_by can in theory
// be NULLed on an imperative row if its authoring user is deleted (ON DELETE SET NULL), which
// would let the operator adopt that row. Deferred here to keep this subsystem migration-free.
package policydb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// signatureCategory is the runtime_dlp_rules.category every ConstellationSignatureRule maps to.
// The shared runtime_dlp_rules table also holds category='dlp' dataplane rules; the operator's
// signature CRD owns only the 'signature' slice (the DPI/WAF surface, migration 046).
const signatureCategory = "signature"

// ----------------------- DPI/WAF signatures (runtime_dlp_rules) ----------------------

// SignatureRow is the mapped, org+cluster-scoped representation of a ConstellationSignatureRule
// spec ready to upsert into a runtime_dlp_rules row of category='signature'.
type SignatureRow struct {
	OrgID       uuid.UUID
	ClusterID   uuid.UUID
	Name        string
	Mode        string // monitor | enforce | disabled
	Severity    int    // 1..9
	ApplyDir    int    // 1=egress 2=ingress 3=both
	Patterns    []string
	Description string
}

// UpsertSignatureRule idempotently writes the DPI signature into runtime_dlp_rules keyed by
// UNIQUE(org_id, cluster_id, name). category is forced to 'signature'. The CR is the source of
// truth: on conflict with a row the operator owns (created_by IS NULL) the mutable columns are
// overwritten, correcting drift. dp_rule_id keeps its sequence-assigned value on update (never
// rewritten). When the identity is owned by an imperative (created_by non-NULL) row the upsert
// affects zero rows and returns ErrImperativeConflict.
//
// SAFETY: the controller defaults Mode to "monitor"; this store does not itself promote a rule to
// enforce. An operator-authored enforce is an explicit, declared choice in the CR spec.
func (s *Store) UpsertSignatureRule(ctx context.Context, row SignatureRow) error {
	patterns, err := json.Marshal(row.Patterns)
	if err != nil {
		return fmt.Errorf("marshal signature patterns: %w", err)
	}
	tag, err := s.db.Exec(ctx, `
INSERT INTO runtime_dlp_rules
    (org_id, cluster_id, name, category, apply_dir, severity, mode, patterns, description, created_by, updated_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, NULL, NULL)
ON CONFLICT (org_id, cluster_id, name) DO UPDATE SET
    apply_dir   = EXCLUDED.apply_dir,
    severity    = EXCLUDED.severity,
    mode        = EXCLUDED.mode,
    patterns    = EXCLUDED.patterns,
    description = EXCLUDED.description,
    updated_at  = NOW()
WHERE runtime_dlp_rules.created_by IS NULL`,
		row.OrgID, row.ClusterID, row.Name, signatureCategory, row.ApplyDir,
		row.Severity, row.Mode, string(patterns), row.Description)
	if err != nil {
		return fmt.Errorf("upsert signature rule %q: %w", row.Name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("upsert signature rule %q: %w", row.Name, ErrImperativeConflict)
	}
	return nil
}

// DeleteSignatureRule removes the operator-managed runtime_dlp_rules signature row for
// (orgID, clusterID, name). Only rows the operator owns (created_by IS NULL) and of
// category='signature' are deleted. It reports whether a row was deleted.
func (s *Store) DeleteSignatureRule(ctx context.Context, orgID, clusterID uuid.UUID, name string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`DELETE FROM runtime_dlp_rules
		 WHERE org_id=$1 AND cluster_id=$2 AND name=$3 AND category=$4 AND created_by IS NULL`,
		orgID, clusterID, name, signatureCategory)
	if err != nil {
		return false, fmt.Errorf("delete signature rule %q: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ----------------------- vulnerability profiles (vuln_profiles) ----------------------

// VulnProfileEntry mirrors one vuln_profiles.entries JSONB element (pkg/vulnprofile.Entry).
// The json tags are the on-disk shape the vuln evaluator reads (snake_case).
type VulnProfileEntry struct {
	Name          string   `json:"name"`
	NameRegex     string   `json:"name_regex,omitempty"`
	Images        []string `json:"images,omitempty"`
	Action        string   `json:"action"`
	DaysToFix     int      `json:"days_to_fix,omitempty"`
	SeverityFloor string   `json:"severity_floor,omitempty"`
	ScoreFloor    float64  `json:"score_floor,omitempty"`
	Reserved      string   `json:"reserved,omitempty"`
	RecentDays    int      `json:"recent_days,omitempty"`
	Comment       string   `json:"comment,omitempty"`
}

// VulnDomainScope mirrors vuln_profiles.domain_scope JSONB (pkg/vulnprofile.DomainScope).
type VulnDomainScope struct {
	Clusters   []string `json:"clusters,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
}

// VulnProfileRow is the mapped, org-scoped representation of a ConstellationVulnProfile spec
// ready to upsert into a vuln_profiles row.
type VulnProfileRow struct {
	OrgID       uuid.UUID
	Name        string
	Description string
	Active      bool
	Entries     []VulnProfileEntry
	DomainScope VulnDomainScope
}

// UpsertVulnProfile idempotently writes the vuln profile into vuln_profiles keyed by
// UNIQUE(org_id, name). The CR is the source of truth: on conflict with a row the operator owns
// (created_by IS NULL) the mutable columns are overwritten, correcting drift. cluster_id is left
// NULL — operator profiles are org-wide (per-cluster narrowing is expressed via domain_scope).
// When the (org_id, name) identity is owned by an imperative (created_by non-NULL) row the upsert
// affects zero rows and returns ErrImperativeConflict.
func (s *Store) UpsertVulnProfile(ctx context.Context, row VulnProfileRow) error {
	entries, err := json.Marshal(row.Entries)
	if err != nil {
		return fmt.Errorf("marshal vuln entries: %w", err)
	}
	scope, err := json.Marshal(row.DomainScope)
	if err != nil {
		return fmt.Errorf("marshal vuln domain scope: %w", err)
	}
	tag, err := s.db.Exec(ctx, `
INSERT INTO vuln_profiles (org_id, cluster_id, name, description, active, entries, domain_scope, created_by)
VALUES ($1, NULL, $2, $3, $4, $5, $6, NULL)
ON CONFLICT (org_id, name) DO UPDATE SET
    description  = EXCLUDED.description,
    active       = EXCLUDED.active,
    entries      = EXCLUDED.entries,
    domain_scope = EXCLUDED.domain_scope,
    updated_at   = NOW()
WHERE vuln_profiles.created_by IS NULL`,
		row.OrgID, row.Name, row.Description, row.Active, entries, scope)
	if err != nil {
		return fmt.Errorf("upsert vuln profile %q: %w", row.Name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("upsert vuln profile %q: %w", row.Name, ErrImperativeConflict)
	}
	return nil
}

// DeleteVulnProfile removes the operator-managed vuln_profiles row for (orgID, name). Only rows
// the operator owns (created_by IS NULL) are deleted. It reports whether a row was deleted.
func (s *Store) DeleteVulnProfile(ctx context.Context, orgID uuid.UUID, name string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`DELETE FROM vuln_profiles WHERE org_id=$1 AND name=$2 AND created_by IS NULL`,
		orgID, name)
	if err != nil {
		return false, fmt.Errorf("delete vuln profile %q: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}
