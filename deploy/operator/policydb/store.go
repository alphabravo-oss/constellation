// Package policydb is the constellation-operator's thin, org-scoped data-access layer for
// reconciling policy CRs into the Constellation policy store.
//
// DESIGN — direct DB upsert vs. reconciling through the REST API.
//
// The operator reconciles policy CRs straight into the same tables the REST handlers write
// (policies, response_rules), rather than calling the constellation-api REST endpoints, for
// three concrete reasons:
//
//  1. Org scoping. Every policy CR carries its own explicit OrgID and the operator may manage
//     many orgs from one process, but the REST auth model is "one PAT = one org" (org is
//     derived from the authenticated subject, internal/handler/authctx). There is no
//     "act-as-org" affordance, so an API client would need a per-org service token minted out
//     of band — impractical for a cluster operator.
//
//  2. Idempotent, name-keyed upsert. The CR's stable identity is (OrgID, metadata.name), which
//     mirrors the tables' UNIQUE constraints. The REST create endpoints always INSERT a fresh
//     UUID (no name-keyed upsert), so "CR is source of truth, reconcile is idempotent" is not
//     expressible through the existing REST surface without either new endpoints (which would
//     trip the I1 OpenAPI completeness gate) or a racy read-then-write.
//
//  3. Faithful column parity. The upserts here write the exact same columns the handlers do
//     (internal/handler/policy/policies.go and response_rule_defs.go) and validate response
//     rules through the same pkg/responserule.Validate gatekeeper, so the operator stays a
//     thin k8s->store bridge with no behavioral divergence.
//
// Operator-managed rows are tagged source='declarative' — the existing StackRox-inspired
// provenance value (pkg/policy/dsl, migration 027) meaning "committed as YAML and reconciled
// by the operator", as opposed to 'imperative' (UI/API-authored). The policies table already
// carries this column; migration 108 adds the matching column to response_rules. Provenance is
// enforced symmetrically: the finalizer only DELETEs declarative rows, and the upsert's conflict
// path is source-guarded (DO UPDATE ... WHERE source='declarative') so it only UPDATEs declarative
// rows — a REST/UI-authored (imperative) policy that shares a name is never clobbered or relabelled
// (a colliding upsert returns ErrImperativeConflict instead).
//
// ORG SCOPE / AUTHORIZATION BOUNDARY. Every SQL statement here is org-scoped on org_id (taken from
// the CR's spec.OrgID), so cross-org clobber-by-name is impossible. The operator does NOT itself
// authorize which org a CR may target — spec.OrgID is author-asserted and validated only for
// existence (the org_id FK). Authorization over which orgs a CR may write is therefore the
// Kubernetes RBAC boundary on these cluster-scoped CR kinds: whoever can create a
// ConstellationAdmissionRule / ConstellationResponseRule can target any existing org. Operators
// running multi-tenant clusters must gate create/update on these kinds accordingly (or front them
// with an admission webhook that pins spec.OrgID to the authoring tenant).
package policydb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// ErrImperativeConflict is returned by UpsertAdmissionRule / UpsertResponseRule when the CR's
// (org_id, name) identity already exists as an imperative (REST/UI-authored) row. The operator
// refuses to overwrite or relabel that row — the upsert is source-guarded (DO UPDATE ... WHERE
// source='declarative'), so a conflict on an imperative row updates zero rows. This preserves the
// documented invariant that declarative reconcile never clobbers imperative policy. The controller
// surfaces it as a Conflict on the CR status; it self-heals only if the imperative row is removed.
var ErrImperativeConflict = errors.New("policy identity already owned by an imperative (REST/UI-authored) row")

// SourceDeclarative is the policies.source / response_rules.source value stamped on every row
// the operator manages. It is the existing StackRox-inspired "GitOps / reconciled-by-operator"
// provenance value (pkg/policy/dsl.SourceDeclarative), distinguishing CR-authored rows from
// 'imperative' (UI/API-authored) ones.
const SourceDeclarative = "declarative"

// operatorVersion is the fixed policies.version the operator manages. The policies table is
// keyed UNIQUE(org_id, name, version); the operator owns a single version per CR (REST-side
// versioning/history is out of scope for declarative GitOps reconcile).
const operatorVersion = 1

// admissionCategory is the policies.category every ConstellationAdmissionRule maps to.
const admissionCategory = "admission"

// Execer is the subset of pgxpool.Pool the store needs: Exec for the reconcile upserts/deletes
// and Query for the GitOps export reads (List*). A *pgxpool.Pool satisfies it; tests that
// exercise the SQL directly can substitute a fake.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Store is the operator's org-scoped policy data-access layer over the constellation DB.
type Store struct {
	db Execer
}

// New constructs a Store over the given executor (typically a *pgxpool.Pool).
func New(db Execer) *Store { return &Store{db: db} }

// AdmissionRuleRow is the mapped, org-scoped representation of a ConstellationAdmissionRule
// spec ready to upsert into a policies row of category="admission".
type AdmissionRuleRow struct {
	OrgID       uuid.UUID
	Name        string
	Description string
	Engine      string
	Mode        string
	Enabled     bool
	SpecYAML    string
}

// UpsertAdmissionRule idempotently writes the admission rule into the policies table keyed by
// UNIQUE(org_id, name, version). The CR is the source of truth: on conflict with a row the operator
// owns (source='declarative') every mutable column is overwritten, correcting any drift in the
// stored row. The conflict update is source-guarded — it never overwrites or relabels an imperative
// (REST/UI-authored) row, and never flips source imperative->declarative. When the (org_id, name)
// identity is already owned by an imperative row the upsert affects zero rows and returns
// ErrImperativeConflict, leaving that row untouched.
func (s *Store) UpsertAdmissionRule(ctx context.Context, row AdmissionRuleRow) error {
	tag, err := s.db.Exec(ctx, `
INSERT INTO policies (org_id, name, description, engine, category, spec_yaml, enabled, mode, version, source)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (org_id, name, version) DO UPDATE SET
    description = EXCLUDED.description,
    engine      = EXCLUDED.engine,
    category    = EXCLUDED.category,
    spec_yaml   = EXCLUDED.spec_yaml,
    enabled     = EXCLUDED.enabled,
    mode        = EXCLUDED.mode,
    updated_at  = NOW()
WHERE policies.source = $10`,
		row.OrgID, row.Name, row.Description, row.Engine, admissionCategory,
		row.SpecYAML, row.Enabled, row.Mode, operatorVersion, SourceDeclarative)
	if err != nil {
		return fmt.Errorf("upsert admission rule %q: %w", row.Name, err)
	}
	if tag.RowsAffected() == 0 {
		// The INSERT hit a unique conflict but the source guard blocked the update: the row is
		// imperative. Refuse to clobber it.
		return fmt.Errorf("upsert admission rule %q: %w", row.Name, ErrImperativeConflict)
	}
	return nil
}

// DeleteAdmissionRule removes the operator-managed policies row for (orgID, name). Only rows
// the operator owns (source='declarative') are deleted, so a finalizer never orphans — nor
// clobbers — a REST-authored policy that happens to share the name. It reports whether a row
// was deleted.
func (s *Store) DeleteAdmissionRule(ctx context.Context, orgID uuid.UUID, name string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`DELETE FROM policies WHERE org_id=$1 AND name=$2 AND version=$3 AND source=$4`,
		orgID, name, operatorVersion, SourceDeclarative)
	if err != nil {
		return false, fmt.Errorf("delete admission rule %q: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}

// UpsertResponseRule idempotently writes the response rule into the response_rules table keyed
// by UNIQUE(org_id, name). The CR is the source of truth: on conflict with a row the operator owns
// (source='declarative') every mutable column is overwritten, correcting drift. The conflict update
// is source-guarded — it never overwrites or relabels an imperative (REST/UI-authored) row. When the
// (org_id, name) identity is already owned by an imperative row the upsert affects zero rows and
// returns ErrImperativeConflict. The rule must already have passed responserule.Validate (the
// controller validates before calling).
func (s *Store) UpsertResponseRule(ctx context.Context, rule responserule.ResponseRule) error {
	conds, err := json.Marshal(rule.Conditions)
	if err != nil {
		return fmt.Errorf("marshal conditions: %w", err)
	}
	acts, err := json.Marshal(rule.Actions)
	if err != nil {
		return fmt.Errorf("marshal actions: %w", err)
	}
	tag, err := s.db.Exec(ctx, `
INSERT INTO response_rules (org_id, name, enabled, priority, event_type, conditions, actions, source)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (org_id, name) DO UPDATE SET
    enabled    = EXCLUDED.enabled,
    priority   = EXCLUDED.priority,
    event_type = EXCLUDED.event_type,
    conditions = EXCLUDED.conditions,
    actions    = EXCLUDED.actions,
    updated_at = NOW()
WHERE response_rules.source = $8`,
		rule.OrgID, rule.Name, rule.Enabled, rule.Priority, rule.EventType, conds, acts, SourceDeclarative)
	if err != nil {
		return fmt.Errorf("upsert response rule %q: %w", rule.Name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("upsert response rule %q: %w", rule.Name, ErrImperativeConflict)
	}
	return nil
}

// DeleteResponseRule removes the operator-managed response_rules row for (orgID, name). Only
// rows the operator owns (source='declarative') are deleted. It reports whether a row was deleted.
func (s *Store) DeleteResponseRule(ctx context.Context, orgID uuid.UUID, name string) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`DELETE FROM response_rules WHERE org_id=$1 AND name=$2 AND source=$3`,
		orgID, name, SourceDeclarative)
	if err != nil {
		return false, fmt.Errorf("delete response rule %q: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ListAdmissionRules reads the operator-owned (source='declarative') admission policies for orgID
// as upsert-shaped rows, ordered by name. It backs the GitOps `constellationctl policy export-crds`
// path: each returned row maps 1:1 to a ConstellationAdmissionRule CR (see AdmissionCR) that,
// re-applied, upserts the identical row. Only declarative rows are exported, so the export is a
// faithful dump of operator-owned policy and never adopts an imperative (REST/UI-authored) row into
// the CR delete-on-removal lifecycle. (Declarative rows only ever carry the six operator-managed
// columns, so the round-trip is also column-complete for everything it emits.) When a name carries
// multiple versions, only the latest is exported — the operator manages a single version per CR.
func (s *Store) ListAdmissionRules(ctx context.Context, orgID uuid.UUID) ([]AdmissionRuleRow, error) {
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT ON (name) name, description, engine, mode, enabled, spec_yaml
FROM policies
WHERE org_id=$1 AND category=$2 AND source=$3
ORDER BY name, version DESC`, orgID, admissionCategory, SourceDeclarative)
	if err != nil {
		return nil, fmt.Errorf("list admission rules: %w", err)
	}
	defer rows.Close()

	var out []AdmissionRuleRow
	for rows.Next() {
		r := AdmissionRuleRow{OrgID: orgID}
		var description *string
		if err := rows.Scan(&r.Name, &description, &r.Engine, &r.Mode, &r.Enabled, &r.SpecYAML); err != nil {
			return nil, fmt.Errorf("scan admission rule: %w", err)
		}
		if description != nil {
			r.Description = *description
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admission rules: %w", err)
	}
	return out, nil
}

// ListResponseRules reads the operator-owned (source='declarative') response rules for orgID,
// ordered by priority then name, as responserule.ResponseRule values. It backs the GitOps export
// path: each rule maps 1:1 to a ConstellationResponseRule CR (see ResponseCR) that, re-applied,
// upserts the identical row. Only declarative rules are exported, so the export never adopts an
// imperative (REST/UI-authored) rule into the CR delete-on-removal lifecycle.
func (s *Store) ListResponseRules(ctx context.Context, orgID uuid.UUID) ([]responserule.ResponseRule, error) {
	rows, err := s.db.Query(ctx, `
SELECT name, enabled, priority, event_type, conditions, actions
FROM response_rules
WHERE org_id=$1 AND source=$2
ORDER BY priority, name`, orgID, SourceDeclarative)
	if err != nil {
		return nil, fmt.Errorf("list response rules: %w", err)
	}
	defer rows.Close()

	var out []responserule.ResponseRule
	for rows.Next() {
		rule := responserule.ResponseRule{OrgID: orgID}
		var conds, acts []byte
		var eventType string
		if err := rows.Scan(&rule.Name, &rule.Enabled, &rule.Priority, &eventType, &conds, &acts); err != nil {
			return nil, fmt.Errorf("scan response rule: %w", err)
		}
		rule.EventType = responserule.EventType(eventType)
		if err := json.Unmarshal(conds, &rule.Conditions); err != nil {
			return nil, fmt.Errorf("unmarshal conditions for %q: %w", rule.Name, err)
		}
		if err := json.Unmarshal(acts, &rule.Actions); err != nil {
			return nil, fmt.Errorf("unmarshal actions for %q: %w", rule.Name, err)
		}
		out = append(out, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate response rules: %w", err)
	}
	return out, nil
}
