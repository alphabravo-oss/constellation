// Package rbac implements the Constellation RBAC engine.
//
// Mirrors Astronomer's resource/verb model + adds security-specific verbs (read-findings,
// triage-findings, suppress-findings, accept-risk, manage-policies, manage-cve-db,
// manage-runtime-rules).
//
// Scope hierarchy: Org > Cluster > Project. A role assigned at a higher scope covers nested
// scopes (Org-Admin can act on any of the org's clusters and projects).
package rbac

import (
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
)

// Verb is a permission action checked at the request boundary.
type Verb string

const (
	VerbReadFindings       Verb = "read-findings"
	VerbTriageFindings     Verb = "triage-findings"
	VerbSuppressFindings   Verb = "suppress-findings"
	VerbAcceptRisk         Verb = "accept-risk"
	VerbManagePolicies     Verb = "manage-policies"
	VerbManageCVEDB        Verb = "manage-cve-db"
	VerbManageRuntimeRules Verb = "manage-runtime-rules"
	VerbReadAudit          Verb = "read-audit"
	VerbManageUsers        Verb = "manage-users"
	VerbManageOrg          Verb = "manage-org"
	VerbInvokeAI           Verb = "invoke-ai"
	// VerbRuntimeIngest is the narrow privilege granted to runtime-agent service
	// principals: POST /api/v1/events:bulk (write-only). Intentionally not part
	// of any user-facing role — it is only ever attached to runtime_agent_tokens
	// in their middleware-derived assignment, so a compromised agent token cannot
	// read findings, list audit events, etc.
	VerbRuntimeIngest Verb = "runtime-ingest"
	// VerbManageRegistries gates the container-registry CRUD endpoints
	// (POST/PATCH/DELETE /api/v1/registries…) and the walker sync trigger.
	// Granted to SecurityAdmin and GlobalAdmin alongside other manage-* verbs.
	VerbManageRegistries Verb = "manage-registries"
	// VerbManageQuarantine gates the runtime quarantine list — adding,
	// listing, and lifting entries that drive admission webhook denials.
	// Granted to ClusterAdmin and above because every entry can block all new
	// pods in a namespace; Auditors/Analysts see entries through the
	// finding/threat relations (VerbReadFindings) but cannot mutate them.
	VerbManageQuarantine Verb = "manage-quarantine"
	// VerbManageSystemConfig gates the runtime-mutable system configuration surface
	// (GET/PATCH /api/v1/system/config — egress proxy, TLS-verify + CA bundle,
	// syslog/SIEM target, scanner autoscale bounds). These are org-wide operational
	// knobs that change outbound traffic, certificate trust, and log routing, so the
	// privilege is granted only to GlobalAdmin alongside the other org-level admin verbs.
	VerbManageSystemConfig Verb = "manage-system-config"
	// VerbManageAuthServers gates the B4 DB-backed auth-provider (IdP) CRUD surface
	// (GET/POST/PUT/DELETE /api/v1/auth-servers — LDAP/SAML/OIDC provider rows, their
	// secrets, auth_order, and group->role mappings). Authoring an IdP row controls who
	// can authenticate and what roles a federated login is granted org-wide, so the
	// privilege is granted only to GlobalAdmin alongside the other org-level admin verbs.
	VerbManageAuthServers Verb = "manage-auth-servers"
	// VerbManageResponseRules gates the E1 declarative response-rule engine CRUD
	// (GET/POST/PUT/DELETE /api/v1/response-rule-defs). A response rule binds runtime
	// event conditions to automated actions (quarantine, suppress-log, webhook, tag),
	// so authoring one can quarantine workloads org-wide — the privilege sits alongside
	// the other runtime-control verbs (ClusterAdmin and above). The narrower verb (vs.
	// reusing manage-runtime-rules) lets an org grant rule authorship via a custom role
	// without also handing over baselines/WAF/DLP.
	VerbManageResponseRules Verb = "manage-response-rules"
	// VerbFederationSync is the narrow, fed-only privilege a per-cluster federation
	// credential holds: GET /api/v1/federation/sync (read the master's replicated rule
	// log). Like VerbRuntimeIngest it is a SERVICE-PRINCIPAL verb — never part of any
	// user-facing role and not user-grantable, so a generic read-findings principal can
	// no longer pull /sync (D1). It is granted only via the per-joint fed credential the
	// FedSyncTokenMiddleware authenticates, giving each joint cluster a privilege
	// envelope that even a GlobalAdmin user JWT cannot use.
	VerbFederationSync Verb = "federation-sync"
)

// Role names map to a static verb set.
const (
	RoleGlobalAdmin   = "GlobalAdmin"
	RoleSecurityAdmin = "SecurityAdmin"
	RoleClusterAdmin  = "ClusterAdmin"
	RoleAnalyst       = "Analyst"
	RoleAuditor       = "Auditor"
)

// rolePermissions is the canonical role -> verbs mapping. The unit test in this package
// asserts each role's verbs is a subset of the next-higher tier. Editing this table is
// intentionally the only place to change RBAC for user-facing roles.
//
// Service-principal verbs (e.g. VerbRuntimeIngest) are intentionally NOT in any of these
// role rows — they're granted only via per-token assignments synthesized by the
// corresponding token middleware (scanner-token, runtime-agent-token, …), giving each
// machine identity a narrow privilege envelope that even a GlobalAdmin user JWT cannot use.
var rolePermissions = map[string][]Verb{
	RoleAuditor: {
		VerbReadFindings,
		VerbReadAudit,
	},
	RoleAnalyst: {
		VerbReadFindings,
		VerbReadAudit,
		VerbTriageFindings,
		VerbInvokeAI,
	},
	RoleClusterAdmin: {
		VerbReadFindings,
		VerbReadAudit,
		VerbTriageFindings,
		VerbSuppressFindings,
		VerbAcceptRisk,
		VerbManagePolicies,
		VerbManageRuntimeRules,
		VerbManageResponseRules,
		VerbManageQuarantine,
		VerbInvokeAI,
	},
	RoleSecurityAdmin: {
		VerbReadFindings,
		VerbReadAudit,
		VerbTriageFindings,
		VerbSuppressFindings,
		VerbAcceptRisk,
		VerbManagePolicies,
		VerbManageRuntimeRules,
		VerbManageResponseRules,
		VerbManageRegistries,
		VerbManageQuarantine,
		VerbManageCVEDB,
		VerbInvokeAI,
	},
	RoleGlobalAdmin: {
		VerbReadFindings,
		VerbReadAudit,
		VerbTriageFindings,
		VerbSuppressFindings,
		VerbAcceptRisk,
		VerbManagePolicies,
		VerbManageRuntimeRules,
		VerbManageResponseRules,
		VerbManageRegistries,
		VerbManageQuarantine,
		VerbManageCVEDB,
		VerbManageUsers,
		VerbManageOrg,
		VerbManageSystemConfig,
		VerbManageAuthServers,
		VerbInvokeAI,
	},
}

// Scope is the (org, cluster, project, namespace) tuple a role applies to. Cluster and project are
// optional — nil means "org-wide" or "any cluster's project." Namespace (P0-10) is optional too —
// "" means "any namespace"; a set value narrows the grant to that namespace on ClusterID (mirroring
// NeuVector's per-namespace RoleDomains), and covers only a resource carrying the same namespace.
type Scope struct {
	OrgID     uuid.UUID
	ClusterID *uuid.UUID
	ProjectID *uuid.UUID
	Namespace string
}

// RoleAssignment binds a user to a role at a particular scope.
type RoleAssignment struct {
	Role  string
	Scope Scope
}

// Resource identifies what the verb is being checked against. Namespace (P0-10) is "" for the
// cluster/org-level resources most call sites check; a namespace-scoped assignment covers a
// resource only when the resource carries that same namespace (see Authorize).
type Resource struct {
	OrgID     uuid.UUID
	ClusterID *uuid.UUID
	ProjectID *uuid.UUID
	Namespace string
}

// ErrForbidden is returned by Authorize when no assignment grants the requested verb.
var ErrForbidden = errors.New("rbac: forbidden")

// Authorize returns nil iff some assignment in `assignments` grants `verb` on `resource`.
//
// Algorithm: for each assignment whose role grants `verb` AND whose scope covers `resource`,
// return nil. Otherwise return ErrForbidden.
//
// "Covers" means: assignment.OrgID == resource.OrgID, and (assignment.ClusterID == nil OR
// equals resource.ClusterID), and (assignment.ProjectID == nil OR equals resource.ProjectID), and
// (assignment.Namespace == "" OR equals resource.Namespace). The namespace clause (P0-10) makes a
// namespace-scoped grant authorize ONLY a matching-namespace resource; it never widens to the whole
// cluster (a resource with no namespace is not covered by a namespace-scoped assignment).
func Authorize(assignments []RoleAssignment, verb Verb, resource Resource) error {
	return AuthorizeWithCustom(assignments, verb, resource, nil)
}

// AuthorizeWithCustom is Authorize plus org-defined custom roles: `custom` maps
// a custom role name to its verb set (loaded from the custom_roles table). A
// role name not in the static catalog is resolved against `custom`. Custom roles
// can ONLY grant user-grantable verbs — a service-principal verb (e.g.
// runtime-ingest) is never granted via a custom role even if the row lists it,
// so a tampered custom_roles row can't escalate to a service privilege.
func AuthorizeWithCustom(assignments []RoleAssignment, verb Verb, resource Resource, custom map[string][]Verb) error {
	for _, a := range assignments {
		if a.Scope.OrgID != resource.OrgID {
			continue
		}
		if a.Scope.ClusterID != nil && (resource.ClusterID == nil || *a.Scope.ClusterID != *resource.ClusterID) {
			continue
		}
		if a.Scope.ProjectID != nil && (resource.ProjectID == nil || *a.Scope.ProjectID != *resource.ProjectID) {
			continue
		}
		// P0-10: a namespace-scoped grant covers ONLY a resource carrying the same namespace, so it
		// never widens to the whole cluster. An unscoped ("") assignment namespace covers any resource.
		if a.Scope.Namespace != "" && a.Scope.Namespace != resource.Namespace {
			continue
		}
		if roleGrants(a.Role, verb) {
			return nil
		}
		if customGrants(custom, a.Role, verb) {
			return nil
		}
	}
	return fmt.Errorf("%w: verb=%s", ErrForbidden, verb)
}

// NamespaceRestriction reports whether a subject's access to `verb` (within the
// org/cluster scope of `resource`, ignoring `resource.Namespace`) is limited to a
// specific set of namespaces. It underpins RBAC-NS-24 row-level list filtering:
//
//   - restricted=false  → the subject has an org/cluster-wide (namespace="") grant
//     for `verb`, OR no grant at all. Callers apply NO namespace filter (a no-grant
//     subject is denied by Authorize separately).
//   - restricted=true   → every assignment granting `verb` is namespace-scoped;
//     `namespaces` is the de-duplicated set the subject may see. Callers MUST filter
//     list rows to this set. Never empty when restricted is true.
//
// This is deliberately conservative: a single namespace-unrestricted grant for the
// verb makes the subject unrestricted (restricted=false), so we never narrow a user
// who legitimately has cluster-wide read.
func NamespaceRestriction(assignments []RoleAssignment, verb Verb, resource Resource, custom map[string][]Verb) (namespaces []string, restricted bool) {
	seen := map[string]bool{}
	for _, a := range assignments {
		if a.Scope.OrgID != resource.OrgID {
			continue
		}
		if a.Scope.ClusterID != nil && (resource.ClusterID == nil || *a.Scope.ClusterID != *resource.ClusterID) {
			continue
		}
		if a.Scope.ProjectID != nil && (resource.ProjectID == nil || *a.Scope.ProjectID != *resource.ProjectID) {
			continue
		}
		if !roleGrants(a.Role, verb) && !customGrants(custom, a.Role, verb) {
			continue
		}
		// A namespace-unrestricted grant for this verb ⇒ full access, no filter.
		if a.Scope.Namespace == "" {
			return nil, false
		}
		if !seen[a.Scope.Namespace] {
			seen[a.Scope.Namespace] = true
			namespaces = append(namespaces, a.Scope.Namespace)
		}
	}
	if len(namespaces) == 0 {
		return nil, false // no grant for this verb at all — Authorize denies separately
	}
	sort.Strings(namespaces)
	return namespaces, true
}

func roleGrants(role string, verb Verb) bool {
	for _, v := range rolePermissions[role] {
		if v == verb {
			return true
		}
	}
	return false
}

func customGrants(custom map[string][]Verb, role string, verb Verb) bool {
	if custom == nil || !IsUserGrantableVerb(verb) {
		return false
	}
	for _, v := range custom[role] {
		if v == verb {
			return true
		}
	}
	return false
}

// IsRole reports whether role is one of the product-facing RBAC roles.
func IsRole(role string) bool { _, ok := rolePermissions[role]; return ok }

// VerbsForRole returns the canonical verb set for a role. Used by the UI for capability hints
// and by tests.
func VerbsForRole(role string) []Verb {
	verbs := rolePermissions[role]
	out := make([]Verb, len(verbs))
	copy(out, verbs)
	return out
}

// AllVerbs is the canonical, ordered list of every verb the RBAC engine knows about.
// Service-principal verbs (VerbRuntimeIngest) are included so the catalog UI can render
// them as read-only/info entries — they are NOT selectable as user-facing API-token
// scopes (the create endpoint rejects them via IsUserGrantableVerb).
var AllVerbs = []Verb{
	VerbReadFindings,
	VerbReadAudit,
	VerbTriageFindings,
	VerbSuppressFindings,
	VerbAcceptRisk,
	VerbManagePolicies,
	VerbManageRuntimeRules,
	VerbManageResponseRules,
	VerbManageRegistries,
	VerbManageQuarantine,
	VerbManageCVEDB,
	VerbManageUsers,
	VerbManageOrg,
	VerbManageSystemConfig,
	VerbManageAuthServers,
	VerbInvokeAI,
	VerbRuntimeIngest,
	VerbFederationSync,
}

// VerbInfo describes a single verb for the UI scope picker and docs surface.
type VerbInfo struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Category      string `json:"category"`
	UserGrantable bool   `json:"user_grantable"`
}

// verbInfo is the per-verb metadata table used by VerbCatalog. Keeping it in a single
// map makes it easy to add new verbs without touching call sites.
var verbInfo = map[Verb]VerbInfo{
	VerbReadFindings: {
		Description: "Read findings, deployments, assets, and most read-only surfaces",
		Category:    "Read-only", UserGrantable: true,
	},
	VerbReadAudit: {
		Description: "Read the audit log and verify chain integrity",
		Category:    "Read-only", UserGrantable: true,
	},
	VerbTriageFindings: {
		Description: "Triage findings, set lifecycle, leave comments",
		Category:    "Findings", UserGrantable: true,
	},
	VerbSuppressFindings: {
		Description: "Suppress findings (mark as won't-fix or out-of-scope)",
		Category:    "Findings", UserGrantable: true,
	},
	VerbAcceptRisk: {
		Description: "Accept residual risk on findings or image acceptances",
		Category:    "Findings", UserGrantable: true,
	},
	VerbManagePolicies: {
		Description: "Create / edit / delete admission and runtime policies",
		Category:    "Policies", UserGrantable: true,
	},
	VerbManageRuntimeRules: {
		Description: "Manage runtime response rules, baselines, WAF, and DLP",
		Category:    "Runtime", UserGrantable: true,
	},
	VerbManageResponseRules: {
		Description: "Author declarative response rules (condition -> quarantine/suppress/webhook/tag)",
		Category:    "Runtime", UserGrantable: true,
	},
	VerbManageRegistries: {
		Description: "Manage container registries (CRUD + walker triggers)",
		Category:    "Supply Chain", UserGrantable: true,
	},
	VerbManageQuarantine: {
		Description: "Manage runtime quarantine entries and admission deny controls",
		Category:    "Runtime", UserGrantable: true,
	},
	VerbManageCVEDB: {
		Description: "Manage the local CVE bundle + scanner database",
		Category:    "Admin", UserGrantable: true,
	},
	VerbManageUsers: {
		Description: "Manage users, role bindings, and service accounts",
		Category:    "Admin", UserGrantable: true,
	},
	VerbManageOrg: {
		Description: "Manage org-level settings and federation",
		Category:    "Admin", UserGrantable: true,
	},
	VerbManageSystemConfig: {
		Description: "Manage runtime system config (egress proxy, TLS/CA bundle, syslog/SIEM, autoscale)",
		Category:    "Admin", UserGrantable: true,
	},
	VerbManageAuthServers: {
		Description: "Manage auth providers (LDAP/SAML/OIDC servers, secrets, order, group->role mappings)",
		Category:    "Admin", UserGrantable: true,
	},
	VerbInvokeAI: {
		Description: "Invoke the Abbot AI surface (/ai/query)",
		Category:    "Findings", UserGrantable: true,
	},
	VerbRuntimeIngest: {
		Description: "Internal: write runtime events / flows (granted only to runtime-agent tokens)",
		Category:    "Service principals", UserGrantable: false,
	},
	VerbFederationSync: {
		Description: "Internal: pull the master's federated rule log (granted only to per-cluster federation credentials)",
		Category:    "Service principals", UserGrantable: false,
	},
}

// VerbCatalog returns the registry of every verb plus its UI-facing metadata in the
// order declared by AllVerbs. Callers that only want user-grantable verbs should filter
// on VerbInfo.UserGrantable.
func VerbCatalog() []VerbInfo {
	out := make([]VerbInfo, 0, len(AllVerbs))
	for _, v := range AllVerbs {
		info, ok := verbInfo[v]
		if !ok {
			// Belt-and-suspenders: an unregistered verb still gets surfaced so a
			// developer adding a new const and forgetting verbInfo isn't silent.
			info = VerbInfo{Description: "(uncategorized)", Category: "Other", UserGrantable: true}
		}
		info.Name = string(v)
		out = append(out, info)
	}
	return out
}

// IsKnownVerb reports whether v is a verb the engine recognizes. Used by token-mint
// endpoints to reject scopes that don't exist (typos, deprecated names).
func IsKnownVerb(v Verb) bool {
	_, ok := verbInfo[v]
	return ok
}

// IsUserGrantableVerb reports whether v can be attached to a user-issued API token.
// Service-principal verbs (runtime-ingest) are not user-grantable.
func IsUserGrantableVerb(v Verb) bool {
	info, ok := verbInfo[v]
	return ok && info.UserGrantable
}
