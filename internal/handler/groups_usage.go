package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type groupUsageReferenceDTO struct {
	ID           string `json:"id"`
	Family       string `json:"family"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Role         string `json:"role,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Detail       string `json:"detail,omitempty"`
	Route        string `json:"route,omitempty"`
	ClusterID    string `json:"cluster_id,omitempty"`
	Blocking     bool   `json:"blocking"`
	LastModified string `json:"last_modified,omitempty"`
}

type groupUsageCoverageDTO struct {
	Family string `json:"family"`
	Status string `json:"status"` // covered | derived | not_modeled
	Detail string `json:"detail"`
}

type groupUsageSummaryDTO struct {
	TotalReferences    int  `json:"total_references"`
	BlockingReferences int  `json:"blocking_references"`
	NetworkRules       int  `json:"network_rules"`
	DPISensorBindings  int  `json:"dpi_sensor_bindings"`
	ProcessProfiles    int  `json:"process_profiles"`
	FileProfiles       int  `json:"file_profiles"`
	ResponseRules      int  `json:"response_rules"`
	AdmissionRules     int  `json:"admission_rules"`
	DerivedReferences  int  `json:"derived_references"`
	MemberTargets      int  `json:"member_targets"`
	DeleteBlocked      bool `json:"delete_blocked"`
}

type groupUsageDTO struct {
	GroupID    string                   `json:"group_id"`
	GroupName  string                   `json:"group_name"`
	Summary    groupUsageSummaryDTO     `json:"summary"`
	References []groupUsageReferenceDTO `json:"references"`
	Coverage   []groupUsageCoverageDTO  `json:"coverage"`
}

// Usage returns the concrete policy/profile objects that reference a group.
// NeuVector operators use the group detail page as their "what will this affect?"
// surface; this endpoint gives the UI that map without guessing client-side.
func (h *Groups) Usage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	var name string
	var membersRaw []byte
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT name, members
  FROM groups
 WHERE id = $1
   AND org_id = $2
   AND ($3::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $3)`,
		id, subj.OrgID, clusterArg).Scan(&name, &membersRaw); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	members := []string{}
	_ = json.Unmarshal(membersRaw, &members)
	members = normalizeGroupMembers(members)

	refs := []groupUsageReferenceDTO{}
	networkRefs, err := h.groupNetworkEdgeUsage(r, subj.OrgID, clusterArg, name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	refs = append(refs, networkRefs...)
	dpiRefs, err := h.groupDPIBindingUsage(r, subj.OrgID, clusterArg, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	refs = append(refs, dpiRefs...)
	responseRefs, err := h.groupResponseRuleUsage(r, subj.OrgID, clusterArg, id, name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	refs = append(refs, responseRefs...)
	admissionRefs, err := h.groupAdmissionRuleUsage(r.Context(), subj.OrgID, clusterArg, id, name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	refs = append(refs, admissionRefs...)
	profileRefs, err := h.groupMemberProfileUsage(r, subj.OrgID, clusterArg, members)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	refs = append(refs, profileRefs...)

	summary := groupUsageSummaryDTO{TotalReferences: len(refs), MemberTargets: len(members)}
	for _, ref := range refs {
		if ref.Blocking {
			summary.BlockingReferences++
		} else {
			summary.DerivedReferences++
		}
		switch ref.Family {
		case "network":
			summary.NetworkRules++
		case "dpi":
			summary.DPISensorBindings++
		case "process":
			summary.ProcessProfiles++
		case "file":
			summary.FileProfiles++
		case "response":
			summary.ResponseRules++
		case "admission":
			summary.AdmissionRules++
		}
	}
	summary.DeleteBlocked = summary.BlockingReferences > 0

	writeJSON(w, http.StatusOK, groupUsageDTO{
		GroupID:    id.String(),
		GroupName:  name,
		Summary:    summary,
		References: refs,
		Coverage:   groupUsageCoverage(members),
	})
}

func (h *Groups) groupNetworkEdgeUsage(r *http.Request, orgID uuid.UUID, clusterArg any, groupName string) ([]groupUsageReferenceDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, cluster_id::text, from_group, to_group, mode, comment, updated_at::text
  FROM group_rule_edges
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND (from_group = $3 OR to_group = $3)
 ORDER BY updated_at DESC`, orgID, clusterArg, groupName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []groupUsageReferenceDTO{}
	for rows.Next() {
		var id, clusterID, fromGroup, toGroup, mode, comment, updatedAt string
		if err := rows.Scan(&id, &clusterID, &fromGroup, &toGroup, &mode, &comment, &updatedAt); err != nil {
			return nil, err
		}
		role := "source"
		peer := toGroup
		if toGroup == groupName {
			role = "destination"
			peer = fromGroup
		}
		out = append(out, groupUsageReferenceDTO{
			ID:           id,
			Family:       "network",
			Kind:         "group-rule-edge",
			Name:         fmt.Sprintf("%s -> %s", fromGroup, toGroup),
			Role:         role,
			Mode:         mode,
			Detail:       firstNonEmpty(strings.TrimSpace(comment), "peer group "+peer),
			Route:        clusterRoute(clusterID, "network-rules"),
			ClusterID:    clusterID,
			Blocking:     true,
			LastModified: updatedAt,
		})
	}
	return out, rows.Err()
}

func (h *Groups) groupDPIBindingUsage(r *http.Request, orgID uuid.UUID, clusterArg any, groupID uuid.UUID) ([]groupUsageReferenceDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT b.id::text,
       COALESCE(ds.cluster_id::text, wg.cluster_id::text, '') AS cluster_id,
       b.sensor_kind,
       b.sensor_id::text,
       COALESCE(ds.name, wg.name, b.sensor_id::text) AS sensor_name,
       b.created_at::text
  FROM group_dpi_sensor_bindings b
  LEFT JOIN dlp_sensors ds
    ON b.sensor_kind = 'dlp'
   AND ds.id = b.sensor_id
   AND ds.org_id = b.org_id
  LEFT JOIN waf_groups wg
    ON b.sensor_kind = 'waf'
   AND wg.id = b.sensor_id
   AND wg.org_id = b.org_id
 WHERE b.org_id = $1
   AND b.group_id = $2
   AND ($3::uuid IS NULL OR COALESCE(ds.cluster_id, wg.cluster_id) IS NULL OR COALESCE(ds.cluster_id, wg.cluster_id) = $3)
 ORDER BY b.created_at DESC`, orgID, groupID, clusterArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []groupUsageReferenceDTO{}
	for rows.Next() {
		var id, clusterID, kind, sensorID, sensorName, createdAt string
		if err := rows.Scan(&id, &clusterID, &kind, &sensorID, &sensorName, &createdAt); err != nil {
			return nil, err
		}
		route := "runtime-dlp"
		if kind == "waf" {
			route = "runtime-signatures"
		}
		out = append(out, groupUsageReferenceDTO{
			ID:           id,
			Family:       "dpi",
			Kind:         kind + "-sensor-binding",
			Name:         sensorName,
			Role:         "scope",
			Detail:       kind + " sensor " + sensorID,
			Route:        clusterRoute(clusterID, route),
			ClusterID:    clusterID,
			Blocking:     true,
			LastModified: createdAt,
		})
	}
	return out, rows.Err()
}

func (h *Groups) groupResponseRuleUsage(r *http.Request, orgID uuid.UUID, clusterArg any, groupID uuid.UUID, groupName string) ([]groupUsageReferenceDTO, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, COALESCE(cluster_id::text, '') AS cluster_id, name, event_type, enabled, updated_at::text
  FROM response_rules_v2
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
   AND (workload_match->>'group' = $3 OR workload_match->>'group' = $4)
 ORDER BY updated_at DESC`, orgID, clusterArg, groupName, groupID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []groupUsageReferenceDTO{}
	for rows.Next() {
		var id, clusterID, name, eventType, updatedAt string
		var enabled bool
		if err := rows.Scan(&id, &clusterID, &name, &eventType, &enabled, &updatedAt); err != nil {
			return nil, err
		}
		mode := eventType
		if !enabled {
			mode = eventType + " disabled"
		}
		out = append(out, groupUsageReferenceDTO{
			ID:           id,
			Family:       "response",
			Kind:         "response-rule-v2",
			Name:         name,
			Role:         "workload-selector",
			Mode:         mode,
			Detail:       "workload group " + groupName,
			Route:        clusterRoute(clusterID, "response-rules"),
			ClusterID:    clusterID,
			Blocking:     true,
			LastModified: updatedAt,
		})
	}
	return out, rows.Err()
}

func (h *Groups) groupAdmissionRuleUsage(ctx context.Context, orgID uuid.UUID, clusterArg any, groupID uuid.UUID, groupName string) ([]groupUsageReferenceDTO, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id::text,
       COALESCE(cluster_id::text, '') AS cluster_id,
       name,
       mode,
       enabled,
       updated_at::text,
       COALESCE(spec_yaml, '') AS spec_yaml
  FROM policies
 WHERE org_id = $1
   AND engine = 'constellation-admission'
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
 ORDER BY updated_at DESC`, orgID, clusterArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []groupUsageReferenceDTO{}
	for rows.Next() {
		var id, clusterID, name, mode, updatedAt, specYAML string
		var enabled bool
		if err := rows.Scan(&id, &clusterID, &name, &mode, &enabled, &updatedAt, &specYAML); err != nil {
			return nil, err
		}
		if !admissionRuleReferencesGroup(specYAML, groupID, groupName) {
			continue
		}
		displayMode := mode
		if !enabled {
			displayMode = mode + " disabled"
		}
		out = append(out, groupUsageReferenceDTO{
			ID:           id,
			Family:       "admission",
			Kind:         "admission-rule",
			Name:         name,
			Role:         "match-group",
			Mode:         displayMode,
			Detail:       "match group " + groupName,
			Route:        clusterRoute(clusterID, "admission"),
			ClusterID:    clusterID,
			Blocking:     true,
			LastModified: updatedAt,
		})
	}
	return out, rows.Err()
}

func (h *Groups) groupMemberProfileUsage(r *http.Request, orgID uuid.UUID, clusterArg any, members []string) ([]groupUsageReferenceDTO, error) {
	if len(members) == 0 {
		return []groupUsageReferenceDTO{}, nil
	}
	rows, err := h.db.Pool().Query(r.Context(), `
WITH member_workloads AS (
    SELECT DISTINCT workload_id
      FROM unnest($3::text[]) AS member(workload_id)
     WHERE TRIM(workload_id) <> ''
),
profile_refs AS (
    SELECT s.id::text AS id,
           'process' AS family,
           'process-baseline-state' AS kind,
           s.workload_id AS name,
           'member' AS role,
           s.mode AS mode,
           s.namespace || '/' || s.name || ' baseline lifecycle' AS detail,
           s.cluster_id::text AS cluster_id,
           s.workload_id,
           s.updated_at::text AS last_modified,
           s.updated_at AS sort_at
      FROM process_baseline_states s
      JOIN member_workloads m ON m.workload_id = s.workload_id
     WHERE s.org_id = $1
       AND ($2::uuid IS NULL OR s.cluster_id = $2)
    UNION ALL
    SELECT r.id::text AS id,
           'process' AS family,
           'process-profile-rule' AS kind,
           r.name AS name,
           'member' AS role,
           r.action AS mode,
           COALESCE(NULLIF(TRIM(r.description), ''), 'workload ' || r.workload_id || CASE WHEN r.path <> '' THEN ' path ' || r.path ELSE '' END) AS detail,
           r.cluster_id::text AS cluster_id,
           r.workload_id,
           r.updated_at::text AS last_modified,
           r.updated_at AS sort_at
      FROM process_profile_rules r
      JOIN member_workloads m ON m.workload_id = r.workload_id
     WHERE r.org_id = $1
       AND ($2::uuid IS NULL OR r.cluster_id = $2)
    UNION ALL
    SELECT s.id::text AS id,
           'file' AS family,
           'file-profile-state' AS kind,
           s.workload_id AS name,
           'member' AS role,
           s.mode AS mode,
           s.namespace || '/' || s.name || ' file-monitor lifecycle' AS detail,
           s.cluster_id::text AS cluster_id,
           s.workload_id,
           s.updated_at::text AS last_modified,
           s.updated_at AS sort_at
      FROM file_profile_states s
      JOIN member_workloads m ON m.workload_id = s.workload_id
     WHERE s.org_id = $1
       AND ($2::uuid IS NULL OR s.cluster_id = $2)
    UNION ALL
    SELECT r.id::text AS id,
           'file' AS family,
           'file-profile-rule' AS kind,
           r.filter AS name,
           'member' AS role,
           r.behavior AS mode,
           COALESCE(NULLIF(TRIM(r.description), ''), 'workload ' || r.workload_id || ' path ' || r.path) AS detail,
           r.cluster_id::text AS cluster_id,
           r.workload_id,
           r.updated_at::text AS last_modified,
           r.updated_at AS sort_at
      FROM file_profile_rules r
      JOIN member_workloads m ON m.workload_id = r.workload_id
     WHERE r.org_id = $1
       AND ($2::uuid IS NULL OR r.cluster_id = $2)
    UNION ALL
    SELECT e.id::text AS id,
           'file' AS family,
           'file-profile-exception' AS kind,
           e.filter AS name,
           'member' AS role,
           CASE WHEN e.enabled THEN 'enabled' ELSE 'disabled' END AS mode,
           COALESCE(NULLIF(TRIM(e.description), ''), 'workload ' || e.workload_id || ' exception for ' || e.path) AS detail,
           e.cluster_id::text AS cluster_id,
           e.workload_id,
           e.updated_at::text AS last_modified,
           e.updated_at AS sort_at
      FROM file_profile_exceptions e
      JOIN member_workloads m ON m.workload_id = e.workload_id
     WHERE e.org_id = $1
       AND ($2::uuid IS NULL OR e.cluster_id = $2)
)
SELECT id, family, kind, name, role, mode, detail, cluster_id, workload_id, last_modified
  FROM profile_refs
 ORDER BY sort_at DESC, family, kind, name`, orgID, clusterArg, members)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []groupUsageReferenceDTO{}
	for rows.Next() {
		var id, family, kind, name, role, mode, detail, clusterID, workloadID, updatedAt string
		if err := rows.Scan(&id, &family, &kind, &name, &role, &mode, &detail, &clusterID, &workloadID, &updatedAt); err != nil {
			return nil, err
		}
		out = append(out, groupUsageReferenceDTO{
			ID:           id,
			Family:       family,
			Kind:         kind,
			Name:         name,
			Role:         role,
			Mode:         mode,
			Detail:       detail,
			Route:        groupProfileRoute(clusterID, family, workloadID),
			ClusterID:    clusterID,
			Blocking:     false,
			LastModified: updatedAt,
		})
	}
	return out, rows.Err()
}

func normalizeGroupMembers(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, member := range in {
		member = strings.TrimSpace(member)
		if member == "" {
			continue
		}
		if _, ok := seen[member]; ok {
			continue
		}
		seen[member] = struct{}{}
		out = append(out, member)
	}
	return out
}

func (h *Groups) groupBlockingReferenceCount(ctx context.Context, orgID uuid.UUID, clusterArg any, groupID uuid.UUID, groupName string) (int, error) {
	total := 0
	var networkCount int
	if err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*)
  FROM group_rule_edges
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND (from_group = $3 OR to_group = $3)`, orgID, clusterArg, groupName).Scan(&networkCount); err != nil {
		return 0, err
	}
	total += networkCount
	var dpiCount int
	if err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*)
  FROM group_dpi_sensor_bindings
 WHERE org_id = $1
   AND group_id = $2`, orgID, groupID).Scan(&dpiCount); err != nil {
		return 0, err
	}
	total += dpiCount
	var responseCount int
	if err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*)
  FROM response_rules_v2
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
   AND (workload_match->>'group' = $3 OR workload_match->>'group' = $4)`,
		orgID, clusterArg, groupName, groupID.String()).Scan(&responseCount); err != nil {
		return 0, err
	}
	total += responseCount
	admissionRefs, err := h.groupAdmissionRuleUsage(ctx, orgID, clusterArg, groupID, groupName)
	if err != nil {
		return 0, err
	}
	total += len(admissionRefs)
	return total, nil
}

func groupUsageCoverage(members []string) []groupUsageCoverageDTO {
	return []groupUsageCoverageDTO{
		{Family: "Network rules", Status: "covered", Detail: "Group-to-group rule edges are explicit references and block delete."},
		{Family: "DLP/WAF bindings", Status: "covered", Detail: "Group-to-sensor bindings are explicit references and block delete."},
		{Family: "Response rules", Status: "covered", Detail: "Response-rule workload group selectors are explicit references and block delete."},
		{Family: "Admission", Status: "covered", Detail: "Admission rule match.groups selectors are explicit references and block delete."},
		{Family: "Process profiles", Status: "derived", Detail: fmt.Sprintf("Process baseline state and authored process rules are shown for %d current member workload(s); they do not block group delete.", len(members))},
		{Family: "File profiles and exceptions", Status: "derived", Detail: fmt.Sprintf("File-monitor state, rules, and exceptions are shown for %d current member workload(s); they do not block group delete.", len(members))},
	}
}

func admissionRuleReferencesGroup(specYAML string, groupID uuid.UUID, groupName string) bool {
	for _, selector := range admissionRuleGroups(specYAML) {
		if selector == groupID.String() || selector == groupName || strings.EqualFold(selector, groupName) {
			return true
		}
	}
	return false
}

func admissionRuleGroups(specYAML string) []string {
	if strings.TrimSpace(specYAML) == "" {
		return nil
	}
	var doc struct {
		Spec struct {
			Match struct {
				Groups []string `yaml:"groups"`
			} `yaml:"match"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(specYAML), &doc); err != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Spec.Match.Groups))
	for _, selector := range doc.Spec.Match.Groups {
		if selector = strings.TrimSpace(selector); selector != "" {
			out = append(out, selector)
		}
	}
	return out
}

func groupProfileRoute(clusterID, family, workloadID string) string {
	if family == "process" {
		return clusterRoute(clusterID, "runtime/baselines/"+url.PathEscape(workloadID))
	}
	return clusterRoute(clusterID, "file-monitor") + "?workload=" + url.QueryEscape(workloadID)
}

func clusterRoute(clusterID, path string) string {
	if strings.TrimSpace(clusterID) == "" {
		return "/" + path
	}
	return "/clusters/" + clusterID + "/" + path
}
