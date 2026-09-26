package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/group"
)

// GitOps YAML portability for groups (NV parity — NeuVector exports/imports groups as YAML
// for config-as-code). Only the authored fields travel: name/kind/comment/criteria/modes.
// Members and ids are derived, so they are never exported and always recomputed on import.

type portableGroupCriterion struct {
	Key   string `yaml:"key" json:"key"`
	Op    string `yaml:"op" json:"op"`
	Value string `yaml:"value" json:"value"`
}

type portableGroup struct {
	Name        string                   `yaml:"name" json:"name"`
	Kind        string                   `yaml:"kind,omitempty" json:"kind,omitempty"`
	Comment     string                   `yaml:"comment,omitempty" json:"comment,omitempty"`
	PolicyMode  string                   `yaml:"policy_mode,omitempty" json:"policy_mode,omitempty"`
	ProfileMode string                   `yaml:"profile_mode,omitempty" json:"profile_mode,omitempty"`
	Criteria    []portableGroupCriterion `yaml:"criteria" json:"criteria"`
}

type groupBundle struct {
	APIVersion string          `yaml:"apiVersion" json:"apiVersion"`
	Kind       string          `yaml:"kind" json:"kind"`
	Groups     []portableGroup `yaml:"groups" json:"groups"`
}

// Export serializes the org's (optionally cluster-scoped) groups to a YAML bundle. Learned
// groups are excluded by default since they are re-synthesized from observed traffic; pass
// ?include_learned=1 to include them. GET /api/v1/groups:export
func (h *Groups) Export(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	includeLearned := r.URL.Query().Get("include_learned") == "1" || r.URL.Query().Get("include_learned") == "true"
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT name, kind, comment, criteria, policy_mode, profile_mode, cfg_type, learned_from
  FROM groups
 WHERE org_id=$1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
 ORDER BY name`, subj.OrgID, clusterArg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	bundle := groupBundle{APIVersion: "constellation/v1", Kind: "GroupBundle", Groups: []portableGroup{}}
	for rows.Next() {
		var name, kind, comment, policyMode, profileMode, cfgType, learnedFrom string
		var criteriaRaw []byte
		if err := rows.Scan(&name, &kind, &comment, &criteriaRaw, &policyMode, &profileMode, &cfgType, &learnedFrom); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if !includeLearned && (cfgType == "learned" || learnedFrom != "") {
			continue
		}
		var criteria []group.Criterion
		_ = json.Unmarshal(criteriaRaw, &criteria)
		pg := portableGroup{Name: name, Kind: kind, Comment: comment, PolicyMode: policyMode, ProfileMode: profileMode}
		for _, c := range criteria {
			pg.Criteria = append(pg.Criteria, portableGroupCriterion{Key: c.Key, Op: string(c.Op), Value: c.Value})
		}
		bundle.Groups = append(bundle.Groups, pg)
	}
	out, err := yaml.Marshal(bundle)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="constellation-groups.yaml"`)
	_, _ = w.Write(out)
}

// Import upserts groups from a YAML (or JSON) bundle, keyed by name. Members are recomputed
// from each group's criteria; ids/members in the payload are ignored. Returns a per-group
// summary. POST /api/v1/groups:import
func (h *Groups) Import(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	var bundle groupBundle
	if err := yaml.Unmarshal(raw, &bundle); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid bundle: " + err.Error()})
		return
	}
	if len(bundle.Groups) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bundle contains no groups"})
		return
	}
	type result struct {
		Name   string `json:"name"`
		Status string `json:"status"` // created | updated | error
		Error  string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(bundle.Groups))
	created, updated := 0, 0
	for _, pg := range bundle.Groups {
		res := result{Name: pg.Name}
		g := &group.Group{
			Name: strings.TrimSpace(pg.Name), Kind: group.Kind(orDefault(pg.Kind, "ground")),
			Comment: pg.Comment, CfgType: "user",
			PolicyMode: group.Mode(orDefault(pg.PolicyMode, "monitor")), ProfileMode: group.Mode(orDefault(pg.ProfileMode, "monitor")),
		}
		for _, c := range pg.Criteria {
			g.Criteria = append(g.Criteria, group.Criterion{Key: c.Key, Op: group.Op(orDefault(c.Op, "eq")), Value: c.Value})
		}
		if err := g.Validate(); err != nil {
			res.Status, res.Error = "error", err.Error()
			results = append(results, res)
			continue
		}
		memberIDs, err := h.computeMembers(r, subj.OrgID, clusterArg, g)
		if err != nil {
			res.Status, res.Error = "error", err.Error()
			results = append(results, res)
			continue
		}
		criteriaJSON, _ := json.Marshal(g.Criteria)
		membersJSON, _ := json.Marshal(memberIDs)
		wasInsert, err := h.importPortableGroup(r, subj.OrgID, subj.UserID, clusterArg, g, criteriaJSON, membersJSON)
		if err != nil {
			res.Status, res.Error = "error", err.Error()
			results = append(results, res)
			continue
		}
		h.maybePropagateGroupMode(r.Context(), subj.OrgID, clusterArg, memberIDs, g.ProfileMode)
		if wasInsert {
			res.Status = "created"
			created++
		} else {
			res.Status = "updated"
			updated++
		}
		results = append(results, res)
	}
	if h.auditLog != nil {
		oid, uid := subj.OrgID, subj.UserID
		_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
			Action: "group.import", TargetKind: "group", TargetID: "",
			After: map[string]any{"created": created, "updated": updated, "total": len(bundle.Groups)}})
	}
	writeJSON(w, http.StatusOK, map[string]any{"created": created, "updated": updated, "results": results})
}

func (h *Groups) importPortableGroup(r *http.Request, orgID, userID uuid.UUID, clusterArg any, groupValue *group.Group, criteriaJSON, membersJSON []byte) (bool, error) {
	if clusterID, ok := clusterArg.(uuid.UUID); ok {
		var owned bool
		if err := h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, clusterID, orgID).Scan(&owned); err != nil {
			return false, err
		}
		if !owned {
			return false, fmt.Errorf("cluster not found in organization")
		}
	}
	var groupID uuid.UUID
	err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO groups (org_id, cluster_id, name, kind, comment, criteria, members, cfg_type, policy_mode, profile_mode, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (org_id, name) DO NOTHING
RETURNING id`,
		orgID, clusterArg, groupValue.Name, groupValue.Kind, groupValue.Comment, criteriaJSON, membersJSON,
		groupValue.CfgType, groupValue.PolicyMode, groupValue.ProfileMode, userID).Scan(&groupID)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if err := h.db.Pool().QueryRow(r.Context(), `SELECT id FROM groups WHERE org_id=$1 AND name=$2`, orgID, groupValue.Name).Scan(&groupID); err != nil {
		return false, err
	}
	tx, err := h.beginGroupReferenceMutation(r.Context(), orgID, groupID)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(r.Context())
	var currentName, learnedFrom, cfgType string
	var currentClusterID *uuid.UUID
	var currentKind group.Kind
	var currentCriteria, currentMembers []byte
	if err := tx.QueryRow(r.Context(), `SELECT name, cluster_id, kind, criteria, members, learned_from, cfg_type FROM groups WHERE id=$1 AND org_id=$2`, groupID, orgID).
		Scan(&currentName, &currentClusterID, &currentKind, &currentCriteria, &currentMembers, &learnedFrom, &cfgType); err != nil {
		return false, err
	}
	if currentClusterID != nil {
		requestedClusterID, ok := clusterArg.(uuid.UUID)
		if !ok || requestedClusterID != *currentClusterID {
			return false, fmt.Errorf("group belongs to another cluster")
		}
	}
	if currentName != groupValue.Name {
		return false, fmt.Errorf("group changed during import; retry")
	}
	if cfgType == "fed" {
		return false, errFedReadOnly
	}
	next := *groupValue
	next.CfgType = cfgType
	next.LearnedFrom = learnedFrom
	changes := groupReferenceSensitiveChanges(currentName, currentKind, currentCriteria, learnedFrom, cfgType, &next)
	var previousMembers, nextMembers []string
	if err := json.Unmarshal(currentMembers, &previousMembers); err != nil {
		return false, err
	}
	if err := json.Unmarshal(membersJSON, &nextMembers); err != nil {
		return false, err
	}
	if (&group.Group{Members: normalizeGroupMembers(previousMembers)}).MembersChanged(normalizeGroupMembers(nextMembers)) {
		changes = append(changes, "members")
	}
	if len(changes) > 0 {
		blockingRefs, err := groupBlockingReferenceCount(r.Context(), tx, orgID, groupID, currentName)
		if err != nil {
			return false, err
		}
		if blockingRefs > 0 {
			return false, fmt.Errorf("group has %d policy references; unlink before importing changes", blockingRefs)
		}
	}
	if _, err := tx.Exec(r.Context(), `
UPDATE groups SET kind=$1, comment=$2, criteria=$3, members=$4,
  policy_mode=$5, profile_mode=$6, updated_at=NOW()
 WHERE id=$7 AND org_id=$8`,
		groupValue.Kind, groupValue.Comment, criteriaJSON, membersJSON, groupValue.PolicyMode, groupValue.ProfileMode,
		groupID, orgID); err != nil {
		return false, err
	}
	return false, tx.Commit(r.Context())
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
