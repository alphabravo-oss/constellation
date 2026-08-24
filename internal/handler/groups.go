package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/netutil"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/group"
)

type Groups struct {
	db       *db.DB
	auditLog *audit.Logger
}

func NewGroups(d *db.DB, a *audit.Logger) *Groups {
	return &Groups{db: d, auditLog: a}
}

type groupDTO struct {
	ID          uuid.UUID          `json:"id"`
	Name        string             `json:"name"`
	Kind        group.Kind         `json:"kind"`
	Comment     string             `json:"comment"`
	Criteria    []group.Criterion  `json:"criteria"`
	Members     []string           `json:"members"`
	LearnedFrom string             `json:"learned_from"`
	CfgType     string             `json:"cfg_type"`
	PolicyMode  group.Mode         `json:"policy_mode"`
	ProfileMode group.Mode         `json:"profile_mode"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	Membership  groupMembershipDTO `json:"membership"`
}

type groupMembershipDTO struct {
	CriteriaCount     int        `json:"criteria_count"`
	MemberCount       int        `json:"member_count"`
	PolicyMode        group.Mode `json:"policy_mode"`
	ProfileMode       group.Mode `json:"profile_mode"`
	LastMatchedAt     *time.Time `json:"last_matched_at,omitempty"`
	LastMatchedMember string     `json:"last_matched_member,omitempty"`
}

type groupBody struct {
	Name        string            `json:"name"`
	Kind        group.Kind        `json:"kind"`
	Comment     string            `json:"comment"`
	Criteria    []group.Criterion `json:"criteria"`
	Members     []string          `json:"members"`
	LearnedFrom string            `json:"learned_from"`
	CfgType     string            `json:"cfg_type"`
	PolicyMode  group.Mode        `json:"policy_mode"`
	ProfileMode group.Mode        `json:"profile_mode"`
}

// computeMembers loads the org's deployments (optionally cluster-scoped) and
// returns the workload ids matching g's criteria — server-side membership so
// client-supplied members are never trusted (NeuVector treats members as a
// derived cache of the criteria).
func (h *Groups) computeMembers(r *http.Request, orgID uuid.UUID, clusterArg any, g *group.Group) ([]string, error) {
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT namespace, name, labels
  FROM deployments
 WHERE org_id=$1 AND ($2::uuid IS NULL OR cluster_id = $2)`, orgID, clusterArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wls []group.Workload
	for rows.Next() {
		var ns, name string
		var labels []byte
		if err := rows.Scan(&ns, &name, &labels); err != nil {
			continue
		}
		lm := map[string]string{}
		_ = json.Unmarshal(labels, &lm)
		wls = append(wls, group.Workload{ID: ns + "/" + name, Namespace: ns, Labels: lm})
	}
	return g.ComputeMembers(wls), nil
}

// baselineModeForGroupMode maps a group profile_mode to the process-baseline
// mode vocabulary: discover->learn, monitor->monitor, protect->enforce. Empty
// when the group mode is unset/invalid (caller skips propagation).
func baselineModeForGroupMode(m group.Mode) string {
	switch m {
	case group.ModeDiscover:
		return "learn"
	case group.ModeMonitor:
		return "monitor"
	case group.ModeProtect:
		return "enforce"
	}
	return ""
}

// propagateGroupProfileMode sets each member workload's process-baseline mode to
// match the group's profile_mode — the NeuVector model where the group is the
// control point that drives member enforcement. Cluster-scoped only. The process
// enforcer is opt-in (default OFF), so this updates the recorded mode without
// killing anything until the agent flag is enabled.
func (h *Groups) propagateGroupProfileMode(ctx context.Context, orgID, clusterID uuid.UUID, members []string, gmode group.Mode) error {
	bmode := baselineModeForGroupMode(gmode)
	if bmode == "" || len(members) == 0 {
		return nil
	}
	for _, wid := range members {
		ns, name := netutil.SplitWorkload(wid)
		if _, err := h.db.Pool().Exec(ctx, `
INSERT INTO process_baseline_states (org_id, cluster_id, workload_id, namespace, name, mode,
       learn_started_at, monitor_started_at, enforce_started_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6, NOW(),
        CASE WHEN $6 IN ('monitor','enforce') THEN NOW() END,
        CASE WHEN $6 = 'enforce' THEN NOW() END, NOW())
ON CONFLICT (org_id, cluster_id, workload_id) DO UPDATE SET
       mode = EXCLUDED.mode,
       monitor_started_at = CASE WHEN $6 IN ('monitor','enforce')
              THEN COALESCE(process_baseline_states.monitor_started_at, NOW())
              ELSE process_baseline_states.monitor_started_at END,
       enforce_started_at = CASE WHEN $6 = 'enforce'
              THEN COALESCE(process_baseline_states.enforce_started_at, NOW())
              ELSE process_baseline_states.enforce_started_at END,
       updated_at = NOW()`,
			orgID, clusterID, wid, ns, name, bmode); err != nil {
			return err
		}
	}
	return nil
}

// maybePropagateGroupMode propagates profile_mode to members when the group is
// cluster-scoped. Best-effort: a failure is logged, not fatal to the group write.
func (h *Groups) maybePropagateGroupMode(ctx context.Context, orgID uuid.UUID, clusterArg any, members []string, gmode group.Mode) {
	cid, ok := clusterArg.(uuid.UUID)
	if !ok {
		return // org-wide group: cross-cluster propagation is ambiguous, skip
	}
	if err := h.propagateGroupProfileMode(ctx, orgID, cid, members, gmode); err != nil {
		slog.Default().Warn("group profile_mode propagation failed",
			slog.String("cluster", cid.String()), slog.String("err", err.Error()))
	}
}

func (h *Groups) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, name, kind, comment, criteria, members, learned_from, cfg_type, policy_mode, profile_mode, created_at, updated_at
  FROM groups
 WHERE org_id=$1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
 ORDER BY name`, subj.OrgID, clusterArg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []groupDTO{}
	for rows.Next() {
		var d groupDTO
		var criteria, members []byte
		if err := rows.Scan(&d.ID, &d.Name, &d.Kind, &d.Comment, &criteria, &members,
			&d.LearnedFrom, &d.CfgType, &d.PolicyMode, &d.ProfileMode, &d.CreatedAt, &d.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_ = json.Unmarshal(criteria, &d.Criteria)
		_ = json.Unmarshal(members, &d.Members)
		d.Membership = groupMembershipDTO{
			CriteriaCount: len(d.Criteria),
			MemberCount:   len(d.Members),
			PolicyMode:    d.PolicyMode,
			ProfileMode:   d.ProfileMode,
		}
		out = append(out, d)
	}
	if err := h.attachMembershipPreviews(r.Context(), subj.OrgID, clusterArg, out); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (h *Groups) attachMembershipPreviews(ctx context.Context, orgID uuid.UUID, clusterArg any, groups []groupDTO) error {
	if len(groups) == 0 {
		return nil
	}
	rows, err := h.db.Pool().Query(ctx, `
SELECT namespace, name, MAX(last_seen_at)
  FROM deployments
 WHERE org_id=$1 AND ($2::uuid IS NULL OR cluster_id = $2)
 GROUP BY namespace, name`, orgID, clusterArg)
	if err != nil {
		return err
	}
	defer rows.Close()
	type seen struct {
		member string
		at     time.Time
	}
	seenByMember := map[string]seen{}
	for rows.Next() {
		var namespace, name string
		var lastSeen time.Time
		if err := rows.Scan(&namespace, &name, &lastSeen); err != nil {
			return err
		}
		member := namespace + "/" + name
		seenByMember[member] = seen{member: member, at: lastSeen}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range groups {
		groups[i].Membership.CriteriaCount = len(groups[i].Criteria)
		groups[i].Membership.MemberCount = len(groups[i].Members)
		groups[i].Membership.PolicyMode = groups[i].PolicyMode
		groups[i].Membership.ProfileMode = groups[i].ProfileMode
		var latest *seen
		for _, member := range groups[i].Members {
			candidate, ok := seenByMember[member]
			if !ok {
				continue
			}
			if latest == nil || candidate.at.After(latest.at) {
				next := candidate
				latest = &next
			}
		}
		if latest != nil {
			at := latest.at
			groups[i].Membership.LastMatchedAt = &at
			groups[i].Membership.LastMatchedMember = latest.member
		}
	}
	return nil
}

// serviceModeDefaults returns the cluster's configured new-service default modes (NV
// NewServiceMode), or monitor/monitor when unset. Keyed the same as the policy handler.
func (h *Groups) serviceModeDefaults(ctx context.Context, orgID, clusterID uuid.UUID) (policyMode, profileMode string) {
	policyMode, profileMode = "monitor", "monitor"
	_ = h.db.Pool().QueryRow(ctx,
		`SELECT policy_mode, profile_mode FROM service_mode_defaults WHERE org_id = $1 AND cluster_id = $2`,
		orgID, clusterID).Scan(&policyMode, &profileMode)
	return
}

func (h *Groups) Create(w http.ResponseWriter, r *http.Request) {
	var body groupBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Seed unspecified modes from the cluster's new-service default (NV NewServiceMode).
	// A caller that supplies an explicit mode always wins; only blank fields inherit.
	if body.PolicyMode == "" || body.ProfileMode == "" {
		if cid, ok := clusterArg.(uuid.UUID); ok {
			dp, dpr := h.serviceModeDefaults(r.Context(), subj.OrgID, cid)
			if body.PolicyMode == "" {
				body.PolicyMode = group.Mode(dp)
			}
			if body.ProfileMode == "" {
				body.ProfileMode = group.Mode(dpr)
			}
		}
	}
	g := &group.Group{Name: strings.TrimSpace(body.Name), Kind: body.Kind,
		Comment: body.Comment, Criteria: body.Criteria, LearnedFrom: body.LearnedFrom,
		CfgType: body.CfgType, PolicyMode: body.PolicyMode, ProfileMode: body.ProfileMode}
	if g.CfgType == "" {
		g.CfgType = "user"
	}
	if err := g.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Members are server-computed from criteria against current deployments;
	// client-supplied members are ignored (NeuVector derives membership).
	memberIDs, err := h.computeMembers(r, subj.OrgID, clusterArg, g)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	criteria, _ := json.Marshal(body.Criteria)
	members, _ := json.Marshal(memberIDs)
	var id uuid.UUID
	if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO groups (org_id, cluster_id, name, kind, comment, criteria, members, learned_from, cfg_type, policy_mode, profile_mode, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		subj.OrgID, clusterArg, g.Name, g.Kind, g.Comment, criteria, members, g.LearnedFrom, g.CfgType, g.PolicyMode, g.ProfileMode, subj.UserID).Scan(&id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// NeuVector model: the group drives member enforcement. Push profile_mode
	// down to member workloads' process-baseline mode (cluster-scoped groups).
	h.maybePropagateGroupMode(r.Context(), subj.OrgID, clusterArg, memberIDs, g.ProfileMode)
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "group.create", TargetKind: "group", TargetID: id.String()})
	logFedRevision(r.Context(), h.db.Pool(), oid, "group", id.String(), fedSyncPayload{
		OrgID: oid, Name: g.Name, Comment: g.Comment, Criteria: json.RawMessage(criteria)})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (h *Groups) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	var body groupBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	g := &group.Group{Name: strings.TrimSpace(body.Name), Kind: body.Kind, Comment: body.Comment,
		Criteria: body.Criteria, LearnedFrom: body.LearnedFrom, CfgType: body.CfgType,
		PolicyMode: body.PolicyMode, ProfileMode: body.ProfileMode}
	if err := g.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	// Fed (master-authored) groups are read-only on a joint; reject local edits so
	// they cannot drift from the master before the next sync overwrites them.
	if isFed, err := groupIsFed(r.Context(), h.db.Pool(), id, subj.OrgID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	} else if isFed {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": errFedReadOnly.Error()})
		return
	}
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var currentName, currentLearnedFrom, currentCfgType string
	var currentKind group.Kind
	var currentCriteriaRaw, currentMembersRaw []byte
	if err := h.db.Pool().QueryRow(r.Context(), `
SELECT name, kind, criteria, members, learned_from, cfg_type
  FROM groups
 WHERE id=$1
   AND org_id=$2
   AND ($3::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $3)`,
		id, subj.OrgID, clusterArg).Scan(&currentName, &currentKind, &currentCriteriaRaw, &currentMembersRaw, &currentLearnedFrom, &currentCfgType); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var currentMembers []string
	_ = json.Unmarshal(currentMembersRaw, &currentMembers)
	memberIDs := normalizeGroupMembers(currentMembers)
	changedFields := groupReferenceSensitiveChanges(currentName, currentKind, currentCriteriaRaw, currentLearnedFrom, currentCfgType, g)
	if stringSetContains(changedFields, "criteria") {
		memberIDs, err = h.computeMembers(r, subj.OrgID, clusterArg, g)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		memberIDs = normalizeGroupMembers(memberIDs)
		if (&group.Group{Members: normalizeGroupMembers(currentMembers)}).MembersChanged(memberIDs) {
			changedFields = append(changedFields, "members")
		}
	}
	if len(changedFields) > 0 {
		blockingRefs, err := h.groupBlockingReferenceCount(r.Context(), subj.OrgID, clusterArg, id, currentName)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if blockingRefs > 0 {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":               "group has policy references",
				"blocking_references": blockingRefs,
				"changed_fields":      changedFields,
			})
			return
		}
	}
	criteria, _ := json.Marshal(body.Criteria)
	members, _ := json.Marshal(memberIDs)
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE groups SET name=$1, kind=$2, comment=$3, criteria=$4, members=$5, learned_from=$6, cfg_type=$7, policy_mode=$8, profile_mode=$9, updated_at=NOW()
 WHERE id=$10 AND org_id=$11`,
		g.Name, body.Kind, body.Comment, criteria, members, body.LearnedFrom, body.CfgType, g.PolicyMode, g.ProfileMode, id, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	h.maybePropagateGroupMode(r.Context(), subj.OrgID, clusterArg, memberIDs, g.ProfileMode)
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "group.update", TargetKind: "group", TargetID: id.String()})
	logFedRevision(r.Context(), h.db.Pool(), oid, "group", id.String(), fedSyncPayload{
		OrgID: oid, Name: g.Name, Comment: body.Comment, Criteria: json.RawMessage(criteria)})
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func groupReferenceSensitiveChanges(currentName string, currentKind group.Kind, currentCriteriaRaw []byte, currentLearnedFrom, currentCfgType string, next *group.Group) []string {
	changes := []string{}
	if currentName != strings.TrimSpace(next.Name) {
		changes = append(changes, "name")
	}
	if currentKind != next.Kind {
		changes = append(changes, "kind")
	}
	if currentLearnedFrom != next.LearnedFrom {
		changes = append(changes, "learned_from")
	}
	if currentCfgType != next.CfgType {
		changes = append(changes, "cfg_type")
	}
	var currentCriteria []group.Criterion
	if err := json.Unmarshal(currentCriteriaRaw, &currentCriteria); err != nil || !reflect.DeepEqual(normalizeGroupCriteria(currentCriteria), normalizeGroupCriteria(next.Criteria)) {
		changes = append(changes, "criteria")
	}
	return changes
}

func stringSetContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func normalizeGroupCriteria(in []group.Criterion) []group.Criterion {
	out := make([]group.Criterion, len(in))
	copy(out, in)
	for i := range out {
		if out[i].Op == "" {
			out[i].Op = group.OpEq
		}
	}
	return out
}

func (h *Groups) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	// Capture name + fed status before deleting: reject local deletes of fed rows,
	// and emit a delete tombstone for master-owned ones so joints drop their copy.
	var name, cfgType string
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT name, cfg_type FROM groups WHERE id=$1 AND org_id=$2`, id, subj.OrgID).
		Scan(&name, &cfgType); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if cfgType == "fed" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": errFedReadOnly.Error()})
		return
	}
	blockingRefs, err := h.groupBlockingReferenceCount(r.Context(), subj.OrgID, nil, id, name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if blockingRefs > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":               "group has policy references",
			"blocking_references": blockingRefs,
		})
		return
	}
	if _, err := h.db.Pool().Exec(r.Context(), `DELETE FROM groups WHERE id=$1 AND org_id=$2`, id, subj.OrgID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "group.delete", TargetKind: "group", TargetID: id.String()})
	// G3a: propagate the deletion to joints via a tombstone revision (master only).
	logFedRevision(r.Context(), h.db.Pool(), oid, "group_delete", id.String(), fedSyncPayload{OrgID: oid, Name: name})
	writeJSON(w, http.StatusNoContent, nil)
}
