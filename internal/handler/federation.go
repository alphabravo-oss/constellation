package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/federation"
)

// fedPollInterval is the joint poll cadence the master assumes when deriving a
// member's liveness from its last_sync_at age. It mirrors ReconcileFedSyncLoop's
// default interval.
const fedPollInterval = 60 * time.Second

type Federation struct {
	db       *db.DB
	auditLog *audit.Logger
	// D1 trust handshake: the dedicated fed signing key + join knobs. nil signer leaves
	// the mint/join/sync-credential surface disabled. Wired via WithFedTrust.
	fedSigner *auth.FedSigner
	joinCfg   FedJoinConfig
	// D2 per-joint mTLS: the federation CA that mints per-joint client certs at join and
	// anchors verification on /sync. nil leaves the bearer-only path. Wired via WithFedCA.
	fedCA *auth.FedCA
}

func NewFederation(d *db.DB, a *audit.Logger) *Federation {
	return &Federation{db: d, auditLog: a}
}

// State returns the current federation membership.
func (h *Federation) State(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	var m federation.Membership
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT state, master_id, cluster_name, revision, updated_at FROM federation_state WHERE org_id=$1`,
		subj.OrgID).Scan(&m.State, &m.MasterID, &m.ClusterName, &m.Revision, &m.UpdatedAt)
	if err == pgx.ErrNoRows {
		m = federation.Membership{State: federation.StateStandalone}
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, m)
}

type fedActionBody struct {
	Action      string `json:"action"` // promote | demote | join | leave
	MasterID    string `json:"master_id,omitempty"`
	ClusterName string `json:"cluster_name,omitempty"`
}

func (h *Federation) Transition(w http.ResponseWriter, r *http.Request) {
	var body fedActionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	// Load existing.
	var cur federation.Membership
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT state, master_id, cluster_name, revision FROM federation_state WHERE org_id=$1`,
		subj.OrgID).Scan(&cur.State, &cur.MasterID, &cur.ClusterName, &cur.Revision); err != nil && err != pgx.ErrNoRows {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	} else if err == pgx.ErrNoRows {
		cur.State = federation.StateStandalone
	}

	var next federation.Membership
	var err error
	switch body.Action {
	case "promote":
		next, err = federation.Promote(cur)
	case "demote":
		next, err = federation.Demote(cur)
	case "join":
		next, err = federation.Join(cur, body.MasterID, body.ClusterName)
	case "leave":
		next, err = federation.Leave(cur)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO federation_state (org_id, state, master_id, cluster_name, revision, updated_at)
VALUES ($1,$2,$3,$4,$5,NOW())
ON CONFLICT (org_id) DO UPDATE SET state=EXCLUDED.state, master_id=EXCLUDED.master_id,
       cluster_name=EXCLUDED.cluster_name, revision=EXCLUDED.revision, updated_at=NOW()`,
		subj.OrgID, next.State, next.MasterID, next.ClusterName, next.Revision); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Fed-teardown purge: leaving (joint→standalone) or demoting (master→standalone)
	// severs the federation link, so the master-authored cfg_type='fed' rows this org
	// holds become orphans — permanently uneditable (the read-only guards keep
	// rejecting local edits) with no master left to sync or tombstone them. Purge them
	// so they do not become zombies. Best-effort: a purge failure is logged via audit
	// below but must not fail the already-committed membership transition.
	if body.Action == "leave" || body.Action == "demote" {
		if err := PurgeFedRows(r.Context(), h.db.Pool(), subj.OrgID); err != nil {
			slog.Default().Warn("fed teardown purge failed",
				slog.String("org", subj.OrgID.String()),
				slog.String("action", body.Action), slog.String("err", err.Error()))
		}
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "federation." + body.Action, TargetKind: "federation",
		After: map[string]any{"state": next.State}})
	writeJSON(w, http.StatusOK, next)
}

// Members handlers
func (h *Federation) ListMembers(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, cluster_id, name, role, endpoint, status, last_sync_at, revision
  FROM fed_members WHERE org_id=$1 ORDER BY name`, subj.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	now := time.Now().UTC()
	out := []federation.Member{}
	for rows.Next() {
		var m federation.Member
		var lastSync *time.Time
		if err := rows.Scan(&m.ID, &m.ClusterID, &m.Name, &m.Role, &m.Endpoint, &m.Status, &lastSync, &m.Revision); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		// Derive a live status (active/stale/offline) from last_sync_at age, leaving
		// terminal states (kicked, never-synced pending) intact.
		var ls time.Time
		if lastSync != nil {
			ls = *lastSync
			m.LastSyncAt = *lastSync
		}
		m.Status = federation.DeriveStatus(m.Status, ls, now, fedPollInterval)
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": out})
}

func (h *Federation) AddMember(w http.ResponseWriter, r *http.Request) {
	var m federation.Member
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := m.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO fed_members (org_id, cluster_id, name, role, endpoint, status, revision)
VALUES ($1,$2,$3,$4,$5,COALESCE(NULLIF($6,''),'pending'),$7)
ON CONFLICT (org_id, cluster_id) DO UPDATE SET name=EXCLUDED.name, role=EXCLUDED.role,
       endpoint=EXCLUDED.endpoint, status=EXCLUDED.status, revision=EXCLUDED.revision`,
		subj.OrgID, m.ClusterID, m.Name, m.Role, m.Endpoint, m.Status, m.Revision); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "fed_member.add", TargetKind: "fed-member", TargetID: m.ClusterID})
	writeJSON(w, http.StatusCreated, m)
}

// KickMember ejects a joint: the master sets its status to 'kicked' so subsequent
// /sync polls are rejected, and tombstones the fed rows replicated to it by clearing
// its consumed revision so it stops at zero. Mirrors NeuVector's CLUSEvFedKick.
// {id} is the fed_members.id (UUID) of the member to eject.
func (h *Federation) KickMember(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	id := chi.URLParam(r, "id")
	mid, err := uuid.Parse(id)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid member id"})
		return
	}
	var status, clusterID string
	if err := h.db.Pool().QueryRow(r.Context(),
		`SELECT status, cluster_id FROM fed_members WHERE org_id=$1 AND id=$2`,
		subj.OrgID, mid).Scan(&status, &clusterID); err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "member not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	next, err := federation.Kick(status)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	if _, err := h.db.Pool().Exec(r.Context(),
		`UPDATE fed_members SET status=$3, kicked_at=NOW() WHERE org_id=$1 AND id=$2`,
		subj.OrgID, mid, next); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// D1: revoke the kicked joint's per-cluster credential (bump epoch + tombstone) so its
	// already-issued sync ticket is rejected on the next poll — the DB-backed revocation
	// primitive (A1 parity) that complements the status='kicked' /sync guard. Best-effort:
	// a missing credential row (kicked before it ever joined) is a no-op.
	if err := RevokeFedCredential(r.Context(), h.db.Pool(), subj.OrgID, clusterID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "fed_member.kick", TargetKind: "fed-member", TargetID: clusterID,
		Before: map[string]any{"status": status}, After: map[string]any{"status": next}})
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": next})
}

// Sync returns rule revisions strictly greater than ?since=. Used by joints polling.
//
// A joint identifies itself with ?cluster_id=; the master treats each poll as a
// liveness heartbeat: it stamps that member's last_sync_at=now() and transitions a
// 'pending' member to 'active'. A member the master has kicked is rejected (403)
// so its future polls stop, mirroring NeuVector's CLUSEvFedKick.
func (h *Federation) Sync(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	// D1: when the request was authenticated by a per-cluster fed credential, the joint
	// identity is the AUTHENTICATED cluster id from the validated ticket — not a
	// caller-supplied ?cluster_id= (which a credential could otherwise spoof to heartbeat
	// as another member). Fall back to the query param for the legacy/un-migrated path.
	clusterID := r.URL.Query().Get("cluster_id")
	if p, ok := FedSyncPrincipalFrom(r.Context()); ok {
		clusterID = p.ClusterID
	}
	if clusterID != "" {
		// Kicked members are revoked: refuse the poll without leaking rule data.
		var status string
		err := h.db.Pool().QueryRow(r.Context(),
			`SELECT status FROM fed_members WHERE org_id=$1 AND cluster_id=$2`,
			subj.OrgID, clusterID).Scan(&status)
		if err == nil && status == federation.MemberStatusKicked {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "federation: member revoked"})
			return
		}
		// Heartbeat: stamp last_sync_at and activate a still-pending member. Scoped
		// away from kicked rows so a revoked member can never self-reactivate.
		_, _ = h.db.Pool().Exec(r.Context(), `
UPDATE fed_members
   SET last_sync_at=NOW(),
       status=CASE WHEN status='pending' THEN 'active' ELSE status END
 WHERE org_id=$1 AND cluster_id=$2 AND status<>'kicked'`,
			subj.OrgID, clusterID)
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT rule_kind, rule_id, revision, payload, updated_at
  FROM fed_rule_revisions WHERE org_id=$1 AND revision > $2
  ORDER BY revision ASC LIMIT 500`, subj.OrgID, since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []federation.RuleRevision{}
	for rows.Next() {
		var rev federation.RuleRevision
		if err := rows.Scan(&rev.Kind, &rev.RuleID, &rev.Revision, &rev.Payload, &rev.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, rev)
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": out, "since": since})
}
