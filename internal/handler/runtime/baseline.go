// Process Baseline handlers — Wave L4. Front of the learn → monitor → enforce
// lifecycle UI (NeuVector parity). Backed by pkg/runtime/baseline today; profiles
// are created from observed deployments and only gain process evidence from
// real runtime telemetry.
//
//	GET  /api/v1/runtime/baselines?cluster_id=&namespace=    list profiles
//	GET  /api/v1/runtime/baselines/{workload_id}             one profile + processes
//	POST /api/v1/runtime/baselines/{workload_id}/mode        transition (audit-logged)
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

// Baselines is the HTTP handler for the process baseline lifecycle page.
type Baselines struct {
	db       *db.DB
	auditLog *audit.Logger

	mu     sync.Mutex
	engine *baseline.Engine
	// state holds per-workload baseline metadata that pkg/runtime/baseline doesn't
	// keep (the UI needs mode-transition timestamps, alert/block counts in the
	// last 24h, and the full process list with first/last seen). Keyed on
	// "cluster_id::workload" so we never bleed across clusters.
	state map[string]*baselineState
}

// NewBaselines constructs the handler. The Engine is created up-front and reused
// for the lifetime of the process; lifecycle state is persisted when storage is
// available and only falls back to memory for storage-free tests.
func NewBaselines(d *db.DB, a *audit.Logger) *Baselines {
	h := &Baselines{
		db:       d,
		auditLog: a,
		engine:   baseline.NewEngine(),
		state:    map[string]*baselineState{},
	}
	// RT-DRIFT-50: rehydrate the in-memory baseline map (the ONLY source BaselineMode
	// consults on the runtime-drift hot path) from the DB at startup, so a fresh /
	// restarted API classifies drift immediately instead of staying blind until a
	// List/Get request happens to repopulate the workload. Best-effort, off the
	// request path; a missing table (pre-migration) is a no-op.
	if d != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = h.Hydrate(ctx)
		}()
	}
	return h
}

// Hydrate loads persisted process-baseline state (mode + learned process set) from the
// DB into the in-memory map BaselineMode reads (RT-DRIFT-50). Idempotent and safe to
// call repeatedly. Best-effort: a missing process_baseline_states table (pre-migration)
// returns nil so a fresh DB doesn't error.
func (h *Baselines) Hydrate(ctx context.Context) error {
	if h.db == nil {
		return nil
	}
	rows, err := h.db.Pool().Query(ctx, `
SELECT org_id, cluster_id::text, workload_id, COALESCE(namespace,''), COALESCE(name,''), mode,
       learn_started_at, monitor_started_at, enforce_started_at
  FROM process_baseline_states`)
	if err != nil {
		if strings.Contains(err.Error(), "process_baseline_states") {
			return nil
		}
		return err
	}
	type hydrateRow struct {
		orgID      uuid.UUID
		clusterID  string
		workloadID string
		namespace  string
		name       string
		mode       string
		learnAt    time.Time
		monitorAt  *time.Time
		enforceAt  *time.Time
	}
	var pending []hydrateRow
	for rows.Next() {
		var hr hydrateRow
		if err := rows.Scan(&hr.orgID, &hr.clusterID, &hr.workloadID, &hr.namespace, &hr.name,
			&hr.mode, &hr.learnAt, &hr.monitorAt, &hr.enforceAt); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, hr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// Resolve observations after the cursor is drained (each does its own query).
	for _, hr := range pending {
		clusterID, perr := uuid.Parse(hr.clusterID)
		if perr != nil {
			continue
		}
		st := &baselineState{
			WorkloadID:     hr.workloadID,
			ClusterID:      hr.clusterID,
			Namespace:      hr.namespace,
			Name:           hr.name,
			Mode:           baseline.Mode(hr.mode),
			LearnStartedAt: hr.learnAt,
		}
		if hr.monitorAt != nil {
			st.MonitorStartedAt = *hr.monitorAt
		}
		if hr.enforceAt != nil {
			st.EnforceStartedAt = *hr.enforceAt
		}
		if procs, alerts, blocks, lastNew, oerr := h.processObservations(ctx, hr.orgID, clusterID, hr.workloadID); oerr == nil {
			st.Processes = procs
			st.Alerts24h = alerts
			st.Blocks24h = blocks
			st.LastNewProcessAt = lastNew
		}
		h.cacheState(st)
	}
	return nil
}

// cacheState stores st into the in-memory map keyed clusterID::workloadID (the same key
// the memory-state path uses) so BaselineMode can serve it on the hot path. Overwrites a
// prior entry so a re-hydrate / SetMode refreshes rather than duplicates.
func (h *Baselines) cacheState(st *baselineState) {
	if st == nil {
		return
	}
	h.mu.Lock()
	h.state[st.ClusterID+"::"+st.WorkloadID] = st
	h.mu.Unlock()
}

// baselineState is the per-workload bookkeeping that lives alongside the engine
// (which only stores the learned process *set*; the UI needs counts + timestamps).
type baselineState struct {
	WorkloadID       string
	ClusterID        string
	Namespace        string
	Name             string
	Mode             baseline.Mode
	LearnStartedAt   time.Time
	MonitorStartedAt time.Time
	EnforceStartedAt time.Time
	Processes        []processObservation // sorted high → low by ObservedCount
	Alerts24h        int
	Blocks24h        int
	LastNewProcessAt time.Time
	Transitions      []transitionEvent
}

type processObservation struct {
	Name string
	Args []string
	Path string
	// RT-MATCH-16: full-path + content + lineage keys captured from the agent's
	// /proc exec enrichment (empty when the agent did not send them — the baseline
	// then falls back to basename-only matching for that process).
	Sha256        string
	ParentName    string
	ObservedCount int
	FirstSeen     time.Time
	LastSeen      time.Time
}

type transitionEvent struct {
	At     time.Time
	Actor  string
	From   baseline.Mode
	To     baseline.Mode
	Reason string
}

// ----- DTOs -----------------------------------------------------------------

type baselineSummaryDTO struct {
	WorkloadID            string `json:"workload_id"`
	ClusterID             string `json:"cluster_id,omitempty"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	Mode                  string `json:"mode"`
	LearnedProcessesCount int    `json:"learned_processes_count"`
	MonitoredAlerts24h    int    `json:"monitored_alerts_24h"`
	EnforcedBlocks24h     int    `json:"enforced_blocks_24h"`
	LearnStartedAt        string `json:"learn_started_at,omitempty"`
	MonitorStartedAt      string `json:"monitor_started_at,omitempty"`
	EnforceStartedAt      string `json:"enforce_started_at,omitempty"`
	LastNewProcessAt      string `json:"last_new_process_at,omitempty"`
	// TopProcesses surfaces the 5 most-observed process names so the card hover
	// state can render inline without a follow-up round trip.
	TopProcesses []string `json:"top_processes,omitempty"`
}

type baselineProcessDTO struct {
	Name          string   `json:"name"`
	Args          []string `json:"args"`
	Path          string   `json:"path"`
	ObservedCount int      `json:"observed_count"`
	FirstSeen     string   `json:"first_seen"`
	LastSeen      string   `json:"last_seen"`
}

type baselineTransitionDTO struct {
	At     string `json:"at"`
	Actor  string `json:"actor"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

type baselineDetailDTO struct {
	baselineSummaryDTO
	Processes   []baselineProcessDTO    `json:"processes"`
	Transitions []baselineTransitionDTO `json:"transitions"`
	Rules       []processRuleDTO        `json:"rules"`
}

// ----- HTTP handlers --------------------------------------------------------

// List returns one profile per deployment in the cluster (or all clusters when
// cluster_id is omitted). Profiles are synthesized lazily and cached.
func (h *Baselines) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))

	workloads, err := h.observedWorkloads(r.Context(), subj.OrgID, clusterArg, namespace)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	profiles := make([]baselineSummaryDTO, 0, len(workloads))
	for _, wl := range workloads {
		state, err := h.ensureState(r.Context(), subj.OrgID, wl, now)
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		profiles = append(profiles, h.summary(state))
	}
	sort.SliceStable(profiles, func(i, j int) bool {
		if profiles[i].Mode != profiles[j].Mode {
			return modeRank(profiles[i].Mode) < modeRank(profiles[j].Mode)
		}
		if profiles[i].Namespace != profiles[j].Namespace {
			return profiles[i].Namespace < profiles[j].Namespace
		}
		return profiles[i].Name < profiles[j].Name
	})

	summary := map[string]any{
		"total":   len(profiles),
		"learn":   countBaselines(profiles, string(baseline.ModeLearn)),
		"monitor": countBaselines(profiles, string(baseline.ModeMonitor)),
		"enforce": countBaselines(profiles, string(baseline.ModeEnforce)),
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"profiles": profiles,
		"summary":  summary,
	})
}

// Get returns one profile with its full process list + audit timeline.
func (h *Baselines) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	workloadID := workloadIDParam(r)
	if workloadID == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "workload_id required"})
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	wl, ok, err := h.findWorkload(r.Context(), subj.OrgID, clusterArg, workloadID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
		return
	}
	state, err := h.ensureState(r.Context(), subj.OrgID, wl, time.Now().UTC())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	detail := baselineDetailDTO{
		baselineSummaryDTO: h.summary(state),
		Processes:          processesDTO(state.Processes),
		Transitions:        transitionsDTO(state.Transitions),
		Rules:              h.loadProcessRules(r.Context(), subj.OrgID, wl.ClusterID, wl.WorkloadID),
	}
	httpx.WriteJSON(w, http.StatusOK, detail)
}

// ModeBody is the POST payload for /runtime/baselines/{workload_id}/mode.
type baselineModeBody struct {
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
}

// SetMode transitions a workload's baseline mode. Audit-logged.
//
// Allowed transitions:
//
//	learn   → monitor
//	monitor → enforce
//	enforce → monitor   (rollback)
//	monitor → learn     (rollback)
func (h *Baselines) SetMode(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	workloadID := workloadIDParam(r)
	if workloadID == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "workload_id required"})
		return
	}
	var body baselineModeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	target, err := normalizeMode(body.Mode)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	wl, ok, err := h.findWorkload(r.Context(), subj.OrgID, clusterArg, workloadID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
		return
	}
	now := time.Now().UTC()
	state, err := h.ensureState(r.Context(), subj.OrgID, wl, now)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	from := state.Mode
	if !validTransition(from, target) {
		httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("transition %s → %s not allowed", from, target)})
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = fmt.Sprintf("manual transition from %s to %s", from, target)
	}
	if err := h.persistModeTransition(r.Context(), subj, wl, from, target, reason, now); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// A memory-backed state (empty ClusterID) is the SAME pointer stored in h.state that
	// BaselineMode reads under h.mu on the ingest hot path, so its mutation must take the
	// same lock. DB-backed states are per-request locals, so the lock is uncontended there
	// and behavior is unchanged.
	h.mu.Lock()
	applyBaselineTransition(state, subj.UserID.String(), from, target, reason, now)
	h.mu.Unlock()

	// Mirror into the engine so the actual lifecycle math reflects the new mode.
	// We don't track promote-failures here — the in-handler `state` is the source
	// of truth for the UI and the engine is best-effort.
	h.driveEngineToMode(workloadID, target)

	h.audit(r, subj, target, from, workloadID, reason)
	// P2-3: federate the new baseline mode + allowed-process set (master only;
	// LogFedRevision no-ops otherwise). Memory-backed states have no cluster, so
	// there is no DB-derived allowed set to ship — skip them.
	if clusterID, perr := uuid.Parse(wl.ClusterID); perr == nil {
		if obs, _, _, _, oerr := h.processObservations(r.Context(), subj.OrgID, clusterID, wl.WorkloadID); oerr == nil {
			recordFedBaseline(r.Context(), h.db.Pool(), subj.OrgID, processBaselineBundleRow{
				WorkloadID: wl.WorkloadID,
				Namespace:  wl.Namespace,
				Name:       wl.Name,
				Mode:       string(target),
				Processes:  allowedBasenames(obs),
				UpdatedAt:  now.UTC().Format(time.RFC3339),
			})
		}
	}
	httpx.WriteJSON(w, http.StatusOK, h.summary(state))
}

// BaselineMode is the hot-path lookup the events-ingest classifier uses to decide
// whether a shell exec is a baseline drift (-> runtime.alert). It reads ONLY the
// in-memory state map (populated by the List/Get/SetMode handlers and the learn
// flow) — no DB round-trip per event. Workloads not yet resident in memory return
// ("", nil, false), which the classifier treats as "don't promote".
//
// The returned set is keyed to match `commBasename(comm, filename)` (the same form
// the classifier derives `bin` from): the process basename. We also add the
// basename of the recorded path defensively in case the two ever diverge.
func (h *Baselines) BaselineMode(orgID uuid.UUID, workloadID string) (baseline.Mode, map[string]struct{}, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var match *baselineState
	for _, st := range h.state {
		if st != nil && st.WorkloadID == workloadID {
			match = st
			break
		}
	}
	if match == nil {
		return "", nil, false
	}
	set := make(map[string]struct{}, len(match.Processes))
	for _, p := range match.Processes {
		if name := strings.TrimSpace(p.Name); name != "" {
			set[name] = struct{}{}
		}
		if base := pathBasename(p.Path); base != "" {
			set[base] = struct{}{}
		}
	}
	return match.Mode, set, true
}

func pathBasename(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// ----- helpers --------------------------------------------------------------

type observedWorkload struct {
	WorkloadID string
	ClusterID  string
	Namespace  string
	Name       string
	Labels     map[string]string
}

// observedWorkloads pulls every deployment in scope so the baseline page can
// surface a profile per workload — same source the deployments + network policy
// pages use.
func (h *Baselines) observedWorkloads(ctx context.Context, orgID uuid.UUID, clusterArg any, namespace string) ([]observedWorkload, error) {
	if h.db == nil {
		return nil, nil
	}
	rows, err := h.db.Pool().Query(ctx, `
SELECT COALESCE(cluster_id::text, ''), namespace, name, COALESCE(labels,'{}'::jsonb)
  FROM deployments
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND ($3::text = '' OR namespace = $3)
 ORDER BY namespace, name`, orgID, clusterArg, namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []observedWorkload{}
	for rows.Next() {
		var clusterID, ns, name string
		var labelsRaw []byte
		if err := rows.Scan(&clusterID, &ns, &name, &labelsRaw); err != nil {
			return nil, err
		}
		var labels map[string]string
		if len(labelsRaw) > 0 {
			_ = json.Unmarshal(labelsRaw, &labels)
		}
		out = append(out, observedWorkload{
			WorkloadID: ns + "/" + name,
			ClusterID:  clusterID,
			Namespace:  ns,
			Name:       name,
			Labels:     labels,
		})
	}
	return out, rows.Err()
}

func (h *Baselines) findWorkload(ctx context.Context, orgID uuid.UUID, clusterArg any, workloadID string) (observedWorkload, bool, error) {
	all, err := h.observedWorkloads(ctx, orgID, clusterArg, "")
	if err != nil {
		return observedWorkload{}, false, err
	}
	for _, wl := range all {
		if wl.WorkloadID == workloadID {
			return wl, true, nil
		}
	}
	return observedWorkload{}, false, nil
}

// ensureState gets or initializes per-workload baseline state.
func (h *Baselines) ensureState(ctx context.Context, orgID uuid.UUID, wl observedWorkload, now time.Time) (*baselineState, error) {
	if h.db == nil || strings.TrimSpace(wl.ClusterID) == "" {
		return h.ensureMemoryState(wl, now), nil
	}
	clusterID, err := uuid.Parse(wl.ClusterID)
	if err != nil {
		return synthesizeState(wl, now), nil
	}
	var state baselineState
	var monitorAt, enforceAt *time.Time
	err = h.db.Pool().QueryRow(ctx, `
INSERT INTO process_baseline_states (
    org_id, cluster_id, workload_id, namespace, name, mode, learn_started_at
) VALUES ($1, $2, $3, $4, $5, 'learn', $6)
ON CONFLICT (org_id, cluster_id, workload_id) DO UPDATE
   SET namespace = EXCLUDED.namespace,
       name = EXCLUDED.name
RETURNING workload_id, cluster_id::text, namespace, name, mode,
          learn_started_at, monitor_started_at, enforce_started_at`,
		orgID, clusterID, wl.WorkloadID, wl.Namespace, wl.Name, now).
		// monitor/enforce_started_at are nullable (set only once that mode is
		// entered); scan via pointers so a NULL maps to the zero time the rest of
		// the code already treats as "not set" (see summary()/rfc3339Or).
		Scan(&state.WorkloadID, &state.ClusterID, &state.Namespace, &state.Name, &state.Mode,
			&state.LearnStartedAt, &monitorAt, &enforceAt)
	if monitorAt != nil {
		state.MonitorStartedAt = *monitorAt
	}
	if enforceAt != nil {
		state.EnforceStartedAt = *enforceAt
	}
	if err != nil {
		if strings.Contains(err.Error(), "process_baseline_states") {
			return h.ensureMemoryState(wl, now), nil
		}
		return nil, err
	}
	processes, alerts, blocks, lastNew, err := h.processObservations(ctx, orgID, clusterID, wl.WorkloadID)
	if err != nil {
		return nil, err
	}
	state.Processes = processes
	state.Alerts24h = alerts
	state.Blocks24h = blocks
	state.LastNewProcessAt = lastNew
	transitions, err := h.baselineTransitions(ctx, orgID, clusterID, wl.WorkloadID)
	if err != nil {
		return nil, err
	}
	state.Transitions = transitions
	h.driveEngineToMode(wl.WorkloadID, state.Mode)
	// RT-DRIFT-50: keep the hot-path BaselineMode map current on every List/Get/SetMode
	// (in addition to the startup Hydrate), so a DB-backed workload's mode + learned set
	// are served to the drift classifier without waiting for the next full hydrate.
	h.cacheState(&state)
	return &state, nil
}

func (h *Baselines) ensureMemoryState(wl observedWorkload, now time.Time) *baselineState {
	key := wl.ClusterID + "::" + wl.WorkloadID
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.state[key]; ok {
		return s
	}
	s := synthesizeState(wl, now)
	h.state[key] = s
	h.engine.StartLearn(wl.WorkloadID, 14*24*time.Hour)
	h.driveEngineToMode(wl.WorkloadID, s.Mode)
	return s
}

func (h *Baselines) processObservations(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string) ([]processObservation, int, int, time.Time, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT severity,
       verdict,
       payload,
       at
  FROM events
 WHERE org_id = $1
   AND cluster_id = $2
   AND kind = 'process_exec'
   AND (
        workload_id = $3
     OR workload_id IN (
        SELECT pod_workload_id
          FROM pod_workload_links
         WHERE org_id = $1
           AND cluster_id = $2
           AND owner_workload_id = $3
     )
   )
 ORDER BY at DESC
 LIMIT 1000`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, 0, 0, time.Time{}, err
	}
	defer rows.Close()

	type processPayload struct {
		Comm       string   `json:"comm"`
		Filename   string   `json:"filename"`
		Args       []string `json:"args"`
		ExePath    string   `json:"exe_path"`
		ExeSha256  string   `json:"exe_sha256"`
		ParentName string   `json:"parent_name"`
	}
	processes := map[string]*processObservation{}
	var alerts24h, blocks24h int
	var lastNewProcessAt time.Time
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	for rows.Next() {
		var severity, verdict string
		var payloadRaw []byte
		var at time.Time
		if err := rows.Scan(&severity, &verdict, &payloadRaw, &at); err != nil {
			return nil, 0, 0, time.Time{}, err
		}
		if at.After(cutoff) && (severity == "high" || severity == "critical" || verdict == "alert") {
			alerts24h++
		}
		if at.After(cutoff) && (verdict == "block" || verdict == "deny") {
			blocks24h++
		}
		var payload processPayload
		_ = json.Unmarshal(payloadRaw, &payload)
		processName := strings.TrimSpace(commBasename(payload.Comm, payload.Filename))
		if processName == "" {
			continue
		}
		// RT-MATCH-16: prefer the agent-resolved /proc/<pid>/exe path (canonical,
		// symlink/relative-safe) over the raw execve filename for the learned path.
		canonPath := strings.TrimSpace(payload.ExePath)
		if canonPath == "" {
			canonPath = strings.TrimSpace(payload.Filename)
		}
		key := processName + "\x00" + canonPath
		item, ok := processes[key]
		if !ok {
			item = &processObservation{
				Name:       processName,
				Args:       append([]string(nil), payload.Args...),
				Path:       canonPath,
				Sha256:     strings.TrimSpace(payload.ExeSha256),
				ParentName: strings.TrimSpace(payload.ParentName),
				FirstSeen:  at,
				LastSeen:   at,
			}
			processes[key] = item
			if lastNewProcessAt.IsZero() || at.After(lastNewProcessAt) {
				lastNewProcessAt = at.UTC()
			}
		}
		// Backfill hash/parent if a later observation of the same path carries them
		// (e.g. hashing was enabled after the first sighting).
		if item.Sha256 == "" {
			item.Sha256 = strings.TrimSpace(payload.ExeSha256)
		}
		if item.ParentName == "" {
			item.ParentName = strings.TrimSpace(payload.ParentName)
		}
		item.ObservedCount++
		if at.Before(item.FirstSeen) {
			item.FirstSeen = at
		}
		if at.After(item.LastSeen) {
			item.LastSeen = at
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, time.Time{}, err
	}
	out := make([]processObservation, 0, len(processes))
	for _, process := range processes {
		out = append(out, *process)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ObservedCount != out[j].ObservedCount {
			return out[i].ObservedCount > out[j].ObservedCount
		}
		return out[i].Name < out[j].Name
	})
	return out, alerts24h, blocks24h, lastNewProcessAt, nil
}

func (h *Baselines) baselineTransitions(ctx context.Context, orgID, clusterID uuid.UUID, workloadID string) ([]transitionEvent, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT created_at,
       COALESCE(actor_id::text, ''),
       from_mode,
       to_mode,
       reason
  FROM process_baseline_transitions
 WHERE org_id = $1
   AND cluster_id = $2
   AND workload_id = $3
 ORDER BY created_at ASC`, orgID, clusterID, workloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []transitionEvent{}
	for rows.Next() {
		var item transitionEvent
		if err := rows.Scan(&item.At, &item.Actor, &item.From, &item.To, &item.Reason); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *Baselines) persistModeTransition(ctx context.Context, subj authctx.Subject, wl observedWorkload, from, to baseline.Mode, reason string, now time.Time) error {
	if h.db == nil || strings.TrimSpace(wl.ClusterID) == "" {
		return nil
	}
	clusterID, err := uuid.Parse(wl.ClusterID)
	if err != nil {
		return err
	}
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
UPDATE process_baseline_states
   SET mode = $1,
       learn_started_at = CASE WHEN $1 = 'learn' THEN $2 ELSE learn_started_at END,
       monitor_started_at = CASE WHEN $1 = 'monitor' AND monitor_started_at IS NULL THEN $2 ELSE monitor_started_at END,
       enforce_started_at = CASE WHEN $1 = 'enforce' THEN $2 ELSE enforce_started_at END,
       updated_by = $3,
       updated_at = $2
 WHERE org_id = $4
   AND cluster_id = $5
   AND workload_id = $6`,
		string(to), now, subj.UserID, subj.OrgID, clusterID, wl.WorkloadID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO process_baseline_transitions (
    org_id, cluster_id, workload_id, from_mode, to_mode, reason, actor_id, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		subj.OrgID, clusterID, wl.WorkloadID, string(from), string(to), reason, subj.UserID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func applyBaselineTransition(state *baselineState, actor string, from, to baseline.Mode, reason string, now time.Time) {
	state.Mode = to
	switch to {
	case baseline.ModeMonitor:
		if state.MonitorStartedAt.IsZero() {
			state.MonitorStartedAt = now
		}
	case baseline.ModeEnforce:
		state.EnforceStartedAt = now
	case baseline.ModeLearn:
		state.LearnStartedAt = now
	}
	state.Transitions = append(state.Transitions, transitionEvent{
		At: now, Actor: actor, From: from, To: to, Reason: reason,
	})
}

// synthesizeState initializes a neutral learn profile. It intentionally does not
// fabricate process observations or lifecycle transitions.
func synthesizeState(wl observedWorkload, now time.Time) *baselineState {
	return &baselineState{
		WorkloadID:       wl.WorkloadID,
		ClusterID:        wl.ClusterID,
		Namespace:        wl.Namespace,
		Name:             wl.Name,
		Mode:             baseline.ModeLearn,
		LearnStartedAt:   now,
		LastNewProcessAt: time.Time{},
		Processes:        []processObservation{},
		Transitions:      []transitionEvent{},
	}
}

func (h *Baselines) driveEngineToMode(workloadID string, target baseline.Mode) {
	// Engine.Promote only advances forward. For rollback the UI's source of truth
	// is the in-handler state; we just clamp the engine to the most advanced mode
	// we've ever asked it to be in. Best-effort.
	switch target {
	case baseline.ModeMonitor:
		_, _ = h.engine.Promote(workloadID)
	case baseline.ModeEnforce:
		_, _ = h.engine.Promote(workloadID)
		_, _ = h.engine.Promote(workloadID)
	}
}

func (h *Baselines) summary(s *baselineState) baselineSummaryDTO {
	top := make([]string, 0, 5)
	for i, p := range s.Processes {
		if i >= 5 {
			break
		}
		top = append(top, p.Name)
	}
	return baselineSummaryDTO{
		WorkloadID:            s.WorkloadID,
		ClusterID:             s.ClusterID,
		Namespace:             s.Namespace,
		Name:                  s.Name,
		Mode:                  string(s.Mode),
		LearnedProcessesCount: len(s.Processes),
		MonitoredAlerts24h:    s.Alerts24h,
		EnforcedBlocks24h:     s.Blocks24h,
		LearnStartedAt:        rfc3339Or(s.LearnStartedAt),
		MonitorStartedAt:      rfc3339Or(s.MonitorStartedAt),
		EnforceStartedAt:      rfc3339Or(s.EnforceStartedAt),
		LastNewProcessAt:      rfc3339Or(s.LastNewProcessAt),
		TopProcesses:          top,
	}
}

func processesDTO(in []processObservation) []baselineProcessDTO {
	out := make([]baselineProcessDTO, 0, len(in))
	for _, p := range in {
		out = append(out, baselineProcessDTO{
			Name:          p.Name,
			Args:          p.Args,
			Path:          p.Path,
			ObservedCount: p.ObservedCount,
			FirstSeen:     rfc3339Or(p.FirstSeen),
			LastSeen:      rfc3339Or(p.LastSeen),
		})
	}
	return out
}

func transitionsDTO(in []transitionEvent) []baselineTransitionDTO {
	out := make([]baselineTransitionDTO, 0, len(in))
	for _, t := range in {
		out = append(out, baselineTransitionDTO{
			At: rfc3339Or(t.At), Actor: t.Actor,
			From: string(t.From), To: string(t.To), Reason: t.Reason,
		})
	}
	return out
}

func validTransition(from, to baseline.Mode) bool {
	if from == to {
		return false
	}
	switch from {
	case baseline.ModeLearn:
		return to == baseline.ModeMonitor
	case baseline.ModeMonitor:
		return to == baseline.ModeEnforce || to == baseline.ModeLearn
	case baseline.ModeEnforce:
		return to == baseline.ModeMonitor
	}
	return false
}

func normalizeMode(m string) (baseline.Mode, error) {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "learn":
		return baseline.ModeLearn, nil
	case "monitor":
		return baseline.ModeMonitor, nil
	case "enforce":
		return baseline.ModeEnforce, nil
	}
	return "", errors.New("mode must be learn | monitor | enforce")
}

func workloadIDParam(r *http.Request) string {
	raw := chi.URLParam(r, "workload_id")
	if decoded, err := url.PathUnescape(raw); err == nil {
		raw = decoded
	}
	return strings.TrimSpace(raw)
}

func modeRank(m string) int {
	switch m {
	case string(baseline.ModeLearn):
		return 0
	case string(baseline.ModeMonitor):
		return 1
	case string(baseline.ModeEnforce):
		return 2
	}
	return 99
}

func countBaselines(items []baselineSummaryDTO, mode string) int {
	total := 0
	for _, it := range items {
		if it.Mode == mode {
			total++
		}
	}
	return total
}

func rfc3339Or(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (h *Baselines) audit(r *http.Request, subj authctx.Subject, to, from baseline.Mode, workloadID, reason string) {
	if h.auditLog == nil {
		return
	}
	orgID := subj.OrgID
	userID := subj.UserID
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    actorIP,
		Action:     "baseline.transition",
		TargetKind: "process-baseline",
		TargetID:   workloadID,
		Before:     map[string]any{"mode": string(from)},
		After:      map[string]any{"mode": string(to), "reason": reason},
		RequestID:  chimw.GetReqID(r.Context()),
	})
}
