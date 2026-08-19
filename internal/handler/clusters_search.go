// Cluster federation list + global search endpoints.
//
//	GET /api/v1/clusters           — list clusters the org has registered
//	GET /api/v1/search?q=<query>   — case-insensitive substring (ILIKE) search across findings + CVEs + assets
//
// The search path is the "command-K palette" backend for the UI.
package handler

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type Clusters struct {
	db    *db.DB
	audit *audit.Logger
}

// NewClusters constructs a Clusters handler. The optional audit logger is required
// for write paths (cross-scan); read paths work without it.
func NewClusters(d *db.DB, a ...*audit.Logger) *Clusters {
	c := &Clusters{db: d}
	if len(a) > 0 {
		c.audit = a[0]
	}
	return c
}

// List returns clusters with rolled-up risk counts. Each row is enriched with
// open/critical/high finding counts, top-risk workload, and last-seen network
// flow timestamp so the cluster picker UI can render in a single round-trip
// (no N+1 fan-out per cluster card).
func (h *Clusters) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT c.id, c.name, c.distro, COALESCE(c.cloud_provider,''), COALESCE(c.region,''),
       c.state, COALESCE(c.agent_version, ''),
       -- Every correlated subquery is scoped by org_id so the composite
       -- (org_id, cluster_id, …) indexes are usable. Without org_id, the
       -- network_flows MAX(at) subquery seq-scanned ~58M rows (~13s each).
       (SELECT COUNT(*) FROM deployments d WHERE d.org_id = c.org_id AND d.cluster_id = c.id) AS deployments,
       (SELECT COALESCE(MAX(risk_score), 0) FROM deployments d WHERE d.org_id = c.org_id AND d.cluster_id = c.id) AS max_risk,
       c.last_heartbeat_at,
       COALESCE(cpf.kubernetes_git_version, ''),
       COALESCE(cpf.platform_provider, ''),
       cpf.observed_at,
       (SELECT COUNT(*) FROM findings f WHERE f.org_id = c.org_id AND f.cluster_id = c.id AND f.severity = 'critical' AND f.lifecycle = 'open') AS critical_open,
       (SELECT COUNT(*) FROM findings f WHERE f.org_id = c.org_id AND f.cluster_id = c.id AND f.severity = 'high' AND f.lifecycle = 'open') AS high_open,
       (SELECT COUNT(*) FROM findings f WHERE f.org_id = c.org_id AND f.cluster_id = c.id AND f.lifecycle = 'open') AS open_findings,
       (SELECT COUNT(*) FROM findings f WHERE f.org_id = c.org_id AND f.cluster_id = c.id) AS total_findings,
       (SELECT MAX(nf.at) FROM network_flows nf WHERE nf.org_id = c.org_id AND nf.cluster_id = c.id) AS last_flow_at,
       (SELECT COUNT(DISTINCT ch.component)
          FROM component_heartbeats ch
         WHERE ch.org_id = c.org_id
           AND ch.cluster_id = c.id
           AND ch.component = ANY($2::text[])
           AND ch.last_seen_at > NOW() - INTERVAL '2 minutes') AS connected_sensors,
       (SELECT d.namespace || '/' || d.name FROM deployments d
         WHERE d.org_id = c.org_id AND d.cluster_id = c.id ORDER BY d.risk_score DESC NULLS LAST, d.last_seen_at DESC NULLS LAST LIMIT 1) AS top_workload,
       (SELECT d.risk_score FROM deployments d
         WHERE d.org_id = c.org_id AND d.cluster_id = c.id ORDER BY d.risk_score DESC NULLS LAST, d.last_seen_at DESC NULLS LAST LIMIT 1) AS top_workload_risk
  FROM clusters c
  LEFT JOIN cluster_platform_facts cpf
    ON cpf.org_id = c.org_id AND cpf.cluster_id = c.id
 WHERE c.org_id = $1
 ORDER BY c.name`, subj.OrgID, expectedClusterComponents)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var (
			id, name, distro, cloud, region, state, agentVer    string
			kubernetesVersion, platformProvider                 string
			hb, platformObservedAt, lastFlow                    *time.Time
			deployments, maxRisk                                int
			criticalOpen, highOpen, openFindings, totalFindings int
			connectedSensors                                    int
			topWorkload                                         *string
			topWorkloadRisk                                     *int
		)
		if err := rows.Scan(&id, &name, &distro, &cloud, &region, &state, &agentVer,
			&deployments, &maxRisk, &hb,
			&kubernetesVersion, &platformProvider, &platformObservedAt,
			&criticalOpen, &highOpen, &openFindings, &totalFindings,
			&lastFlow, &connectedSensors, &topWorkload, &topWorkloadRisk); err != nil {
			continue
		}
		var heartbeat, platformObservedOut, lastFlowOut, topWorkloadOut, topWorkloadRiskOut any
		if hb != nil {
			heartbeat = hb.Format(time.RFC3339)
		}
		if platformObservedAt != nil {
			platformObservedOut = platformObservedAt.Format(time.RFC3339)
		}
		if lastFlow != nil {
			lastFlowOut = lastFlow.Format(time.RFC3339)
		}
		if topWorkload != nil {
			topWorkloadOut = *topWorkload
		}
		if topWorkloadRisk != nil {
			topWorkloadRiskOut = *topWorkloadRisk
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "distro": distro, "cloud_provider": cloud, "region": region,
			"state": state, "agent_version": agentVer,
			"deployments": deployments, "max_risk": maxRisk, "last_heartbeat_at": heartbeat,
			"stats": map[string]any{
				"critical_open":  criticalOpen,
				"high_open":      highOpen,
				"open_findings":  openFindings,
				"total_findings": totalFindings,
			},
			"last_flow_at": lastFlowOut,
			"platform": map[string]any{
				"kubernetes_git_version": kubernetesVersion,
				"platform_provider":      platformProvider,
				"observed_at":            platformObservedOut,
			},
			"top_workload":      topWorkloadOut,
			"top_workload_risk": topWorkloadRiskOut,
			"sensor_health": map[string]any{
				"status": clusterSensorStatus(connectedSensors, len(expectedClusterComponents)),
				"ready":  connectedSensors,
				"total":  len(expectedClusterComponents),
			},
			"upgrade": map[string]any{
				"available":       false,
				"target_version":  agentVer,
				"rollout_status":  "current",
				"rollback_window": "",
			},
		})
	}
	writeJSON(w, 200, map[string]any{"clusters": out})
}

// GetOne returns a single cluster's metadata. The cluster picker preloads /clusters
// for the org-wide list; this endpoint backs the in-cluster context where the URL
// is the source of truth and we want to validate the :id deeplinks against the DB
// rather than hoping the cached list is fresh.
func (h *Clusters) GetOne(w http.ResponseWriter, r *http.Request) {
	clusterID := chi.URLParam(r, "id")
	if clusterID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cluster id required"})
		return
	}
	cid, err := uuid.Parse(clusterID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster id"})
		return
	}
	subj, _ := SubjectFrom(r.Context())
	var (
		id, name, distro, cloud, region, state, agentVer string
		hb                                               *time.Time
	)
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT c.id::text, c.name, c.distro, COALESCE(c.cloud_provider,''), COALESCE(c.region,''),
       c.state, COALESCE(c.agent_version, ''), c.last_heartbeat_at
  FROM clusters c
 WHERE c.org_id = $1 AND c.id = $2`, subj.OrgID, cid).
		Scan(&id, &name, &distro, &cloud, &region, &state, &agentVer, &hb)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "cluster not found"})
		return
	}
	var heartbeat any
	if hb != nil {
		heartbeat = hb.Format(time.RFC3339)
	}
	writeJSON(w, 200, map[string]any{
		"id": id, "name": name, "distro": distro, "cloud_provider": cloud, "region": region,
		"state": state, "agent_version": agentVer, "last_heartbeat_at": heartbeat,
	})
}

var expectedClusterComponents = expectedClusterComponentNames()

const clusterHeartbeatFreshAfter = 2 * time.Minute

func clusterSensorStatus(connected, expected int) string {
	switch {
	case expected > 0 && connected >= expected:
		return "healthy"
	case connected > 0:
		return "degraded"
	default:
		return "missing"
	}
}

// Health returns DB-backed operational state for a registered cluster.
func (h *Clusters) Health(w http.ResponseWriter, r *http.Request) {
	clusterIDRaw := chi.URLParam(r, "id")
	if clusterIDRaw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cluster id required"})
		return
	}
	clusterID, err := uuid.Parse(clusterIDRaw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster id"})
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no subject"})
		return
	}

	var (
		clusterName, state, agentVersion string
		clusterHeartbeat                 *time.Time
	)
	err = h.db.Pool().QueryRow(r.Context(), `
SELECT name, state, COALESCE(agent_version,''), last_heartbeat_at
  FROM clusters
 WHERE org_id = $1 AND id = $2`, subj.OrgID, clusterID).
		Scan(&clusterName, &state, &agentVersion, &clusterHeartbeat)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "cluster not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	components, connected, lastCheckIn, err := h.clusterComponentHealth(r, subj.OrgID, clusterID, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if clusterHeartbeat != nil && (lastCheckIn == nil || clusterHeartbeat.After(*lastCheckIn)) {
		lastCheckIn = clusterHeartbeat
	}
	status := clusterStatusFromHealth(state, connected, len(expectedClusterComponents), components)
	bundleID, bundleExpiresAt, registrationState := h.clusterRegistrationState(r, subj.OrgID, clusterID)

	lastCheckInStr := ""
	if lastCheckIn != nil {
		lastCheckInStr = lastCheckIn.UTC().Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"cluster_id": clusterID.String(),
		"summary": map[string]any{
			"status":             status,
			"connected_sensors":  connected,
			"expected_sensors":   len(expectedClusterComponents),
			"last_check_in":      lastCheckInStr,
			"registration_state": registrationState,
		},
		"components": components,
		"registration": map[string]any{
			"bundle_id":      bundleID,
			"expires_at":     bundleExpiresAt,
			"rotate_command": rotateCommand(bundleID),
			"helm_command":   helmInstallCommand(clusterName),
		},
		"gates": clusterHealthGates(state, registrationState, connected, len(expectedClusterComponents), agentVersion, lastCheckIn),
	})
}

type componentRollup struct {
	Name         string
	Kind         string
	Version      string
	Desired      int
	Ready        int
	Seen         int
	LastSeen     *time.Time
	RestartCount int
	LastError    string
	HasError     bool
	Expected     bool
}

func (h *Clusters) clusterComponentHealth(r *http.Request, orgID, clusterID uuid.UUID, now time.Time) ([]map[string]any, int, *time.Time, error) {
	rollups := map[string]*componentRollup{}
	for _, name := range expectedClusterComponents {
		rollups[name] = &componentRollup{Name: name, Kind: componentKind(name), Desired: 1, Expected: true}
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT component, COALESCE(version,''), COALESCE(last_error,''), restart_count, last_seen_at
  FROM component_heartbeats
 WHERE org_id = $1 AND cluster_id = $2
 ORDER BY component, hostname`, orgID, clusterID)
	if err != nil {
		return nil, 0, nil, err
	}
	defer rows.Close()

	var lastCheckIn *time.Time
	for rows.Next() {
		var (
			component, version, lastError string
			restartCount                  int
			lastSeen                      time.Time
		)
		if err := rows.Scan(&component, &version, &lastError, &restartCount, &lastSeen); err != nil {
			continue
		}
		roll := rollups[component]
		if roll == nil {
			roll = &componentRollup{Name: component, Kind: componentKind(component)}
			rollups[component] = roll
		}
		roll.RestartCount += restartCount
		seen := lastSeen.UTC()
		fresh := now.Sub(seen) <= clusterHeartbeatFreshAfter
		roll.Seen++
		if version != "" && (roll.LastSeen == nil || seen.After(*roll.LastSeen)) {
			roll.Version = version
		}
		if roll.LastSeen == nil || seen.After(*roll.LastSeen) {
			roll.LastSeen = &seen
		}
		if lastCheckIn == nil || seen.After(*lastCheckIn) {
			lastCheckIn = &seen
		}
		if fresh {
			roll.Ready++
			if roll.Ready > roll.Desired {
				roll.Desired = roll.Ready
			}
			if lastError != "" {
				roll.HasError = true
				roll.LastError = lastError
			} else if !roll.HasError {
				roll.LastError = ""
			}
		} else if roll.Ready == 0 && roll.LastError == "" && lastError != "" {
			roll.LastError = lastError
		}
	}
	out := clusterComponentsFromRollups(rollups, now)
	connected := 0
	for _, component := range out {
		name, _ := component["name"].(string)
		if !isExpectedClusterComponent(name) {
			continue
		}
		ready, _ := component["ready"].(int)
		if ready > 0 {
			connected++
		}
	}
	return out, connected, lastCheckIn, nil
}

func clusterComponentsFromRollups(rollups map[string]*componentRollup, now time.Time) []map[string]any {
	keys := make([]string, 0, len(rollups))
	for key := range rollups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		ii, jj := expectedIndex(keys[i]), expectedIndex(keys[j])
		if ii != jj {
			return ii < jj
		}
		return keys[i] < keys[j]
	})

	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		roll := rollups[key]
		desired := roll.Desired
		if desired <= 0 {
			desired = 1
		}
		version := roll.Version
		if version == "" {
			version = "unknown"
		}
		lastSeen := ""
		if roll.LastSeen != nil {
			lastSeen = roll.LastSeen.UTC().Format(time.RFC3339)
		}
		out = append(out, map[string]any{
			"name":          roll.Name,
			"kind":          roll.Kind,
			"status":        componentStatus(roll, now),
			"version":       version,
			"desired":       desired,
			"ready":         roll.Ready,
			"last_seen_at":  lastSeen,
			"restart_count": roll.RestartCount,
			"last_error":    roll.LastError,
		})
	}
	return out
}

func (h *Clusters) clusterRegistrationState(r *http.Request, orgID, clusterID uuid.UUID) (bundleID, expiresAt, state string) {
	var (
		id        string
		expires   time.Time
		revokedAt *time.Time
	)
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT id::text, expires_at, revoked_at
  FROM cluster_init_bundles
 WHERE org_id = $1 AND cluster_id = $2
 ORDER BY created_at DESC
 LIMIT 1`, orgID, clusterID).Scan(&id, &expires, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "manual"
	}
	if err != nil {
		return "", "", "unknown"
	}
	return id, expires.UTC().Format(time.RFC3339), "bundle-" + statusOf(expires, revokedAt)
}

func clusterStatusFromHealth(clusterState string, connected, expected int, components []map[string]any) string {
	if expected == 0 {
		return clusterState
	}
	hasDegraded := false
	for _, component := range components {
		status, _ := component["status"].(string)
		switch status {
		case "degraded", "stale", "missing":
			hasDegraded = true
		}
	}
	switch {
	case connected == expected && !hasDegraded:
		return "healthy"
	case connected > 0:
		return "degraded"
	case clusterState == "connected":
		return "stale"
	default:
		return clusterState
	}
}

func clusterHealthGates(clusterState, registrationState string, connected, expected int, agentVersion string, lastCheckIn *time.Time) []map[string]any {
	lastSeen := "not yet"
	if lastCheckIn != nil {
		lastSeen = lastCheckIn.UTC().Format(time.RFC3339)
	}
	regStatus := "pass"
	if registrationState == "manual" {
		regStatus = "warn"
	}
	if strings.HasSuffix(registrationState, "revoked") || strings.HasSuffix(registrationState, "expired") || registrationState == "unknown" {
		regStatus = "blocked"
	}
	componentStatus := "pass"
	if connected == 0 {
		componentStatus = "blocked"
	} else if connected < expected {
		componentStatus = "warn"
	}
	clusterGateStatus := "pass"
	if clusterState != "connected" && clusterState != "healthy" {
		clusterGateStatus = "warn"
	}
	version := agentVersion
	if version == "" {
		version = "unknown"
	}
	return []map[string]any{
		{"name": "Cluster registration", "status": clusterGateStatus, "evidence": "cluster row state=" + clusterState + ", agent_version=" + version},
		{"name": "Init bundle", "status": regStatus, "evidence": "registration_state=" + registrationState},
		{"name": "Component heartbeats", "status": componentStatus, "evidence": strconv.Itoa(connected) + "/" + strconv.Itoa(expected) + " expected components fresh; last_check_in=" + lastSeen},
	}
}

func componentStatus(roll *componentRollup, now time.Time) string {
	if roll.Ready > 0 && !roll.HasError && roll.Ready >= roll.Desired {
		return "ready"
	}
	if roll.Ready > 0 {
		return "degraded"
	}
	if roll.LastSeen != nil && now.Sub(*roll.LastSeen) > clusterHeartbeatFreshAfter {
		return "stale"
	}
	return "missing"
}

func componentKind(name string) string {
	if spec := componentSpecFor(name); spec.Kind != "" {
		return spec.Kind
	}
	return "component"
}

func expectedIndex(name string) int {
	for i, expected := range expectedClusterComponents {
		if expected == name {
			return i
		}
	}
	return len(expectedClusterComponents) + 1
}

func isExpectedClusterComponent(name string) bool {
	return expectedIndex(name) < len(expectedClusterComponents)
}

func rotateCommand(bundleID string) string {
	if bundleID == "" {
		return "constellationctl cluster create <cluster-name> --output cluster-init.yaml"
	}
	return "constellationctl cluster rotate " + bundleID + " --output cluster-init.yaml"
}

func helmInstallCommand(clusterName string) string {
	if clusterName == "" {
		clusterName = "<cluster-name>"
	}
	return "kubectl create ns constellation-system && kubectl -n constellation-system create secret generic constellation-init-bundle --from-file=bundle.yaml=" +
		clusterName + "-init-bundle.yaml && helm upgrade --install constellation deploy/charts/constellation -n constellation-system --set initBundle.secretName=constellation-init-bundle"
}

type Search struct{ db *db.DB }

func NewSearch(d *db.DB) *Search { return &Search{db: d} }

// Q runs a case-insensitive substring (ILIKE) search across findings + CVEs +
// assets, scoped to the calling org. This is plain substring matching, not
// trigram-similarity fuzzy search: findings.external_id and cve_records.cve_id
// have pg_trgm GIN indexes so ILIKE on those columns is index-eligible, but
// title/name/kind fall back to a sequential scan bounded by the trailing LIMIT.
// Results are local to this org only — the search does not federate across joints.
func (h *Search) Q(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, 200, map[string]any{"results": []any{}})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	subj, _ := SubjectFrom(r.Context())
	like := "%" + q + "%"

	results := []map[string]any{}

	// Findings.
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id, title, severity, risk_score
  FROM findings WHERE org_id = $1 AND (title ILIKE $2 OR external_id ILIKE $2)
 ORDER BY risk_score DESC LIMIT $3`, subj.OrgID, like, limit)
	if err == nil {
		for rows.Next() {
			var id, title, sev string
			var risk int
			if err := rows.Scan(&id, &title, &sev, &risk); err == nil {
				results = append(results, map[string]any{
					"kind": "finding", "id": id, "title": title, "severity": sev, "risk_score": risk,
				})
			}
		}
		rows.Close()
	}

	// CVE records.
	rows, err = h.db.Pool().Query(r.Context(), `
SELECT cve_id, COALESCE(title,''), COALESCE(cvss_base, 0)
  FROM cve_records WHERE cve_id ILIKE $1 OR title ILIKE $1
 ORDER BY cvss_base DESC NULLS LAST LIMIT $2`, like, limit)
	if err == nil {
		for rows.Next() {
			var id, title string
			var cvss float64
			if err := rows.Scan(&id, &title, &cvss); err == nil {
				results = append(results, map[string]any{
					"kind": "cve", "id": id, "title": title, "cvss_base": cvss,
				})
			}
		}
		rows.Close()
	}

	// Assets.
	rows, err = h.db.Pool().Query(r.Context(), `
SELECT id, kind, name FROM assets
 WHERE org_id = $1 AND (name ILIKE $2 OR kind ILIKE $2)
 ORDER BY name LIMIT $3`, subj.OrgID, like, limit)
	if err == nil {
		for rows.Next() {
			var id, kind, name string
			if err := rows.Scan(&id, &kind, &name); err == nil {
				results = append(results, map[string]any{
					"kind": "asset", "id": id, "asset_kind": kind, "name": name,
				})
			}
		}
		rows.Close()
	}

	writeJSON(w, 200, map[string]any{"results": results, "q": q})
}
