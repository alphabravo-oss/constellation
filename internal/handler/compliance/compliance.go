// Compliance endpoints.
//
//	GET /api/v1/compliance/frameworks              — list all 16 frameworks
//	GET /api/v1/compliance/checks?framework=<id>   — paginated checks
//	GET /api/v1/compliance/summary                 — pass% per framework (dashboard widget)
//	POST /api/v1/compliance/ingest                 — accept kube-bench JSON, expand + persist
//	POST /api/v1/compliance/ingest?profile=docker-bench — accept docker-bench-security JSON (opt-in)
package compliance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	evidence "github.com/alphabravocompany/constellation/internal/complianceevidence"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
	"github.com/alphabravocompany/constellation/pkg/notify"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

type Compliance struct {
	db     *db.DB
	audit  *audit.Logger
	alerts complianceResponder
}

func NewCompliance(d *db.DB, a *audit.Logger) *Compliance {
	return &Compliance{db: d, audit: a}
}

// WithResponseAlerts wires the RT-2 response hook, the E1 declarative evaluator, and
// the notify dispatcher so ingested bench failures fire response rules, webhooks, and
// the syslog mirror (P1-16). Any argument may be nil. Returns the receiver for chaining.
func (c *Compliance) WithResponseAlerts(
	respond func(ctx context.Context, orgID, clusterID uuid.UUID, ev response.Event),
	eval func(ctx context.Context, orgID uuid.UUID, ev *responserule.Event) ([]responserule.Action, error),
	dispatcher *notify.Dispatcher,
) *Compliance {
	c.alerts = complianceResponder{respond: respond, evalRules: eval, dispatcher: dispatcher}
	return c
}

// Frameworks lists the canonical compliance frameworks.
func (c *Compliance) Frameworks(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"frameworks": compliancepkg.AllFrameworks()})
}

// Checks returns persisted compliance check rows for the calling org. Supports both
// the legacy ?framework= filter (single framework match) and the bench-v2
// ?profile= filter (matches the JSONB tags_v2 column).
func (c *Compliance) Checks(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	framework := r.URL.Query().Get("framework")
	profile := r.URL.Query().Get("profile")
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	rows, err := c.db.Pool().Query(r.Context(), `
SELECT cc.framework, cc.control_id, cc.title, COALESCE(cc.description,''), cc.status, cc.severity,
       COALESCE(cc.evidence,''), cc.evaluated_at, COALESCE(cc.tags_v2, '{}'::jsonb),
       ce.id::text, ce.reason, ce.expires_at
  FROM compliance_checks cc
  LEFT JOIN LATERAL (
        SELECT id, reason, expires_at, cluster_id, created_at
          FROM compliance_exemptions ce
         WHERE ce.org_id = cc.org_id
           AND ce.framework = cc.framework
           AND ce.control_id = cc.control_id
           AND (ce.cluster_id IS NULL OR ce.cluster_id = cc.cluster_id)
           AND ce.revoked_at IS NULL
           AND ce.expires_at > NOW()
         ORDER BY (ce.cluster_id IS NULL), ce.created_at DESC
         LIMIT 1
       ) ce ON TRUE
 WHERE cc.org_id = $1
   AND ($2::text = '' OR cc.framework = $2)
   AND ($3::text = '' OR cc.tags_v2 ? $3)
   AND ($4::uuid IS NULL OR cc.cluster_id = $4)
 ORDER BY cc.framework, cc.control_id
 LIMIT 500`, subj.OrgID, framework, profile, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var row struct {
			Framework, ControlID, Title, Description, Status, Severity, Evidence string
		}
		// evaluated_at is a timestamptz; scan into time.Time then format. Scanning
		// into a string fails the pgx binary path (OID 1184).
		var when time.Time
		var exemptionID, exemptionReason *string
		var exemptionExpiresAt *time.Time
		var tags []byte
		if err := rows.Scan(&row.Framework, &row.ControlID, &row.Title, &row.Description,
			&row.Status, &row.Severity, &row.Evidence, &when, &tags, &exemptionID, &exemptionReason, &exemptionExpiresAt); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		var tagsParsed map[string]any
		_ = json.Unmarshal(tags, &tagsParsed)
		effectiveStatus := row.Status
		var exemption map[string]any
		if exemptionID != nil && exemptionReason != nil && exemptionExpiresAt != nil {
			exemption = map[string]any{
				"id":         *exemptionID,
				"reason":     *exemptionReason,
				"expires_at": exemptionExpiresAt.UTC().Format(time.RFC3339),
			}
			if row.Status == "fail" {
				effectiveStatus = "exempted"
			}
		}
		item := map[string]any{
			"framework":        row.Framework,
			"control_id":       row.ControlID,
			"title":            row.Title,
			"description":      row.Description,
			"status":           row.Status,
			"effective_status": effectiveStatus,
			"severity":         row.Severity,
			"evidence":         row.Evidence,
			"evaluated_at":     when.UTC().Format(time.RFC3339),
			"tags_v2":          tagsParsed,
		}
		if exemption != nil {
			item["exemption"] = exemption
		}
		out = append(out, item)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"checks": out})
}

// Summary returns pass% + counts per framework.
func (c *Compliance) Summary(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rows, err := c.db.Pool().Query(r.Context(), `
WITH checks AS (
    SELECT cc.framework,
           cc.status,
           ce.id IS NOT NULL AS exempted
      FROM compliance_checks cc
      LEFT JOIN LATERAL (
            SELECT id, cluster_id, created_at
              FROM compliance_exemptions ce
             WHERE ce.org_id = cc.org_id
               AND ce.framework = cc.framework
               AND ce.control_id = cc.control_id
               AND (ce.cluster_id IS NULL OR ce.cluster_id = cc.cluster_id)
               AND ce.revoked_at IS NULL
               AND ce.expires_at > NOW()
             ORDER BY (ce.cluster_id IS NULL), ce.created_at DESC
             LIMIT 1
           ) ce ON TRUE
     WHERE cc.org_id = $1
       AND ($2::uuid IS NULL OR cc.cluster_id = $2)
)
SELECT framework,
       COUNT(*) FILTER (WHERE status = 'pass') AS passes,
       COUNT(*) FILTER (WHERE status = 'fail' AND NOT exempted) AS fails,
       COUNT(*) FILTER (WHERE status = 'manual') AS manuals,
       COUNT(*) FILTER (WHERE status = 'not_applicable') AS not_applicable,
       COUNT(*) FILTER (WHERE status = 'fail' AND exempted) AS exempted,
       COUNT(*) AS total
  FROM checks
 GROUP BY framework
 ORDER BY framework`, subj.OrgID, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var fw string
		var pass, fail, manual, notApplicable, exempted, total int
		if err := rows.Scan(&fw, &pass, &fail, &manual, &notApplicable, &exempted, &total); err != nil {
			continue
		}
		pct := 0
		effectivePct := 0
		if total > 0 {
			pct = (pass * 100) / total
			effectivePct = ((pass + exempted) * 100) / total
		}
		out = append(out, map[string]any{
			"framework":          fw,
			"pass":               pass,
			"fail":               fail,
			"manual":             manual,
			"not_applicable":     notApplicable,
			"exempted":           exempted,
			"total":              total,
			"pass_pct":           pct,
			"effective_pass_pct": effectivePct,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"frameworks": out})
}

// Evidence returns first-class host/workload/Kubernetes/cloud compliance
// evidence. Use ?scope=node|workload|kubernetes|cloud to narrow the stream.
func (c *Compliance) Evidence(w http.ResponseWriter, r *http.Request) {
	c.writeEvidence(w, r, r.URL.Query().Get("scope"))
}

func (c *Compliance) NodeEvidence(w http.ResponseWriter, r *http.Request) {
	c.writeEvidence(w, r, evidence.ScopeNode)
}

func (c *Compliance) WorkloadEvidence(w http.ResponseWriter, r *http.Request) {
	c.writeEvidence(w, r, evidence.ScopeWorkload)
}

func (c *Compliance) KubernetesEvidence(w http.ResponseWriter, r *http.Request) {
	c.writeEvidence(w, r, evidence.ScopeKubernetes)
}

func (c *Compliance) CloudEvidence(w http.ResponseWriter, r *http.Request) {
	c.writeEvidence(w, r, evidence.ScopeCloud)
}

func (c *Compliance) writeEvidence(w http.ResponseWriter, r *http.Request, scope string) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterID, err := evidenceClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	limit := 1000
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid limit"})
			return
		}
		if parsed < 1 {
			parsed = 1
		}
		if parsed > 5000 {
			parsed = 5000
		}
		limit = parsed
	}
	result, err := evidence.Collector{Pool: c.db.Pool()}.Collect(r.Context(), evidence.Query{
		OrgID:     subj.OrgID,
		ClusterID: clusterID,
		Scope:     scope,
		Framework: r.URL.Query().Get("framework"),
		Namespace: r.URL.Query().Get("namespace"),
		Limit:     limit,
	})
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}

func evidenceClusterIDParam(r *http.Request) (*uuid.UUID, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// Ingest accepts kube-bench JSON and persists expanded check rows. Returns the count of
// rows inserted (with cross-framework expansions counted separately).
func (c *Compliance) Ingest(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad body"})
		return
	}
	// profile selects the host-compliance parser. Default is kube-bench; the
	// opt-in docker-bench profile scores CIS Docker host controls on nodes.
	var checks []compliancepkg.Check
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("profile"))) {
	case "docker-bench", "docker":
		checks, err = compliancepkg.ParseDockerBench(body)
	case "", "kube-bench", "kubebench":
		// ?benchmark= (from the runner's BENCH_VERSION) overrides the report's
		// per-control CIS profile id; empty keeps the report-derived tagging.
		checks, err = compliancepkg.IngestKubeBenchProfile(body, r.URL.Query().Get("benchmark"))
	default:
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown profile"})
		return
	}
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// CMP-CLOBBER-03: attribute host-bench rows to the reporting cluster/node so two
	// clusters (or two nodes) in one org no longer clobber each other. The runner sends
	// ?cluster_id= (from CONSTELLATION_CLUSTER_ID) and, where applicable, ?node=. Both are
	// optional: a missing cluster_id stays NULL (org-wide, matching the pre-136 behaviour),
	// and node defaults to "" (non-NULL) so it participates in the composite unique index
	// from migration 136.
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	tx, err := c.db.Pool().Begin(r.Context())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	var failures []complianceFailure
	for _, ck := range checks {
		if strings.EqualFold(ck.Status, "fail") {
			failures = append(failures, complianceFailure{
				CheckID:   ck.ControlID,
				Title:     ck.Title,
				Framework: ck.Framework,
				Severity:  ck.Severity,
				Detail:    ck.Evidence,
			})
		}
		// Populate tags_v2 from the cross-framework expansion when the check
		// title maps to a known internal id. Best-effort: lookup by control id title.
		tags := compliancepkg.TagsV2{}
		for _, m := range compliancepkg.CoreMappings {
			if m.Title == ck.Title {
				tags = compliancepkg.BuildTagsV2(m.InternalID)
				break
			}
		}
		tagsRaw, _ := json.Marshal(tags)
		// CMP-CLOBBER-03: upsert on the per-cluster/per-node host-compliance key so a re-run
		// of the kube-bench/docker-bench CronJob refreshes each control in place for THAT
		// cluster/node instead of clobbering another cluster's rows. Matches the composite
		// partial unique index from migration 136 (WHERE node IS NOT NULL — the k8s-object
		// collector, which stores many rows per control with node NULL, is unaffected).
		if _, err := tx.Exec(r.Context(), `
INSERT INTO compliance_checks (org_id, cluster_id, node, framework, control_id, title, description, status, severity, evidence, tags_v2)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node, framework, control_id) WHERE node IS NOT NULL
DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    status = EXCLUDED.status,
    severity = EXCLUDED.severity,
    evidence = EXCLUDED.evidence,
    tags_v2 = EXCLUDED.tags_v2,
    evaluated_at = NOW()`,
			subj.OrgID, clusterArg, node, ck.Framework, ck.ControlID, ck.Title, ck.Description, ck.Status, ck.Severity, ck.Evidence, tagsRaw,
		); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Close the compliance->response loop: failed controls fire response rules,
	// webhooks, and the syslog mirror (P1-16). When the runner attributes the scan to a
	// cluster (CMP-CLOBBER-03) the RT-2 hook loads that cluster's rules; an unattributed
	// (org-wide) scan falls back to the org-scoped rules (uuid.Nil).
	fireCluster := uuid.Nil
	if cid, ok := clusterArg.(uuid.UUID); ok {
		fireCluster = cid
	}
	c.alerts.fire(r.Context(), subj.OrgID, fireCluster, failures)
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = c.audit.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action:     "compliance.ingest",
		TargetKind: "compliance",
		After:      map[string]any{"rows": len(checks)},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ingested": len(checks)})
}
