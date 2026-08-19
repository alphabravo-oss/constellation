package k8saudit

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// AuditRow is the read-side shape returned by List. The full audit Event lives
// in the raw column; the list view returns the extracted, indexable columns.
type AuditRow struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	ClusterID   string    `json:"cluster_id"`
	Verb        string    `json:"verb"`
	Resource    string    `json:"resource,omitempty"`
	Subresource string    `json:"subresource,omitempty"`
	APIGroup    string    `json:"api_group,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Name        string    `json:"name,omitempty"`
	User        string    `json:"user,omitempty"`
	SourceIP    string    `json:"source_ip,omitempty"`
	Decision    string    `json:"decision,omitempty"`
	Signal      string    `json:"signal,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	AuditID     string    `json:"audit_id,omitempty"`
	ReportedAt  time.Time `json:"reported_at"`
	At          time.Time `json:"at"`
}

// VerbList is the rbac verb gate for List.
func (h *Ingest) VerbList() rbac.Verb { return rbac.VerbReadFindings }

// List returns recent Kubernetes audit events for the console. Filters:
//
//	?hours=        window, default 24, max 720
//	?cluster_id=   restrict to one cluster
//	?verb=         exact verb (get, create, ...)
//	?resource=     exact resource (pods, secrets, ...)
//	?namespace=    exact namespace
//	?user=         exact user.username
//	?signal=       high-signal tag (pod_exec|secret_access|rbac_change|privileged_create)
//	?high_signal=  true => only rows with a non-empty signal
//	?decision=     allow|forbid
func (h *Ingest) List(w http.ResponseWriter, r *http.Request) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "auth required"})
		return
	}
	q := r.URL.Query()
	hours := clampInt(atoiDefault(q.Get("hours"), 24), 1, 720)
	clusterID := strings.TrimSpace(q.Get("cluster_id"))
	verb := strings.ToLower(strings.TrimSpace(q.Get("verb")))
	resource := strings.ToLower(strings.TrimSpace(q.Get("resource")))
	namespace := strings.TrimSpace(q.Get("namespace"))
	user := strings.TrimSpace(q.Get("user"))
	signal := strings.ToLower(strings.TrimSpace(q.Get("signal")))
	decision := strings.ToLower(strings.TrimSpace(q.Get("decision")))
	highOnly := strings.EqualFold(strings.TrimSpace(q.Get("high_signal")), "true")

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, org_id::text, cluster_id::text,
       COALESCE(verb,''), COALESCE(resource,''), COALESCE(subresource,''), COALESCE(api_group,''),
       COALESCE(namespace,''), COALESCE(name,''), COALESCE("user",''), COALESCE(source_ip,''),
       COALESCE(decision,''), COALESCE(signal,''), COALESCE(severity,''), COALESCE(audit_id,''),
       COALESCE(reported_at, at), at
  FROM k8s_audit_events
 WHERE org_id = $1
   AND at >= NOW() - ($2::text || ' hours')::interval
   AND ($3::text = '' OR cluster_id::text = $3)
   AND ($4::text = '' OR lower(verb) = $4)
   AND ($5::text = '' OR lower(resource) = $5)
   AND ($6::text = '' OR namespace = $6)
   AND ($7::text = '' OR "user" = $7)
   AND ($8::text = '' OR lower(signal) = $8)
   AND ($9::text = '' OR lower(decision) = $9)
   AND (NOT $10::boolean OR (signal IS NOT NULL AND signal <> ''))
 ORDER BY at DESC
 LIMIT 500`,
		sub.OrgID, strconv.Itoa(hours), clusterID, verb, resource, namespace, user, signal, decision, highOnly)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	out := make([]AuditRow, 0, 64)
	for rows.Next() {
		var a AuditRow
		if err := rows.Scan(
			&a.ID, &a.OrgID, &a.ClusterID,
			&a.Verb, &a.Resource, &a.Subresource, &a.APIGroup,
			&a.Namespace, &a.Name, &a.User, &a.SourceIP,
			&a.Decision, &a.Signal, &a.Severity, &a.AuditID,
			&a.ReportedAt, &a.At,
		); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, a)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": out})
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}
