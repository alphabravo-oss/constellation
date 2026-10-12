package compliance

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	evidence "github.com/alphabravocompany/constellation/internal/complianceevidence"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

func (c *Compliance) writeEvidenceInventory(w http.ResponseWriter, r *http.Request, scope string, export bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid query encoding")
		return
	}
	clusterID, err := evidenceClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid cluster_id")
		return
	}
	q := evidence.Query{OrgID: subj.OrgID, ClusterID: clusterID, Scope: scope, Framework: params.Get("framework"), Namespace: params.Get("namespace"), ControlID: params.Get("control_id"), Status: params.Get("status"), Search: params.Get("q"), Target: params.Get("target"), Sort: params.Get("sort"), Order: params.Get("order"), Limit: 1000}
	for _, field := range []struct {
		name  string
		value *int
	}{{"limit", &q.Limit}, {"offset", &q.Offset}} {
		if params.Has(field.name) {
			n, e := strconv.Atoi(params.Get(field.name))
			if e != nil || n < 0 || field.name == "limit" && n == 0 {
				jsonError(w, http.StatusBadRequest, "invalid "+field.name)
				return
			}
			*field.value = n
		}
	}
	q, err = evidence.ValidateQuery(q)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if clusterID != nil {
		var owned bool
		if err := c.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, clusterID, subj.OrgID).Scan(&owned); err != nil {
			jsonError(w, http.StatusInternalServerError, "cluster scope could not be verified")
			return
		}
		if !owned {
			jsonError(w, http.StatusNotFound, "cluster not found")
			return
		}
	}
	if export {
		q.Limit = evidence.ExportLimit
		q.Offset = 0
	}
	result, err := (evidence.Collector{Pool: c.db.Pool()}).Collect(r.Context(), q)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "compliance evidence could not be loaded")
		return
	}
	if !export {
		httpx.WriteJSON(w, http.StatusOK, result)
		return
	}
	// Build before sending headers so serialization failures cannot confirm an export.
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"id", "scope", "source", "framework", "control_id", "internal_id", "title", "severity", "status", "effective_status", "target_kind", "target", "cluster_id", "namespace", "evidence", "remediation", "observed_at", "exemption_id", "exemption_reason", "exemption_expires_at", "tags_v2"}); err != nil {
		jsonError(w, 500, "export failed")
		return
	}
	for _, item := range result.Items {
		cluster, exID, reason, expires := "", "", "", ""
		if item.ClusterID != nil {
			cluster = item.ClusterID.String()
		}
		if item.Exemption != nil {
			exID = item.Exemption.ID
			reason = item.Exemption.Reason
			expires = item.Exemption.ExpiresAt.Format(time.RFC3339Nano)
		}
		tags, err := json.Marshal(item.TagsV2)
		if err != nil {
			jsonError(w, 500, "export failed")
			return
		}
		if err := writer.Write([]string{item.ID, item.Scope, item.Source, item.Framework, item.ControlID, item.InternalID, item.Title, item.Severity, item.Status, item.EffectiveStatus, item.TargetKind, item.Target, cluster, item.Namespace, item.Evidence, item.Remediation, item.ObservedAt.Format(time.RFC3339Nano), exID, reason, expires, string(tags)}); err != nil {
			jsonError(w, 500, "export failed")
			return
		}
	}
	writer.Flush()
	if writer.Error() != nil {
		jsonError(w, 500, "export failed")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="constellation-compliance-evidence.csv"`)
	w.Header().Set("X-Export-Limit", strconv.Itoa(evidence.ExportLimit))
	w.Header().Set("X-Export-Total", strconv.Itoa(result.Total))
	w.Header().Set("X-Export-Truncated", strconv.FormatBool(result.Total > evidence.ExportLimit))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buffer.Bytes())
}
