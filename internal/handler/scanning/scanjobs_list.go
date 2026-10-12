package scanning

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/google/uuid"
)

const scanJobInventorySQL = `SELECT sj.id, sj.org_id, st.id AS target_id, st.type AS target_type, st.ref AS target_ref, st.cluster_id AS target_cluster_id,
 st.source_type, COALESCE(st.source_ref,'') AS source_ref, COALESCE(st.image_ref,'') AS image_ref,
 COALESCE(st.platform,'') AS platform, COALESCE(st.inventory_hash,'') AS inventory_hash,
 st.registry_id, COALESCE(st.image_digest,'') AS image_digest, st.metadata,
 COALESCE(sj.enqueue_reason,'') AS enqueue_reason, COALESCE(sj.registry_policy_hash,'') AS registry_policy_hash, COALESCE(sj.vulndb_bundle_version,'') AS vulndb_bundle_version,
 sj.status, COALESCE(sj.worker_id,'') AS worker_id, COALESCE(sj.error,'') AS error,
 COALESCE(sj.attempt_count,0) AS attempt_count, COALESCE(sj.max_attempts,3) AS max_attempts,
 COALESCE(sj.package_count,0) AS package_count, COALESCE(sj.finding_count,0) AS finding_count,
 sj.bundle_metadata, sj.requested_at, sj.claimed_at, sj.lease_expires_at, sj.next_attempt_at, sj.last_attempt_at, sj.last_error_at, sj.finished_at
 FROM scan_jobs sj JOIN scan_targets st ON st.id=sj.target_id AND st.org_id=sj.org_id WHERE sj.org_id=$1`
const scanJobInventoryColumns = `id,org_id,target_id,target_type,target_ref,target_cluster_id,source_type,source_ref,image_ref,platform,inventory_hash,registry_id,image_digest,metadata,enqueue_reason,registry_policy_hash,vulndb_bundle_version,status,worker_id,error,attempt_count,max_attempts,package_count,finding_count,bundle_metadata,requested_at,claimed_at,lease_expires_at,next_attempt_at,last_attempt_at,last_error_at,finished_at`

func (h *ScanJobs) ExportCSV(w http.ResponseWriter, r *http.Request) { h.listInventory(w, r, true) }
func (h *ScanJobs) listInventory(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "subject required")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		jsonError(w, 400, "invalid query string")
		return
	}
	opts, err := inventorylist.Parse(values, map[string]string{"requested": "requested_at", "target": "lower(target_ref)", "type": "target_type", "status": "status", "attempts": "attempt_count", "findings": "finding_count", "finished": "finished_at"}, "requested")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if values.Get("limit") == "" {
		opts.Limit = 200
	}
	targetType, err := inventorylist.Filter(values, "target_type", "image", "workload", "host", "platform", "registry", "repository", "serverless")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	status, err := inventorylist.Filter(values, "status", "pending", "running", "paused", "failed", "completed", "canceled")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	args := []any{subj.OrgID}
	predicates := []string{"true"}
	bind := func(value any) string { args = append(args, value); return "$" + strconv.Itoa(len(args)) }
	for _, filter := range []struct{ key, column, table string }{{"cluster_id", "target_cluster_id", "clusters"}, {"registry_id", "registry_id", "registries"}} {
		raw := strings.TrimSpace(values.Get(filter.key))
		if raw == "" {
			continue
		}
		id, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			jsonError(w, 400, "invalid "+filter.key)
			return
		}
		var owned bool
		if err := h.db.Pool().QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM "+filter.table+" WHERE id=$1 AND org_id=$2)", id, subj.OrgID).Scan(&owned); err != nil {
			jsonError(w, 500, "scope lookup failed")
			return
		}
		if !owned {
			jsonError(w, 404, "requested scope not found")
			return
		}
		predicates = append(predicates, filter.column+"="+bind(id))
	}
	for _, filter := range []struct{ column, value string }{{"target_type", targetType}, {"status", status}} {
		if filter.value != "" {
			predicates = append(predicates, filter.column+"="+bind(filter.value))
		}
	}
	q := strings.TrimSpace(values.Get("q"))
	if q != "" {
		predicates = append(predicates, "strpos(lower(concat_ws(' ',id,target_ref,target_type,source_type,source_ref,image_ref,worker_id,error)),lower("+bind(q)+"::text))>0")
	}
	d := inventorylist.Definition{SQL: scanJobInventorySQL, Columns: scanJobInventoryColumns, Args: args, Where: strings.Join(predicates, " AND "), Summary: `jsonb_build_object('total',count(*),'pending',count(*) FILTER(WHERE status='pending'),'running',count(*) FILTER(WHERE status='running'),'paused',count(*) FILTER(WHERE status='paused'),'failed',count(*) FILTER(WHERE status='failed'),'completed',count(*) FILTER(WHERE status='completed'),'canceled',count(*) FILTER(WHERE status='canceled'))`}
	if export {
		body, meta, err := inventorylist.CSV(r.Context(), h.db.Pool(), d, opts, scanJobInventoryRow, []string{"Job ID", "Target", "Target type", "Cluster ID", "Registry ID", "Source", "Status", "Attempts", "Max attempts", "Packages", "Findings", "Worker", "Requested", "Finished", "Error"}, func(j JobView) []string {
			cluster, registry, finished := "", "", ""
			if j.TargetClusterID != nil {
				cluster = j.TargetClusterID.String()
			}
			if j.RegistryID != nil {
				registry = j.RegistryID.String()
			}
			if j.FinishedAt != nil {
				finished = j.FinishedAt.UTC().Format(time.RFC3339Nano)
			}
			return []string{j.ID.String(), j.TargetRef, j.TargetType, cluster, registry, j.SourceType, j.Status, strconv.Itoa(j.AttemptCount), strconv.Itoa(j.MaxAttempts), strconv.Itoa(j.PackageCount), strconv.Itoa(j.FindingCount), j.WorkerID, j.RequestedAt.UTC().Format(time.RFC3339Nano), finished, j.Error}
		})
		if err != nil {
			jsonError(w, 500, err.Error())
			return
		}
		inventorylist.WriteCSV(w, "constellation-scan-jobs.csv", body, meta)
		return
	}
	jobs, meta, err := inventorylist.Read(r.Context(), h.db.Pool(), d, opts, scanJobInventoryRow)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	// Queue metrics retain their organization-wide operational scope, independent
	// of inventory filters. They are a separate current-state read.
	metrics, err := handler.ScanQueueMetrics(r.Context(), h.db.Pool(), subj.OrgID)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"jobs": jobs, "queue_metrics": metrics, "total": meta.Total, "summary": meta.Summary, "has_more": meta.HasMore, "limit": opts.Limit, "offset": opts.Offset, "sort": opts.Sort, "order": opts.Order})
}

func scanJobInventoryRow(row inventorylist.Row) (JobView, error) {
	var j JobView
	var bundleRaw, metadataRaw []byte
	if err := row.Scan(&j.ID, &j.OrgID, &j.TargetID, &j.TargetType, &j.TargetRef, &j.TargetClusterID,
		&j.SourceType, &j.SourceRef, &j.ImageRef, &j.Platform, &j.InventoryHash,
		&j.RegistryID, &j.ImageDigest, &metadataRaw, &j.EnqueueReason, &j.RegistryPolicyHash, &j.VulnDBBundleVersion,
		&j.Status, &j.WorkerID, &j.Error, &j.AttemptCount, &j.MaxAttempts, &j.PackageCount, &j.FindingCount,
		&bundleRaw,
		&j.RequestedAt, &j.ClaimedAt, &j.LeaseExpiresAt, &j.NextAttemptAt, &j.LastAttemptAt, &j.LastErrorAt, &j.FinishedAt); err != nil {
		return j, err
	}
	if len(bundleRaw) > 0 {
		var metadata scanner.BundleMetadata
		if err := json.Unmarshal(bundleRaw, &metadata); err != nil {
			return j, fmt.Errorf("invalid scan job bundle metadata")
		}
		j.BundleMetadata = &metadata
	}
	j.Metadata = handler.NormalizedJSONRaw(metadataRaw)
	return j, nil
}
