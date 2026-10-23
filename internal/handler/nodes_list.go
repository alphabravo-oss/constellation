package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

const nodeInventoryColumns = `node,os_id,os_version_id,kernel_release,arch,cni_name,cri_runtime,btf_present,nfqueue_capable,cpu_count,memory_bytes,package_count,package_source,container_count,process_count,cis_profile,cis_passed,cis_failed,cis_warned,cis_skipped,critical_vulns,high_vulns,medium_vulns,low_vulns,open_vulns,runtime_agent_version,runtime_agent_last_seen_at,scan_target_id,inventory_hash,scan_status,last_scanned_at,host_facts_observed_at,packages_observed_at,containers_observed_at,processes_observed_at,cis_observed_at,last_seen_at,runtime_agent_status,coverage_text,id`
const nodeInventorySQL = `WITH source(node,os_id,os_version_id,kernel_release,arch,cni_name,cri_runtime,btf_present,nfqueue_capable,cpu_count,memory_bytes,package_count,package_source,container_count,process_count,cis_profile,cis_passed,cis_failed,cis_warned,cis_skipped,critical_vulns,high_vulns,medium_vulns,low_vulns,open_vulns,runtime_agent_version,runtime_agent_last_seen_at,scan_target_id,inventory_hash,scan_status,last_scanned_at,host_facts_observed_at,packages_observed_at,containers_observed_at,processes_observed_at,cis_observed_at,last_seen_at) AS (` + nodeSummarySQL + `)
SELECT node,os_id,os_version_id,kernel_release,arch,cni_name,cri_runtime,btf_present,nfqueue_capable,cpu_count,memory_bytes,package_count,package_source,container_count,process_count,cis_profile,cis_passed,cis_failed,cis_warned,cis_skipped,critical_vulns,high_vulns,medium_vulns,low_vulns,open_vulns,runtime_agent_version,runtime_agent_last_seen_at,scan_target_id,inventory_hash,
CASE WHEN scan_status<>'' THEN scan_status WHEN scan_target_id IS NOT NULL THEN 'targeted' ELSE 'missing' END,last_scanned_at,host_facts_observed_at,packages_observed_at,containers_observed_at,processes_observed_at,cis_observed_at,last_seen_at,
CASE WHEN runtime_agent_last_seen_at>=NOW()-INTERVAL '2 minutes' THEN 'healthy' WHEN host_facts_observed_at IS NOT NULL OR packages_observed_at IS NOT NULL OR containers_observed_at IS NOT NULL OR processes_observed_at IS NOT NULL OR cis_observed_at IS NOT NULL THEN 'stale' ELSE 'missing' END,
concat_ws(' ',CASE WHEN host_facts_observed_at IS NULL THEN 'host_facts' END,CASE WHEN packages_observed_at IS NULL THEN 'host_packages' END,CASE WHEN scan_status<>'completed' THEN 'host_vulnerability_scan' END,CASE WHEN cis_observed_at IS NULL THEN 'host_cis' END),node
FROM source`

func (h *Nodes) ExportCSV(w http.ResponseWriter, r *http.Request) { h.writeNodeInventory(w, r, true) }
func (h *Nodes) writeNodeInventory(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "subject required")
		return
	}
	cluster, ok := h.clusterIDFromRoute(w, r, subj.OrgID)
	if !ok {
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		jsonError(w, 400, "invalid query string")
		return
	}
	opts, err := inventorylist.Parse(values, map[string]string{"node": "lower(node)", "agent": "runtime_agent_status", "os": "lower(concat_ws(' ',os_id,os_version_id))", "critical": "critical_vulns", "high": "high_vulns", "open": "open_vulns", "packages": "package_count", "containers": "container_count", "cis": "cis_failed", "last_scan": "last_scanned_at", "seen": "last_seen_at"}, "seen")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	opts.Limit = 500
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 500 {
			jsonError(w, 400, "limit must be between 1 and 500")
			return
		}
		opts.Limit = limit
	}
	if raw := values.Get("offset"); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			jsonError(w, 400, "offset must be nonnegative")
			return
		}
		opts.Offset = offset
	}
	agent, err := inventorylist.Filter(values, "agent", "healthy", "stale", "missing")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	risk, err := inventorylist.Filter(values, "risk", "critical", "high", "open", "clean", "host-cves")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if raw := values.Get("host_cves"); raw != "" && raw != "open" {
		jsonError(w, 400, "host_cves must be open")
		return
	}
	hostCVEs := values.Get("host_cves") == "open" || risk == "host-cves"
	q := strings.TrimSpace(values.Get("q"))
	definition := inventorylist.Definition{SinglePass: true, SQL: nodeInventorySQL, Columns: nodeInventoryColumns, Args: []any{subj.OrgID, cluster, "", hostCVEs, q, agent, risk}, Where: `($5='' OR strpos(lower(concat_ws(' ',node,os_id,os_version_id,kernel_release,arch,cni_name,cri_runtime,package_source,inventory_hash,coverage_text)),lower($5))>0) AND ($6='' OR runtime_agent_status=$6) AND ($7='' OR ($7='critical' AND critical_vulns>0) OR ($7='high' AND critical_vulns+high_vulns>0) OR ($7 IN('open','host-cves') AND open_vulns>0) OR ($7='clean' AND open_vulns=0 AND cis_failed=0 AND coverage_text=''))`, Summary: `jsonb_build_object('nodes',count(*),'runtime_agent_healthy',count(*) FILTER(WHERE runtime_agent_status='healthy'),'runtime_agent_stale',count(*) FILTER(WHERE runtime_agent_status='stale'),'runtime_agent_missing',count(*) FILTER(WHERE runtime_agent_status='missing'),'scan_completed',count(*) FILTER(WHERE scan_status='completed'),'scan_gaps',count(*) FILTER(WHERE scan_status<>'completed'),'critical_vulns',COALESCE(sum(critical_vulns),0),'high_vulns',COALESCE(sum(high_vulns),0),'cis_failed',COALESCE(sum(cis_failed),0))`}
	scan := func(row inventorylist.Row) (NodeSummary, error) { return scanNodeInventory(row, cluster) }
	if export {
		body, meta, err := inventorylist.CSV(r.Context(), h.db.Pool(), definition, opts, scan, []string{"Cluster ID", "Node", "Runtime agent", "OS", "OS version", "Kernel", "Architecture", "CNI", "Runtime", "Critical", "High", "Open vulnerabilities", "Packages", "Containers", "CIS failures", "Scan status", "Last scanned", "Last observed", "Coverage gaps", "Inventory hash"}, func(item NodeSummary) []string {
			scanned := ""
			if item.LastScannedAt != nil {
				scanned = item.LastScannedAt.Format(time.RFC3339)
			}
			observed := ""
			if item.LastSeenAt.After(time.Unix(0, 0)) {
				observed = item.LastSeenAt.Format(time.RFC3339)
			}
			return []string{cluster.String(), item.Node, item.RuntimeAgentStatus, item.OSID, item.OSVersionID, item.KernelRelease, item.Arch, item.CNIName, item.CRIRuntime, strconv.Itoa(item.CriticalVulns), strconv.Itoa(item.HighVulns), strconv.Itoa(item.OpenVulns), strconv.Itoa(item.PackageCount), strconv.Itoa(item.ContainerCount), strconv.Itoa(item.CISFailed), item.ScanStatus, scanned, observed, strings.Join(item.CoverageGaps, "; "), item.InventoryHash}
		})
		if err != nil {
			jsonError(w, 500, "node export: "+err.Error())
			return
		}
		inventorylist.WriteCSV(w, "constellation-nodes.csv", body, meta)
		return
	}
	items, meta, err := inventorylist.Read(r.Context(), h.db.Pool(), definition, opts, scan)
	if err != nil {
		jsonError(w, 500, "query nodes: "+err.Error())
		return
	}
	hostCVEsParam := ""
	if hostCVEs {
		hostCVEsParam = "open"
	}
	writeJSON(w, 200, map[string]any{"cluster_id": cluster, "items": items, "summary": meta.Summary, "total": meta.Total, "has_more": meta.HasMore, "q": q, "agent": agent, "risk": risk, "host_cves": hostCVEsParam, "sort": opts.Sort, "order": opts.Order, "limit": opts.Limit, "offset": opts.Offset})
}
func scanNodeInventory(row inventorylist.Row, cluster uuid.UUID) (NodeSummary, error) {
	var item NodeSummary
	item.ClusterID = cluster
	var agent, gaps, id string
	err := row.Scan(&item.Node, &item.OSID, &item.OSVersionID, &item.KernelRelease, &item.Arch, &item.CNIName, &item.CRIRuntime, &item.BTFPresent, &item.NFQueueCapable, &item.CPUCount, &item.MemoryBytes, &item.PackageCount, &item.PackageSource, &item.ContainerCount, &item.ProcessCount, &item.CISProfile, &item.CISPassed, &item.CISFailed, &item.CISWarned, &item.CISSkipped, &item.CriticalVulns, &item.HighVulns, &item.MediumVulns, &item.LowVulns, &item.OpenVulns, &item.RuntimeAgentVersion, &item.RuntimeAgentLastSeenAt, &item.ScanTargetID, &item.InventoryHash, &item.ScanStatus, &item.LastScannedAt, &item.HostFactsObservedAt, &item.PackagesObservedAt, &item.ContainersObservedAt, &item.ProcessesObservedAt, &item.CISObservedAt, &item.LastSeenAt, &agent, &gaps, &id)
	item.RuntimeAgentStatus = agent
	item.CoverageGaps = strings.Fields(gaps)
	return item, err
}
