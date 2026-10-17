package runtime

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

type pcapInventoryFilters struct {
	Query        string `json:"q"`
	Workload     string `json:"workload"`
	Namespace    string `json:"namespace"`
	Node         string `json:"node"`
	Group        string `json:"group"`
	Status       string `json:"status"`
	Protocol     string `json:"protocol"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	DstPort      int    `json:"dst_port"`
	HidePlatform bool   `json:"hide_platform"`
}
type pcapInventoryOptions struct {
	inventorylist.Options
	ClusterID uuid.UUID
	pcapInventoryFilters
}

type pcapInventoryRow struct {
	*PcapCapture
	RowID         string `json:"row_id"`
	PacketCount   *int64 `json:"packet_count"`
	FileSizeBytes *int64 `json:"file_size_bytes"`
}

var pcapInventorySorts = map[string]string{"workload": "workload", "namespace": "namespace", "status": "status", "node": "claimed_by_node", "packets": "recorded_packet_count", "bytes": "recorded_file_size_bytes", "requested": "requested_at", "expires": "expires_at", "completed": "completed_at", "duration": "duration_s", "protocol": "protocol", "port": "dst_port"}

func parsePcapInventory(values url.Values) (pcapInventoryOptions, error) {
	o := pcapInventoryOptions{}
	for _, entries := range values {
		if len(entries) != 1 {
			return o, fmt.Errorf("duplicate query parameter")
		}
	}
	var err error
	if values.Get("cluster_id") == "" {
		return o, fmt.Errorf("cluster_id is required")
	}
	o.ClusterID, err = uuid.Parse(values.Get("cluster_id"))
	if err != nil {
		return o, fmt.Errorf("invalid cluster_id")
	}
	o.Options, err = inventorylist.Parse(values, pcapInventorySorts, "requested")
	if err != nil {
		return o, err
	}
	for key, target := range map[string]*int{"limit": &o.Limit, "offset": &o.Offset} {
		if values.Has(key) {
			n, e := strconv.Atoi(values.Get(key))
			if e != nil || n < 0 || key == "limit" && (n < 1 || n > 500) || key == "offset" && n > inventorylist.MaxOffset {
				return o, fmt.Errorf("invalid %s", key)
			}
			*target = n
		}
	}
	o.Query, o.Workload, o.Namespace, o.Node, o.Group = strings.ToLower(strings.TrimSpace(values.Get("q"))), strings.TrimSpace(values.Get("workload")), strings.TrimSpace(values.Get("namespace")), strings.TrimSpace(values.Get("node")), strings.TrimSpace(values.Get("group"))
	o.Status, err = normalizePcapStatus(values.Get("status"))
	if err != nil {
		return o, err
	}
	o.Protocol, err = normalizePcapProtocol(values.Get("protocol"))
	if err != nil {
		return o, err
	}
	o.SrcIP, err = normalizeOptionalPcapIP("src_ip", values.Get("src_ip"))
	if err != nil {
		return o, err
	}
	o.DstIP, err = normalizeOptionalPcapIP("dst_ip", values.Get("dst_ip"))
	if err != nil {
		return o, err
	}
	o.DstPort, err = parsePcapPortQuery(values.Get("dst_port"))
	if err != nil {
		return o, err
	}
	switch values.Get("hide_platform") {
	case "", "false":
	case "true":
		o.HidePlatform = true
	default:
		return o, fmt.Errorf("invalid hide_platform")
	}
	return o, nil
}

const pcapInventoryColumns = `id,org_id,cluster_id,workload,namespace,requested_by,requested_at,duration_s,src_ip,dst_ip,dst_port,protocol,bpf_filter,capture_interface,file_count,file_size_mb,status,claimed_by_node,claimed_at,completed_at,error_message,file_size_bytes,file_path,sha256,packet_count,expires_at,platform_role,recorded_packet_count,recorded_file_size_bytes`

func pcapDefinition(org uuid.UUID, o pcapInventoryOptions, members []string, active bool) inventorylist.Definition {
	role := handler.EvidencePlatformRoleSQL("$1", "$2", "i.workload", "i.namespace")
	return inventorylist.Definition{
		SQL: `WITH scoped AS (SELECT p.* FROM runtime_pcap_captures p JOIN clusters c ON c.id=p.cluster_id AND c.org_id=p.org_id WHERE p.org_id=$1 AND p.cluster_id=$2),
 roles AS MATERIALIZED (SELECT i.workload,i.namespace,` + role + ` AS role FROM (SELECT DISTINCT workload,namespace FROM scoped) i)
 SELECT ` + pcapCols + `,(SELECT r.role FROM roles r WHERE r.workload=scoped.workload AND r.namespace=scoped.namespace),scoped.packet_count,scoped.file_size_bytes FROM scoped`,
		Columns: pcapInventoryColumns,
		Args:    []any{org, o.ClusterID, o.Query, o.Workload, o.Namespace, o.Node, o.Status, o.Protocol, o.SrcIP, o.DstIP, o.DstPort, active, members, o.HidePlatform},
		Where: `($3::text='' OR strpos(lower(concat_ws(' ',id::text,workload,namespace,claimed_by_node,bpf_filter,capture_interface,src_ip,dst_ip,status,protocol)),$3)>0)
 AND ($4::text='' OR workload=$4) AND ($5::text='' OR namespace=$5) AND ($6::text='' OR claimed_by_node=$6)
 AND ($7::text='' OR status=$7) AND ($8::text='' OR protocol=$8) AND ($9::text='' OR src_ip=$9) AND ($10::text='' OR dst_ip=$10)
 AND ($11::int=0 OR dst_port=$11) AND (NOT $12::boolean OR workload=ANY($13::text[])) AND (NOT $14::boolean OR platform_role<>'core')`,
		Summary: `jsonb_build_object('total',count(*),'pending',count(*) FILTER(WHERE status='pending'),'running',count(*) FILTER(WHERE status='running'),
 'completed',count(*) FILTER(WHERE status='completed'),'failed',count(*) FILTER(WHERE status='failed'),'expired',count(*) FILTER(WHERE status='expired'),
 'packets',COALESCE(sum(packet_count),0),'bytes',COALESCE(sum(file_size_bytes),0),'packet_reports',count(recorded_packet_count),'file_reports',count(recorded_file_size_bytes),'platform',count(*) FILTER(WHERE platform_role='core'))`,
	}
}

type pcapRoleRow struct {
	inventorylist.Row
	extra []any
}

func (row pcapRoleRow) Scan(fields ...any) error {
	return row.Row.Scan(append(fields, row.extra...)...)
}
func scanPcapInventory(row inventorylist.Row) (*pcapInventoryRow, error) {
	var role string
	var packets, bytes *int64
	capture, err := scanPcap(pcapRoleRow{row, []any{&role, &packets, &bytes}})
	if capture != nil {
		capture.PlatformRole = role
	}
	if err != nil {
		return nil, err
	}
	return &pcapInventoryRow{capture, capture.ID.String(), packets, bytes}, nil
}

func (h *PcapHTTP) Inventory(w http.ResponseWriter, r *http.Request) {
	h.writePcapInventory(w, r, false)
}
func (h *PcapHTTP) InventoryCSV(w http.ResponseWriter, r *http.Request) {
	h.writePcapInventory(w, r, true)
}
func (h *PcapHTTP) writePcapInventory(w http.ResponseWriter, r *http.Request, export bool) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "subject required")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		jsonError(w, 400, "invalid query")
		return
	}
	o, err := parsePcapInventory(values)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	var owned bool
	if err := h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, sub.OrgID, o.ClusterID).Scan(&owned); err != nil {
		jsonError(w, 500, "capture scope unavailable")
		return
	}
	if !owned {
		jsonError(w, 404, "cluster not found")
		return
	}
	members, _, active, err := handler.ResolveGroupFilterMembers(r.Context(), h.db.Pool(), sub.OrgID, &o.ClusterID, o.Group)
	if err != nil {
		if err.Error() == "group not found" {
			jsonError(w, 400, "group not found")
		} else {
			jsonError(w, 500, "capture group unavailable")
		}
		return
	}
	d := pcapDefinition(sub.OrgID, o, members, active)
	if export {
		body, meta, err := inventorylist.CSV(r.Context(), h.db.Pool(), d, o.Options, scanPcapInventory,
			[]string{"Capture ID", "Cluster ID", "Workload", "Namespace", "platform_role", "Status", "Requested by", "Requested", "Duration seconds", "Source IP", "Destination IP", "Destination port", "Protocol", "BPF filter", "Interface", "Rolling files", "Rolling file MB", "Node", "Claimed", "Completed", "Packets", "File bytes", "SHA256", "Expires", "Error"}, func(row *pcapInventoryRow) []string {
				stamp := func(value *time.Time) string {
					if value == nil {
						return ""
					}
					return value.UTC().Format(time.RFC3339Nano)
				}
				number := func(value *int64) string {
					if value == nil {
						return ""
					}
					return strconv.FormatInt(*value, 10)
				}
				return []string{row.ID.String(), row.ClusterID.String(), row.Workload, row.Namespace, row.PlatformRole, string(row.Status), row.RequestedBy.String(), row.RequestedAt.UTC().Format(time.RFC3339Nano), strconv.Itoa(int(row.DurationS)), row.SrcIP, row.DstIP, strconv.Itoa(row.DstPort), row.Protocol, row.BPFFilter, row.Interface, strconv.Itoa(row.FileCount), strconv.Itoa(row.FileSizeMB), row.ClaimedByNode, stamp(row.ClaimedAt), stamp(row.CompletedAt), number(row.PacketCount), number(row.FileSizeBytes), row.SHA256, row.ExpiresAt.UTC().Format(time.RFC3339Nano), row.ErrorMessage}
			})
		if err != nil {
			jsonError(w, 500, "capture export unavailable")
			return
		}
		inventorylist.WriteCSV(w, "capture-requests.csv", body, meta)
		return
	}
	items, meta, err := inventorylist.Read(r.Context(), h.db.Pool(), d, o.Options, scanPcapInventory)
	if err != nil {
		jsonError(w, 500, "capture requests unavailable")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"cluster_id": o.ClusterID, "captures": items, "summary": meta.Summary, "total": meta.Total, "limit": o.Limit, "offset": o.Offset,
		"has_more": meta.HasMore, "sort": o.Sort, "order": o.Order, "filters": o.pcapInventoryFilters, "source_complete": true, "summary_scope": "matching_retained_capture_requests"})
}
