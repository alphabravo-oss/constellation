package network

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

// One row is an aggregate of the exact raw protocol/application/port/verdict
// tuple, not an individual packet or retained event. NULL distinctions survive
// in row_id even where the compatibility display uses empty strings or port 0.
type conversationStream struct {
	conversationEntryDTO
	RowID            string `json:"row_id"`
	FromPlatformRole string `json:"from_platform_role"`
	ToPlatformRole   string `json:"to_platform_role"`
}

var streamSorts = map[string]string{"protocol": "protocol", "application": "application", "port": "port", "verdict": "verdict", "bytes": "bytes", "client_bytes": "client_bytes", "server_bytes": "server_bytes", "packets": "packets", "sessions": "sessions", "severity": "severity", "threat": "CASE WHEN threat_id_complete THEN threat_id END", "last_seen": "last_seen_at"}

type streamOptions struct {
	conversationOptions
	Search   string
	Protocol string
}

func parseStreamOptions(values url.Values) (streamOptions, error) {
	var o streamOptions
	copy := url.Values{}
	for key, entries := range values {
		if len(entries) != 1 {
			return o, fmt.Errorf("duplicate parameter")
		}
		copy[key] = append([]string(nil), entries...)
	}
	if values.Has("hours") {
		hours, err := strconv.Atoi(values.Get("hours"))
		if err != nil || hours < 1 || hours > 720 {
			return o, fmt.Errorf("invalid hours")
		}
	}
	// Reuse the precise conversation source filter normalization, while stream
	// sort keys and the new inventory's numeric bounds have their own contract.
	copy.Del("sort")
	var err error
	o.conversationOptions, err = parseConversationOptions(copy)
	if err != nil {
		return o, err
	}
	if o.ClusterID == nil || o.From == "" || o.To == "" {
		return o, fmt.Errorf("cluster_id, from and to are required")
	}
	o.Options, err = inventorylist.Parse(values, streamSorts, "bytes")
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
	o.Search = strings.ToLower(strings.TrimSpace(values.Get("q")))
	o.Protocol = strings.ToLower(strings.TrimSpace(values.Get("protocol")))
	o.OrderSQL = streamSorts[o.Sort] + " " + strings.ToUpper(o.Order) + " NULLS LAST,id ASC"
	return o, nil
}

func streamDefinition(org uuid.UUID, o streamOptions) inventorylist.Definition {
	// Reuse every predicate before aggregation, including per-source-cluster
	// platform visibility, group membership and the legacy hour bucket boundary.
	scoped := strings.SplitN(conversationSQL(o.HidePlatform), ", streams AS (", 2)[0]
	namespace := func(value string) string {
		return "CASE WHEN strpos(" + value + ",'/')>0 THEN split_part(" + value + ", '/',1) ELSE '' END"
	}
	fromRole := handler.EvidencePlatformRoleSQL("$1", "$2", "$11", namespace("$11"))
	toRole := handler.EvidencePlatformRoleSQL("$1", "$2", "$12", namespace("$12"))
	return inventorylist.Definition{
		SQL: scoped + `, aggregated AS (
 SELECT jsonb_build_array(protocol,l7_protocol,dst_port,verdict)::text AS id,upper(protocol) AS protocol,upper(COALESCE(l7_protocol,'')) AS application,
 COALESCE(dst_port,0) AS port,lower(verdict) AS verdict,SUM(sum_bytes)::bigint AS bytes,COALESCE(SUM(sum_client_bytes),0)::bigint AS client_bytes,
 COALESCE(SUM(sum_server_bytes),0)::bigint AS server_bytes,SUM(sum_packets)::bigint AS packets,COALESCE(SUM(sum_sessions),0)::bigint AS sessions,
 COALESCE(MAX(max_severity),0)::int AS severity,COALESCE(MAX(max_threat_id),0)::bigint AS threat_id,BOOL_AND(threat_id_complete) AS threat_id_complete,MAX(max_at) AS last_seen_at
 FROM scoped GROUP BY protocol,l7_protocol,dst_port,verdict
 ), roles AS MATERIALIZED (SELECT ` + fromRole + ` AS from_role,` + toRole + ` AS to_role)
 SELECT a.*,roles.from_role,roles.to_role FROM aggregated a CROSS JOIN roles`,
		Columns: "id,protocol,application,port,verdict,bytes,client_bytes,server_bytes,packets,sessions,severity,threat_id,threat_id_complete,last_seen_at,from_platform_role,to_platform_role",
		Args:    []any{org, o.ClusterID, o.Hours, o.Verdict, o.Namespace, o.GroupActive, o.GroupMembers, o.Port, o.Peer, o.Application, o.From, o.To, o.VerdictGroup, o.Search, o.Protocol},
		Where:   `($14::text='' OR strpos(lower(concat_ws(' ',protocol,application,port::text,verdict)),$14)>0) AND ($15::text='' OR lower(protocol)=$15)`,
		Summary: `jsonb_build_object('total',count(*),'bytes',COALESCE(sum(bytes),0),'client_bytes',COALESCE(sum(client_bytes),0),'server_bytes',COALESCE(sum(server_bytes),0),
 'packets',COALESCE(sum(packets),0),'sessions',COALESCE(sum(sessions),0),'blocked',count(*) FILTER(WHERE verdict IN ('deny','denied','block','blocked')),'violating',count(*) FILTER(WHERE verdict IN ('alert','violate')),'threat_id_incomplete',count(*) FILTER(WHERE NOT threat_id_complete))`,
	}
}

func scanStream(row inventorylist.Row) (conversationStream, error) {
	var item conversationStream
	var last time.Time
	err := row.Scan(&item.RowID, &item.Protocol, &item.Application, &item.Port, &item.Verdict, &item.Bytes, &item.ClientBytes, &item.ServerBytes, &item.Packets, &item.Sessions, &item.Severity, &item.ThreatID, &item.ThreatIDComplete, &last, &item.FromPlatformRole, &item.ToPlatformRole)
	item.LastSeenAt = last.UTC().Format(time.RFC3339Nano)
	return item, err
}

func (h *NetworkConversations) EntriesInventory(w http.ResponseWriter, r *http.Request) {
	h.writeStreamInventory(w, r, false)
}
func (h *NetworkConversations) EntriesCSV(w http.ResponseWriter, r *http.Request) {
	h.writeStreamInventory(w, r, true)
}
func (h *NetworkConversations) writeStreamInventory(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		apiutil.WriteStatus(r.Context(), w, 401, "subject required")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 400, "invalid query")
		return
	}
	o, err := parseStreamOptions(values)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, 400, err.Error())
		return
	}
	var owned bool
	if err = h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, subj.OrgID, o.ClusterID).Scan(&owned); err != nil {
		conversationReadError(w)
		return
	}
	if !owned {
		apiutil.WriteStatus(r.Context(), w, 404, "cluster not found")
		return
	}
	o.GroupMembers, o.GroupName, o.GroupActive, err = handler.ResolveGroupFilterMembers(r.Context(), h.db.Pool(), subj.OrgID, o.ClusterID, o.Group)
	if err != nil {
		if err.Error() == "group not found" {
			apiutil.WriteStatus(r.Context(), w, 400, "group not found")
		} else {
			conversationReadError(w)
		}
		return
	}
	d := streamDefinition(subj.OrgID, o)
	if export {
		body, meta, err := inventorylist.CSV(r.Context(), h.db.Pool(), d, o.Options, scanStream,
			[]string{"Aggregate tuple ID", "Cluster ID", "From", "To", "Protocol", "Application", "Port", "Verdict", "Bytes", "Client bytes", "Server bytes", "Packets", "Sessions", "Severity", "Threat ID", "Threat maximum complete", "Last observed", "from_platform_role", "to_platform_role"}, func(row conversationStream) []string {
				return []string{row.RowID, o.ClusterID.String(), o.From, o.To, row.Protocol, row.Application, strconv.Itoa(row.Port), row.Verdict, strconv.FormatInt(row.Bytes, 10), strconv.FormatInt(row.ClientBytes, 10), strconv.FormatInt(row.ServerBytes, 10), strconv.FormatInt(row.Packets, 10), strconv.FormatInt(row.Sessions, 10), strconv.Itoa(row.Severity), strconv.FormatInt(row.ThreatID, 10), strconv.FormatBool(row.ThreatIDComplete), row.LastSeenAt, row.FromPlatformRole, row.ToPlatformRole}
			})
		if err != nil {
			conversationReadError(w)
			return
		}
		inventorylist.WriteCSV(w, "conversation-streams.csv", body, meta)
		return
	}
	items, meta, err := inventorylist.Read(r.Context(), h.db.Pool(), d, o.Options, scanStream)
	if err != nil {
		conversationReadError(w)
		return
	}
	filters := map[string]any{"hours": o.Hours, "namespace": o.Namespace, "group": o.Group, "verdict": o.Verdict, "from": o.From, "to": o.To, "verdict_group": o.VerdictGroup, "port": o.Port, "peer": o.Peer, "application": o.Application, "hide_platform": o.HidePlatform, "q": o.Search, "protocol": o.Protocol}
	httpx.WriteJSON(w, 200, map[string]any{"cluster_id": o.ClusterID, "from": o.From, "to": o.To, "window_hours": o.Hours, "entries": items, "totals": meta.Summary, "summary": meta.Summary, "total": meta.Total,
		"limit": o.Limit, "offset": o.Offset, "has_more": meta.HasMore, "sort": o.Sort, "order": o.Order, "filters": filters, "source": "rollups", "source_complete": true, "summary_scope": "matching_retained_rollup_streams"})
}
