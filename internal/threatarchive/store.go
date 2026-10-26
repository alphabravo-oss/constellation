package threatarchive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/archiveio"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Export returns one bounded page in [From,Through), strictly after After.
// Concurrent backdated writes can precede a cursor: pages are point-in-time
// exports, not a cross-request database snapshot or proof permitting pruning.
func Export(ctx context.Context, pool *pgxpool.Pool, w Window, limit int, private, public string) ([]byte, Report, error) {
	var report Report
	if err := w.Validate(); err != nil {
		return nil, report, err
	}
	if limit < 1 || limit > MaxRows {
		return nil, report, errors.New("page limit must be 1..1000")
	}
	records, more, err := readPage(ctx, pool, w, limit)
	if err != nil {
		return nil, report, err
	}
	if len(records) == 0 {
		return nil, report, errors.New("no matching threat records; no archive written")
	}
	return encode(ctx, w, records, more, private, public)
}

func readPage(ctx context.Context, pool *pgxpool.Pool, w Window, limit int) ([]Record, bool, error) {
	rawRows, more, err := fetchPage(ctx, pool, w, limit)
	if err != nil {
		return nil, false, err
	}
	records := make([]Record, 0, len(rawRows))
	size := 2
	for _, raw := range rawRows {
		if err = ctx.Err(); err != nil {
			return nil, false, err
		}
		var row Record
		if err = archiveio.Decode(raw, &row); err != nil {
			return nil, false, err
		}
		normalized, err := json.Marshal(row)
		if err != nil {
			return nil, false, err
		}
		if len(normalized) > MaxRecordBytes {
			return nil, false, errors.New("threat record exceeds archive limit; source retained")
		}
		if size+len(normalized)+1 > MaxBatchBytes {
			return records, true, nil
		}
		size += len(normalized) + 1
		records = append(records, row)
	}
	return records, more, nil
}

// Fetch closes the database reader before CPU-intensive strict JSON validation.
// Both the raw fetch buffer and the final normalized page are byte bounded.
func fetchPage(ctx context.Context, pool *pgxpool.Pool, w Window, limit int) ([][]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx, `SELECT CASE WHEN octet_length(to_jsonb(e)::text)<=$7 THEN to_jsonb(e) || jsonb_build_object('packet',CASE WHEN packet IS NULL THEN NULL ELSE '\x'||encode(packet,'hex') END) ELSE NULL END
 FROM runtime_threats e WHERE org_id=$1 AND cluster_id=$2 AND at >= $3 AND at < $4
 AND ($5::timestamptz IS NULL OR (at,id)>($5,$6::uuid)) ORDER BY at,id LIMIT $8`, w.OrgID, w.ClusterID, w.From, w.Through, afterTime(w.After), w.After.ID, MaxRecordBytes, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	records := make([][]byte, 0, limit)
	size := 2
	for rows.Next() {
		if len(records) == limit {
			return records, true, nil
		}
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, false, err
		}
		if len(raw) == 0 || len(raw) > MaxRecordBytes {
			return nil, false, errors.New("threat record exceeds archive limit; source retained")
		}
		if size+len(raw)+1 > MaxBatchBytes {
			return records, true, nil
		}
		size += len(raw) + 1
		records = append(records, raw)
	}
	return records, false, rows.Err()
}

func afterTime(c Cursor) *time.Time {
	if c.At.IsZero() {
		return nil
	}
	return &c.At
}

type RestoreResult struct {
	Report    Report    `json:"archive"`
	OrgID     uuid.UUID `json:"destination_org_id"`
	ClusterID uuid.UUID `json:"destination_cluster_id"`
	Inserted  int       `json:"inserted"`
	Existing  int       `json:"existing"`
}

// Restore explicitly maps a verified page to an existing destination cluster.
// It preserves event IDs/timestamps, never overwrites conflicts, and commits all
// rows and a receipt together. This does not re-trigger notification/response rules.
func Restore(ctx context.Context, pool *pgxpool.Pool, input io.Reader, public string, org, cluster uuid.UUID) (RestoreResult, error) {
	var result RestoreResult
	if org == uuid.Nil || cluster == uuid.Nil {
		return result, errors.New("explicit destination scope required")
	}
	records, report, err := verify(ctx, input, public)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	var id uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM clusters WHERE id=$1 AND org_id=$2 FOR SHARE`, cluster, org).Scan(&id); err != nil {
		return result, errors.New("destination cluster unavailable or outside organization")
	}
	inserted := 0
	for _, row := range records {
		row.OrgID, row.ClusterID = org, cluster
		added, err := restoreRecord(ctx, tx, row)
		if err != nil {
			return result, err
		}
		if added {
			inserted++
		}
	}
	if inserted > 0 {
		_, _, err = audit.New(pool).LogInTx(ctx, tx, audit.Event{OrgID: &org, Action: "runtime.threat.restore", TargetKind: "cluster", TargetID: cluster.String(), After: map[string]any{
			"archive_sha256": report.ArchiveSHA256, "records_sha256": report.Manifest.RecordsSHA256, "signer_identity": report.Manifest.SignerIdentity,
			"source_org_id": report.Manifest.Window.OrgID, "source_cluster_id": report.Manifest.Window.ClusterID, "inserted": inserted, "existing": len(records) - inserted,
		}})
		if err != nil {
			return result, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return RestoreResult{report, org, cluster, inserted, len(records) - inserted}, nil
}

func restoreRecord(ctx context.Context, tx pgx.Tx, row Record) (bool, error) {
	raw, err := json.Marshal(row)
	if err != nil {
		return false, err
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO runtime_threats (id,org_id,cluster_id,node,ep_mac,threat_id,severity,action,application,msg,dlp_name_hash,ip_proto,ether_type,src_ip,src_port,dst_ip,dst_port,icmp_code,icmp_type,packet,pkt_len,cap_len,pkt_ingress,sess_ingress,tap_mode,reported_at,at,workload_id,namespace,pod_name)
 SELECT id,org_id,cluster_id,node,ep_mac,threat_id,severity,action,application,msg,dlp_name_hash,ip_proto,ether_type,src_ip,src_port,dst_ip,dst_port,icmp_code,icmp_type,packet,pkt_len,cap_len,pkt_ingress,sess_ingress,tap_mode,reported_at,at,workload_id,namespace,pod_name
 FROM jsonb_populate_record(NULL::runtime_threats,$1::jsonb) ON CONFLICT(id) DO NOTHING RETURNING id`, raw).Scan(&id)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	var same bool
	err = tx.QueryRow(ctx, `SELECT to_jsonb(e)=to_jsonb(jsonb_populate_record(NULL::runtime_threats,$2::jsonb)) FROM runtime_threats e WHERE id=$1 FOR UPDATE`, row.ID, raw).Scan(&same)
	if err != nil {
		return false, err
	}
	if !same {
		return false, errors.New("conflicting threat record; restore never overwrites evidence")
	}
	return false, nil
}
