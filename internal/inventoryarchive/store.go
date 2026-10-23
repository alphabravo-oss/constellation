package inventoryarchive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Export reads a single bounded inventory and its target identity in one SQL
// snapshot. It does not mark anything eligible for expiry or change source data.
func Export(ctx context.Context, pool *pgxpool.Pool, orgID, evidenceID uuid.UUID, privateKey, publicKey string) ([]byte, Report, error) {
	var report Report
	if orgID == uuid.Nil || evidenceID == uuid.Nil {
		return nil, report, errors.New("organization and evidence IDs required")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var raw, targetRaw []byte
	err := pool.QueryRow(bounded, `SELECT to_jsonb(e),jsonb_build_object('type',t.type,'ref',t.ref,'source_type',t.source_type,'source_ref',t.source_ref)
 FROM scan_evidence e JOIN scan_targets t ON t.id=e.scan_target_id AND t.org_id=e.org_id
 WHERE e.org_id=$1 AND e.id=$2 AND octet_length(to_jsonb(e)::text)<=$3`, orgID, evidenceID, MaxRecordBytes).Scan(&raw, &targetRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, report, errors.New("inventory evidence missing, out of scope, or exceeds byte limit")
	}
	if err != nil {
		return nil, report, err
	}
	var row record
	var target targetIdentity
	if err = strictJSON(raw, &row); err != nil {
		return nil, report, err
	}
	if err = strictJSON(targetRaw, &target); err != nil {
		return nil, report, err
	}
	return encode(ctx, row, target, privateKey, publicKey)
}

// RestoreResult describes insertion or an identical existing record. Restore
// never overwrites an existing inventory or creates targets/credentials for it.
type RestoreResult struct {
	Report   Report    `json:"archive"`
	OrgID    uuid.UUID `json:"destination_org_id"`
	TargetID uuid.UUID `json:"destination_target_id"`
	Inserted bool      `json:"inserted"`
}

// Restore requires explicit destination scope. A target must already exist in
// that organization with the signed type/ref/source identity. Cluster context
// comes from that locked destination target, not an untrusted foreign UUID.
func Restore(ctx context.Context, pool *pgxpool.Pool, input io.Reader, publicKey string, orgID, targetID uuid.UUID) (RestoreResult, error) {
	var result RestoreResult
	if orgID == uuid.Nil || targetID == uuid.Nil {
		return result, errors.New("explicit destination organization and target required")
	}
	row, m, report, err := verify(ctx, input, publicKey)
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
	cluster, err := lockDestination(ctx, tx, orgID, targetID, m.Target)
	if err != nil {
		return result, err
	}
	row.OrgID, row.TargetID, row.ClusterID = orgID, targetID, cluster
	raw, err := json.Marshal(row)
	if err != nil {
		return result, err
	}
	inserted, err := restoreRecord(ctx, tx, row.ID, raw)
	if err != nil {
		return result, err
	}
	if inserted {
		_, _, err = audit.New(pool).LogInTx(ctx, tx, audit.Event{OrgID: &orgID, Action: "scan.evidence.restore", TargetKind: "scan_evidence", TargetID: row.ID.String(), After: map[string]any{
			"archive_sha256": report.ArchiveSHA256, "record_sha256": report.RecordSHA256, "signer_identity": report.SignerIdentity,
			"source_org_id": report.OrgID, "source_target_id": report.TargetID, "destination_target_id": targetID, "package_count": row.PackageCount,
		}})
		if err != nil {
			return result, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return RestoreResult{Report: report, OrgID: orgID, TargetID: targetID, Inserted: inserted}, nil
}

func lockDestination(ctx context.Context, tx pgx.Tx, orgID, targetID uuid.UUID, want targetIdentity) (*uuid.UUID, error) {
	var cluster *uuid.UUID
	var same bool
	err := tx.QueryRow(ctx, `SELECT cluster_id,type=$3 AND ref=$4 AND source_type=$5 AND source_ref IS NOT DISTINCT FROM $6::text
 FROM scan_targets WHERE org_id=$1 AND id=$2 FOR UPDATE`, orgID, targetID, want.Type, want.Ref, want.SourceType, want.SourceRef).Scan(&cluster, &same)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !same {
		return nil, errors.New("destination target does not match signed inventory identity")
	}
	return cluster, err
}

func restoreRecord(ctx context.Context, tx pgx.Tx, id uuid.UUID, raw []byte) (bool, error) {
	var inserted uuid.UUID
	err := tx.QueryRow(ctx, `INSERT INTO scan_evidence
 (id,org_id,scan_target_id,cluster_id,target_type,target_ref,source_type,source_ref,evidence_type,inventory_hash,package_count,payload,observed_at,expires_at,created_at)
 SELECT id,org_id,scan_target_id,cluster_id,target_type,target_ref,source_type,source_ref,evidence_type,inventory_hash,package_count,payload,observed_at,expires_at,created_at
 FROM jsonb_populate_record(NULL::scan_evidence,$1::jsonb) ON CONFLICT(id) DO NOTHING RETURNING id`, raw).Scan(&inserted)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	var identical bool
	err = tx.QueryRow(ctx, `SELECT to_jsonb(e)=to_jsonb(jsonb_populate_record(NULL::scan_evidence,$2::jsonb)) FROM scan_evidence e WHERE e.id=$1 FOR UPDATE`, id, raw).Scan(&identical)
	if err != nil {
		return false, err
	}
	if !identical {
		return false, errors.New("existing inventory differs; restore never overwrites evidence")
	}
	return false, nil
}
