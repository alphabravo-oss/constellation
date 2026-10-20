package handler

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

type backupInventoryFilters struct {
	Query  string `json:"q"`
	Status string `json:"status"`
	Mode   string `json:"mode"`
	Signed string `json:"signed"`
}
type backupInventoryOptions struct {
	inventorylist.Options
	backupInventoryFilters
}
type backupInventoryRow struct {
	backupSummary
	OrgID uuid.UUID `json:"org_id"`
}
type backupInventoryPage struct {
	inventorylist.Metadata
	Backups        []backupInventoryRow   `json:"backups"`
	OrgID          uuid.UUID              `json:"org_id"`
	Filters        backupInventoryFilters `json:"filters"`
	LatestSuccess  *backupInventoryRow    `json:"latest_success"`
	Limit          int                    `json:"limit"`
	Offset         int                    `json:"offset"`
	Sort           string                 `json:"sort"`
	Order          string                 `json:"order"`
	SourceComplete bool                   `json:"source_complete"`
	SummaryScope   string                 `json:"summary_scope"`
}

var backupInventorySorts = map[string]string{"when": "started_at", "mode": "mode", "size": "size_bytes", "status": "status", "signer": "lower(signer_identity)"}

func parseBackupInventoryOptions(values url.Values) (backupInventoryOptions, error) {
	o := backupInventoryOptions{}
	for _, entries := range values {
		if len(entries) != 1 {
			return o, fmt.Errorf("duplicate query parameter")
		}
	}
	var err error
	o.Options, err = inventorylist.Parse(values, backupInventorySorts, "when")
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
	o.Query = strings.ToLower(strings.TrimSpace(values.Get("q")))
	if o.Status, err = inventorylist.Filter(values, "status", "running", "succeeded", "failed"); err != nil {
		return o, err
	}
	if o.Mode, err = inventorylist.Filter(values, "mode", "org-backup", "pg-dump"); err != nil {
		return o, err
	}
	o.Signed, err = inventorylist.Filter(values, "signed", "true", "false")
	return o, err
}

const backupInventorySelect = `id::text,COALESCE(mode,'org-backup'),status,started_at,finished_at,COALESCE(size_bytes,0),COALESCE(sha256,''),COALESCE(signed,false),COALESCE(signer_identity,''),COALESCE(format_version,''),COALESCE(s3_uri,''),COALESCE(tables_included,'{}'::text[]),COALESCE(error,''),org_id`
const backupInventoryWhere = `org_id=$1 AND ($2::text='' OR strpos(lower(concat_ws(' ',id::text,mode,status,signer_identity,format_version,s3_uri,error,array_to_string(tables_included,' '))),$2)>0) AND ($3::text='' OR status=$3) AND ($4::text='' OR mode=$4) AND ($5::text='' OR signed=($5='true'))`

func scanBackupInventory(row inventorylist.Row) (backupInventoryRow, error) {
	var b backupInventoryRow
	err := row.Scan(&b.ID, &b.Mode, &b.Status, &b.StartedAt, &b.FinishedAt, &b.SizeBytes, &b.SHA256, &b.Signed, &b.SignerIdentity, &b.FormatVersion, &b.S3URI, &b.TablesIncluded, &b.ErrorMessage, &b.OrgID)
	return b, err
}
func (h *Backups) readInventory(ctx context.Context, org uuid.UUID, o backupInventoryOptions) (backupInventoryPage, error) {
	out := backupInventoryPage{Backups: []backupInventoryRow{}, OrgID: org, Filters: o.backupInventoryFilters, Limit: o.Limit, Offset: o.Offset, Sort: o.Sort, Order: o.Order, SourceComplete: true, SummaryScope: "matching_owned_backup_runs"}
	tx, err := h.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	args := []any{org, o.Query, o.Status, o.Mode, o.Signed}
	var summary []byte
	err = tx.QueryRow(ctx, `SELECT count(*),jsonb_build_object('total',count(*),'running',count(*) FILTER(WHERE status='running'),'succeeded',count(*) FILTER(WHERE status='succeeded'),'failed',count(*) FILTER(WHERE status='failed'),'signed',count(*) FILTER(WHERE signed),'size_bytes',COALESCE(sum(COALESCE(size_bytes,0)),0)) FROM backups WHERE `+backupInventoryWhere, args...).Scan(&out.Total, &summary)
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(summary, &out.Summary); err != nil {
		return out, err
	}
	latest, err := scanBackupInventory(tx.QueryRow(ctx, `SELECT `+backupInventorySelect+` FROM backups WHERE org_id=$1 AND status='succeeded' ORDER BY started_at DESC,id ASC LIMIT 1`, org))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if err == nil {
		out.LatestSuccess = &latest
	}
	args = append(args, o.Limit, o.Offset)
	rows, err := tx.Query(ctx, `SELECT `+backupInventorySelect+` FROM backups WHERE `+backupInventoryWhere+` ORDER BY `+o.OrderSQL+` LIMIT $6 OFFSET $7`, args...)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		b, e := scanBackupInventory(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Backups = append(out.Backups, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	out.HasMore = int64(o.Offset)+int64(len(out.Backups)) < out.Total
	return out, nil
}
func (h *Backups) Inventory(w http.ResponseWriter, r *http.Request)    { h.inventory(w, r, false) }
func (h *Backups) InventoryCSV(w http.ResponseWriter, r *http.Request) { h.inventory(w, r, true) }
func (h *Backups) inventory(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid query")
		return
	}
	o, err := parseBackupInventoryOptions(values)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if export {
		o.Limit = inventorylist.ExportLimit
		o.Offset = 0
	}
	data, err := h.readInventory(r.Context(), subj.OrgID, o)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Backup history is unavailable")
		return
	}
	if !export {
		writeJSON(w, http.StatusOK, data)
		return
	}
	var body bytes.Buffer
	writer := csv.NewWriter(&body)
	_ = writer.Write([]string{"id", "org_id", "mode", "status", "started_at", "finished_at", "size_bytes", "sha256", "signed", "signer_identity", "format_version", "s3_uri", "tables_included", "error"})
	for _, b := range data.Backups {
		finished := ""
		if b.FinishedAt != nil {
			finished = b.FinishedAt.UTC().Format(time.RFC3339Nano)
		}
		tables, _ := json.Marshal(b.TablesIncluded)
		if err = writer.Write([]string{b.ID, b.OrgID.String(), b.Mode, b.Status, b.StartedAt.UTC().Format(time.RFC3339Nano), finished, strconv.FormatInt(b.SizeBytes, 10), b.SHA256, strconv.FormatBool(b.Signed), b.SignerIdentity, b.FormatVersion, b.S3URI, string(tables), b.ErrorMessage}); err != nil {
			jsonError(w, 500, "Backup metadata export is unavailable")
			return
		}
	}
	writer.Flush()
	if writer.Error() != nil {
		jsonError(w, 500, "Backup metadata export is unavailable")
		return
	}
	w.Header().Set("X-Export-Org-ID", subj.OrgID.String())
	w.Header().Set("X-Export-Scope", "matching_owned_backup_runs")
	inventorylist.WriteCSV(w, "constellation-backup-metadata.csv", body.Bytes(), data.Metadata)
}
