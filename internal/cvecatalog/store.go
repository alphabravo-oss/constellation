// Package cvecatalog owns persistence of shared vulnerability intelligence.
package cvecatalog

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Row holds an imported observation. Sources, aliases and KEV membership are historical.
type Row struct {
	ID          string
	Title       string
	Description string
	CVSSBase    *float64
	CVSSVector  string
	KEVListed   bool
	KEVAdded    *time.Time
	EPSS        *float64
	EPSSAt      *time.Time
	Aliases     []string
	Sources     []string
	Published   *time.Time
	Modified    *time.Time
}

// Writer is implemented by both a transaction and a pool connection.
type Writer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// Upsert retains prior provenance and avoids rewriting unchanged merged rows.
func Upsert(ctx context.Context, pool Writer, rows []Row) error {
	if len(rows) == 0 {
		return nil
	}
	const cols = 13
	args := make([]any, 0, len(rows)*cols)
	var sb strings.Builder
	sb.WriteString(`INSERT INTO cve_records (cve_id,title,description,cvss_base,cvss_vector,kev_listed,kev_added,epss_probability,epss_updated_at,aliases,sources,published_at,modified_at) VALUES `)
	for i, r := range rows {
		if i > 0 {
			sb.WriteByte(',')
		}
		b := i * cols
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			b+1, b+2, b+3, b+4, b+5, b+6, b+7, b+8, b+9, b+10, b+11, b+12, b+13)
		args = append(args,
			r.ID, r.Title, r.Description, r.CVSSBase, r.CVSSVector,
			r.KEVListed, r.KEVAdded, r.EPSS, r.EPSSAt,
			canonical(r.Aliases), canonical(r.Sources), r.Published, r.Modified)
	}
	sb.WriteString(` ON CONFLICT (cve_id) DO UPDATE SET
        title=COALESCE(NULLIF(EXCLUDED.title,''),cve_records.title),
        description=COALESCE(NULLIF(EXCLUDED.description,''),cve_records.description),
        cvss_base=COALESCE(EXCLUDED.cvss_base,cve_records.cvss_base),
        cvss_vector=COALESCE(NULLIF(EXCLUDED.cvss_vector,''),cve_records.cvss_vector),
        kev_listed=cve_records.kev_listed OR EXCLUDED.kev_listed,
        kev_added=COALESCE(EXCLUDED.kev_added,cve_records.kev_added),
        epss_probability=COALESCE(EXCLUDED.epss_probability,cve_records.epss_probability),
        epss_updated_at=COALESCE(EXCLUDED.epss_updated_at,cve_records.epss_updated_at),
        aliases=ARRAY(SELECT DISTINCT value FROM unnest(cve_records.aliases || EXCLUDED.aliases) AS value ORDER BY value),
        sources=ARRAY(SELECT DISTINCT value FROM unnest(cve_records.sources || EXCLUDED.sources) AS value ORDER BY value),
        published_at=COALESCE(EXCLUDED.published_at,cve_records.published_at),
        modified_at=COALESCE(EXCLUDED.modified_at,cve_records.modified_at)
    WHERE (cve_records.title, cve_records.description, cve_records.cvss_base, cve_records.cvss_vector, cve_records.kev_listed, cve_records.kev_added, cve_records.epss_probability, cve_records.epss_updated_at, cve_records.aliases, cve_records.sources, cve_records.published_at, cve_records.modified_at)
    IS DISTINCT FROM (COALESCE(NULLIF(EXCLUDED.title,''),cve_records.title),
        COALESCE(NULLIF(EXCLUDED.description,''),cve_records.description),
        COALESCE(EXCLUDED.cvss_base,cve_records.cvss_base),
        COALESCE(NULLIF(EXCLUDED.cvss_vector,''),cve_records.cvss_vector),
        cve_records.kev_listed OR EXCLUDED.kev_listed,
        COALESCE(EXCLUDED.kev_added,cve_records.kev_added),
        COALESCE(EXCLUDED.epss_probability,cve_records.epss_probability),
        COALESCE(EXCLUDED.epss_updated_at,cve_records.epss_updated_at),
        ARRAY(SELECT DISTINCT value FROM unnest(cve_records.aliases || EXCLUDED.aliases) AS value ORDER BY value),
        ARRAY(SELECT DISTINCT value FROM unnest(cve_records.sources || EXCLUDED.sources) AS value ORDER BY value),
        COALESCE(EXCLUDED.published_at,cve_records.published_at),
        COALESCE(EXCLUDED.modified_at,cve_records.modified_at))`)
	_, err := pool.Exec(ctx, sb.String(), args...)
	return err
}

// canonical makes inserts and merged replays use the same set representation.
func canonical(values []string) []string {
	result := append([]string{}, values...)
	slices.Sort(result)
	return slices.Compact(result)
}

// CheckpointReader reads a durable feed boundary on the reserved import connection.
type CheckpointReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func CompletedThrough(ctx context.Context, db CheckpointReader, feed, sourceHash string) (time.Time, error) {
	var through time.Time
	err := db.QueryRow(ctx, `SELECT completed_through FROM cve_feed_checkpoints WHERE feed=$1 AND source_hash=$2`, feed, sourceHash).Scan(&through)
	return through, err
}

// SaveCompletedWindow is called in the final page transaction, after row writes.
func SaveCompletedWindow(ctx context.Context, tx pgx.Tx, feed, sourceHash string, end time.Time, count int) error {
	if _, err := tx.Exec(ctx, `SET LOCAL synchronous_commit=on`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO cve_feed_checkpoints(feed,source_hash,completed_through,row_count)
 VALUES ($1,$2,$3,$4) ON CONFLICT(feed) DO UPDATE SET source_hash=EXCLUDED.source_hash,
 completed_through=EXCLUDED.completed_through,row_count=EXCLUDED.row_count,updated_at=now()`, feed, sourceHash, end, count)
	return err
}
