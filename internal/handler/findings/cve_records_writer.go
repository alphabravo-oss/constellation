package findings

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// cveImportMu serializes imports so the periodic reconcilers (KEV+EPSS, NVD)
// never run two full cve_records writes at once.
var cveImportMu sync.Mutex

// cveImportRow is one cve_records upsert row. Shared by the KEV+EPSS importer
// (cve_intel_import.go) and the NVD importer (nvd_import.go).
type cveImportRow struct {
	id          string
	title       string
	description string
	cvssBase    *float64
	cvssVector  string
	kevListed   bool
	kevAdded    *time.Time
	epss        *float64
	epssAt      *time.Time
	aliases     []string
	sources     []string
	published   *time.Time
	modified    *time.Time
}

// upsertCVERows writes one multi-row INSERT ... ON CONFLICT, merging with
// COALESCE so a sparser duplicate (e.g. a distro advisory) never clobbers a
// richer existing row (e.g. NVD).
func upsertCVERows(ctx context.Context, pool *pgxpool.Pool, rows []cveImportRow) error {
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
			r.id, r.title, r.description, r.cvssBase, r.cvssVector,
			r.kevListed, r.kevAdded, r.epss, r.epssAt,
			strOrEmpty(r.aliases), strOrEmpty(r.sources), r.published, r.modified)
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
        aliases=CASE WHEN cardinality(EXCLUDED.aliases)>0 THEN EXCLUDED.aliases ELSE cve_records.aliases END,
        sources=CASE WHEN cardinality(EXCLUDED.sources)>0 THEN EXCLUDED.sources ELSE cve_records.sources END,
        published_at=COALESCE(EXCLUDED.published_at,cve_records.published_at),
        modified_at=COALESCE(EXCLUDED.modified_at,cve_records.modified_at)`)
	_, err := pool.Exec(ctx, sb.String(), args...)
	return err
}

// strOrEmpty avoids sending NULL into the NOT NULL TEXT[] columns (a nil slice
// encodes as NULL; an empty slice encodes as '{}').
func strOrEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// shortHash truncates a content hash for log lines.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
