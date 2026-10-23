package findings

import (
	"context"
	"time"

	"github.com/alphabravocompany/constellation/internal/cvecatalog"
)

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

func upsertCVERows(ctx context.Context, pool cvecatalog.Writer, rows []cveImportRow) error {
	observations := make([]cvecatalog.Row, len(rows))
	for i, r := range rows {
		observations[i] = cvecatalog.Row{
			ID:          r.id,
			Title:       r.title,
			Description: r.description,
			CVSSBase:    r.cvssBase,
			CVSSVector:  r.cvssVector,
			KEVListed:   r.kevListed,
			KEVAdded:    r.kevAdded,
			EPSS:        r.epss,
			EPSSAt:      r.epssAt,
			Aliases:     r.aliases,
			Sources:     r.sources,
			Published:   r.published,
			Modified:    r.modified,
		}
	}
	return cvecatalog.Upsert(ctx, pool, observations)
}

// shortHash truncates a content hash for log lines.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
