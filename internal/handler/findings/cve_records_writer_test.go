//go:build integration

package findings

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
)

func TestCVEImportSkipsUnchangedAndSparseRows(t *testing.T) {
	t.Parallel()
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()
	id := "CVE-TEST-" + uuid.NewString()
	defer func() { _, _ = pool.Exec(ctx, `DELETE FROM cve_records WHERE cve_id=$1`, id) }()
	row := cveImportRow{id: id, title: "original", description: "retained description", aliases: []string{"alias"}, sources: []string{"nvd"}}
	if err := upsertCVERows(ctx, pool, []cveImportRow{row}); err != nil {
		t.Fatal(err)
	}
	version := func() string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, `SELECT xmin::text FROM cve_records WHERE cve_id=$1`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := version()
	for _, candidate := range []cveImportRow{row, {id: id}} {
		if err := upsertCVERows(ctx, pool, []cveImportRow{candidate}); err != nil {
			t.Fatal(err)
		}
		if after := version(); after != before {
			t.Fatalf("unchanged merged row rewritten: %s -> %s", before, after)
		}
	}
	row.title = "changed"
	if err := upsertCVERows(ctx, pool, []cveImportRow{row}); err != nil {
		t.Fatal(err)
	}
	if version() == before {
		t.Fatal("changed data was not updated")
	}
	var title, description string
	if err := pool.QueryRow(ctx, `SELECT title,description FROM cve_records WHERE cve_id=$1`, id).Scan(&title, &description); err != nil {
		t.Fatal(err)
	}
	if title != "changed" || description != "retained description" {
		t.Fatalf("bad merged row: %q %q", title, description)
	}
	if err := upsertCVERows(ctx, pool, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCVEHistoricalProvenanceSurvivesFeedWithdrawal(t *testing.T) {
	t.Parallel()
	pool := checkpointPool(t)
	ctx := t.Context()
	rows := []cveImportRow{
		{id: "CVE-2026-12345", sources: []string{"nvd", "nvd"}, aliases: []string{"B", "A"}},
		{id: "CVE-2026-12345", sources: []string{"kev", "epss"}, kevListed: true, aliases: []string{"C"}},
		{id: "CVE-2026-12345", sources: []string{"nvd"}},
	}
	for _, row := range rows {
		if err := upsertCVERows(ctx, pool, []cveImportRow{row}); err != nil {
			t.Fatal(err)
		}
	}
	var sources, aliases []string
	var kev bool
	var before, after string
	if err := pool.QueryRow(ctx, `SELECT sources,aliases,kev_listed,xmin::text FROM cve_records WHERE cve_id='CVE-2026-12345'`).Scan(&sources, &aliases, &kev, &before); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sources, []string{"epss", "kev", "nvd"}) || !slices.Equal(aliases, []string{"A", "B", "C"}) || !kev {
		t.Fatalf("lost historical observations: %v %v %v", sources, aliases, kev)
	}
	for _, row := range rows {
		if err := upsertCVERows(ctx, pool, []cveImportRow{row}); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.QueryRow(ctx, `SELECT xmin::text FROM cve_records WHERE cve_id='CVE-2026-12345'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("alternating feeds rewrote unchanged provenance")
	}
}
