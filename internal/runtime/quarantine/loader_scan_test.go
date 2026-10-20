package quarantine

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	corev1 "k8s.io/api/core/v1"

	pkgquar "github.com/alphabravocompany/constellation/pkg/quarantine"
)

func TestPgLoaderPreservesAutomaticScanMatching(t *testing.T) {
	url := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("test database not configured")
	}
	pool, err := pgxpool.New(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "scan-matching-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM quarantine_entries WHERE org_id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'scan-matching')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO quarantine_entries(org_id,cluster_id,scope,match_key,reason,origin,source_kind) VALUES($1,$2,'image','ghcr.io/acme/api','test','auto','scan')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	entries, err := (&PgLoader{Pool: pool}).Load(t.Context(), cluster)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Origin != "auto" || entries[0].SourceKind != "scan" {
		t.Fatalf("matching provenance lost: %+v", entries)
	}
	snapshot := pkgquar.BuildSnapshot(cluster, time.Now(), entries)
	for _, tc := range []struct {
		image string
		hit   bool
	}{{"ghcr.io/acme/api:1", true}, {"ghcr.io/acme/api-helper:1", false}} {
		pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "candidate", Image: tc.image}}}}
		if (snapshot.Match(pod) != nil) != tc.hit {
			t.Fatalf("loaded match %s wrong", tc.image)
		}
	}
}
