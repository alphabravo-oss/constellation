package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestHostFactsAttributesToBundleCluster covers the multi-tenant host
// attribution fix (finding M). The old ingest path resolved cluster_id as the
// org's OLDEST cluster, so two nodes named the same in different clusters
// collapsed onto one cluster row and overwrote each other. The fix resolves the
// reporting agent's real cluster from the init-bundle that minted its token.
//
// It also covers the NULL-safe dedup: a token with no init-bundle yields
// cluster_id=NULL, and repeated reports for the same node must update one row
// (via the COALESCE(cluster_id, nil-uuid) unique index, migration 111) rather
// than inserting unbounded duplicates.
func TestHostFactsAttributesToBundleCluster(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := httptest.NewRequest("GET", "/", nil).Context()
	pool := d.Pool()

	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.host_facts')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: host_facts migration not applied (%v)", err)
	}
	// Confirm migration 111's NULL-safe unique index exists; otherwise the
	// dedup assertion below cannot hold.
	var hasIdx bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'uniq_host_facts_org_cluster_node')`).Scan(&hasIdx); err != nil {
		t.Fatal(err)
	}
	if !hasIdx {
		t.Skip("skipping: migration 111 (uniq_host_facts_org_cluster_node) not applied")
	}

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	tokenName := "host-facts-attr-" + suffix
	node := "shared-node-" + suffix
	nodeNull := "null-node-" + suffix

	// Cleanup any prior state for this run (and on completion).
	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM host_facts WHERE org_id = $1 AND node IN ($2, $3)`, orgID, node, nodeNull)
		_, _ = pool.Exec(ctx, `DELETE FROM cluster_init_bundles WHERE name = $1`, tokenName)
		_, _ = pool.Exec(ctx, `DELETE FROM runtime_agent_tokens WHERE name = $1`, tokenName)
		_, _ = pool.Exec(ctx, `DELETE FROM clusters WHERE org_id = $1 AND name LIKE $2`, orgID, "attr-cl-"+suffix+"-%")
	}
	cleanup()
	t.Cleanup(cleanup)

	// Two distinct clusters in the same org.
	mkCluster := func(name string) uuid.UUID {
		var id uuid.UUID
		if err := pool.QueryRow(ctx,
			`INSERT INTO clusters (org_id, name, state) VALUES ($1, $2, 'connected') RETURNING id`,
			orgID, name).Scan(&id); err != nil {
			t.Fatalf("create cluster %s: %v", name, err)
		}
		return id
	}
	clusterA := mkCluster("attr-cl-" + suffix + "-a")
	clusterB := mkCluster("attr-cl-" + suffix + "-b")

	// One agent token per cluster, each mapped via an init-bundle row.
	mkBundleToken := func(clusterID uuid.UUID) string {
		raw, tokID, err := IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
INSERT INTO cluster_init_bundles
  (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted)
VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`,
			orgID, clusterID, tokenName, tokID); err != nil {
			t.Fatalf("insert bundle: %v", err)
		}
		return raw
	}
	tokenA := mkBundleToken(clusterA)
	tokenB := mkBundleToken(clusterB)

	report := func(tok, nodeName string, at time.Time) {
		body, _ := json.Marshal(HostFacts{Node: nodeName, ObservedAt: at})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/host-facts:report", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(NewHostFacts(d).Report)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("report status %d: %s", rec.Code, rec.Body.String())
		}
	}

	// Same node name reported by both clusters' agents must NOT collapse:
	// two rows, each attributed to its own cluster.
	report(tokenA, node, time.Now().UTC())
	report(tokenB, node, time.Now().UTC())

	rows, err := pool.Query(ctx, `SELECT cluster_id FROM host_facts WHERE org_id = $1 AND node = $2`, orgID, node)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID]bool{}
	for rows.Next() {
		var cid *uuid.UUID
		if err := rows.Scan(&cid); err != nil {
			t.Fatal(err)
		}
		if cid == nil {
			t.Fatalf("expected non-null cluster_id for bundle-mapped token")
		}
		got[*cid] = true
	}
	rows.Close()
	if len(got) != 2 || !got[clusterA] || !got[clusterB] {
		t.Fatalf("attribution = %v, want exactly {A:%s, B:%s}", got, clusterA, clusterB)
	}

	// NULL-cluster token: a token with no init-bundle mapping. Repeated reports
	// for the same node must dedup to one row, not grow unbounded.
	rawNull, _, err := IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	report(rawNull, nodeNull, time.Now().UTC().Add(-time.Minute))
	report(rawNull, nodeNull, time.Now().UTC())
	report(rawNull, nodeNull, time.Now().UTC().Add(time.Minute))

	var n int
	var nullCID *uuid.UUID
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM host_facts WHERE org_id = $1 AND node = $2`, orgID, nodeNull).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("null-cluster node row count = %d, want 1 (unbounded-growth regression)", n)
	}
	if err := pool.QueryRow(ctx,
		`SELECT cluster_id FROM host_facts WHERE org_id = $1 AND node = $2`, orgID, nodeNull).Scan(&nullCID); err != nil {
		t.Fatal(err)
	}
	if nullCID != nil {
		t.Fatalf("null-cluster node cluster_id = %v, want NULL", nullCID)
	}
}
