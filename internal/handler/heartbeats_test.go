package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestKnownComponentsUseCanonicalChartNames(t *testing.T) {
	for _, component := range []string{
		"audit-archiver",
		"network-policy-applier",
		"vulndb-importer",
		"k8s-compliance-collector",
	} {
		if _, ok := knownComponents[component]; !ok {
			t.Fatalf("known components missing %q", component)
		}
	}
	for _, component := range []string{"archiver", "netpolicy-applier"} {
		if _, ok := knownComponents[component]; ok {
			t.Fatalf("non-canonical component %q should not be accepted", component)
		}
	}
}

func TestAnyServiceTokenMiddlewareAcceptsPrefixlessScannerToken(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	tokenID := uuid.New()
	raw := "legacy-scanner-" + uuid.NewString()
	hash := tokenHashForTest(raw)
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Legacy Scanner Heartbeat Test')`, orgID, "legacy-scanner-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scanner_tokens (id, org_id, name, token_hash)
VALUES ($1, $2, 'legacy-scanner', $3)`, tokenID, orgID, hash); err != nil {
		t.Fatalf("scanner token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	req := httptest.NewRequest("POST", "/api/v1/heartbeats", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	AnyServiceTokenMiddleware(pool)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := scannerTokenFrom(r.Context())
		if !ok || tok == nil {
			t.Fatal("scanner token subject missing")
		}
		if tok.ID != tokenID || tok.OrgID != orgID {
			t.Fatalf("scanner token subject = %+v", tok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
}

func TestAnyServiceTokenMiddlewareAcceptsPrefixlessRuntimeAgentToken(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	tokenID := uuid.New()
	raw := "legacy-runtime-" + uuid.NewString()
	hash := tokenHashForTest(raw)
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Legacy Runtime Heartbeat Test')`, orgID, "legacy-runtime-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO runtime_agent_tokens (id, org_id, name, token_hash)
VALUES ($1, $2, 'legacy-runtime', $3)`, tokenID, orgID, hash); err != nil {
		t.Fatalf("runtime token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	req := httptest.NewRequest("POST", "/api/v1/heartbeats", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	AnyServiceTokenMiddleware(pool)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := runtimeAgentTokenFrom(r.Context())
		if !ok || tok == nil {
			t.Fatal("runtime-agent token subject missing")
		}
		if tok.ID != tokenID || tok.OrgID != orgID {
			t.Fatalf("runtime-agent token subject = %+v", tok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
}

func TestHeartbeatsIngestUpsertsPrefixlessScannerWithNullCluster(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	raw := "legacy-scanner-heartbeat-" + uuid.NewString()
	hash := tokenHashForTest(raw)
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scanner Heartbeat Upsert Test')`, orgID, "scanner-heartbeat-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scanner_tokens (org_id, name, token_hash)
VALUES ($1, 'scanner-heartbeat', $2)`, orgID, hash); err != nil {
		t.Fatalf("scanner token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	h := NewHeartbeats(d, nil)
	handler := AnyServiceTokenMiddleware(pool)(http.HandlerFunc(h.Ingest))
	for i, uptime := range []int{10, 40, 70} {
		body := `{
			"component":"scanner",
			"version":"dev",
			"commit":"dev",
			"hostname":"scanner-null-cluster",
			"uptime_seconds":` + strconv.Itoa(uptime) + `
		}`
		req := httptest.NewRequest("POST", "/api/v1/heartbeats", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+raw)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat %d status: %d body: %s", i+1, w.Code, w.Body.String())
		}
	}

	var count int
	if err := pool.QueryRow(ctx, `
SELECT count(*)
  FROM component_heartbeats
 WHERE org_id = $1
   AND cluster_id IS NULL
   AND component = 'scanner'
   AND hostname = 'scanner-null-cluster'`, orgID).Scan(&count); err != nil {
		t.Fatalf("count heartbeats: %v", err)
	}
	if count != 1 {
		t.Fatalf("heartbeat rows = %d, want 1", count)
	}
	var metadata map[string]any
	if err := pool.QueryRow(ctx, `
SELECT metadata
  FROM component_heartbeats
 WHERE org_id = $1
   AND cluster_id IS NULL
   AND component = 'scanner'
   AND hostname = 'scanner-null-cluster'`, orgID).Scan(&metadata); err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if len(metadata) != 0 {
		t.Fatalf("metadata without payload = %+v", metadata)
	}
}

func TestHeartbeatsIngestResolvesClusterName(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	clusterID := uuid.New()
	raw := "scanner-heartbeat-cluster-name-" + uuid.NewString()
	hash := tokenHashForTest(raw)
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scanner Heartbeat Cluster Name Test')`, orgID, "scanner-heartbeat-cluster-name-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state)
VALUES ($1, $2, 'local', 'k3s', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scanner_tokens (org_id, name, token_hash)
VALUES ($1, 'scanner-heartbeat-cluster-name', $2)`, orgID, hash); err != nil {
		t.Fatalf("scanner token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	body := `{
		"component":"scanner",
		"cluster_name":"local",
		"version":"dev",
		"commit":"dev",
		"hostname":"scanner-cluster-name",
		"uptime_seconds":10
	}`
	req := httptest.NewRequest("POST", "/api/v1/heartbeats", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	AnyServiceTokenMiddleware(pool)(http.HandlerFunc(NewHeartbeats(d, nil).Ingest)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}

	var got uuid.UUID
	if err := pool.QueryRow(ctx, `
SELECT cluster_id
  FROM component_heartbeats
 WHERE org_id = $1
   AND component = 'scanner'
   AND hostname = 'scanner-cluster-name'`, orgID).Scan(&got); err != nil {
		t.Fatalf("cluster_id: %v", err)
	}
	if got != clusterID {
		t.Fatalf("cluster_id = %s, want %s", got, clusterID)
	}
}

func TestHeartbeatsIngestPersistsMetadata(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	raw := "scanner-heartbeat-metadata-" + uuid.NewString()
	hash := tokenHashForTest(raw)
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scanner Heartbeat Metadata Test')`, orgID, "scanner-heartbeat-metadata-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scanner_tokens (org_id, name, token_hash)
VALUES ($1, 'scanner-heartbeat-metadata', $2)`, orgID, hash); err != nil {
		t.Fatalf("scanner token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	body := `{
		"component":"scanner",
		"version":"dev",
		"commit":"dev",
		"hostname":"scanner-metadata",
		"uptime_seconds":10,
		"metadata":{
			"max_concurrent":4,
			"active_jobs":2,
			"target_capacity":{"image":2,"host":4},
			"vulndb":{"enabled":true,"ready":true,"status":"ready","bundle_version":"fixture"}
		}
	}`
	req := httptest.NewRequest("POST", "/api/v1/heartbeats", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	AnyServiceTokenMiddleware(pool)(http.HandlerFunc(NewHeartbeats(d, nil).Ingest)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}

	var rawMetadata []byte
	if err := pool.QueryRow(ctx, `
SELECT metadata
  FROM component_heartbeats
 WHERE org_id = $1
   AND component = 'scanner'
   AND hostname = 'scanner-metadata'`, orgID).Scan(&rawMetadata); err != nil {
		t.Fatalf("metadata: %v", err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(rawMetadata, &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if metadata["active_jobs"].(float64) != 2 {
		t.Fatalf("metadata = %+v", metadata)
	}
	rows, err := LoadHeartbeats(ctx, pool, orgID)
	if err != nil {
		t.Fatalf("load heartbeats: %v", err)
	}
	if len(rows) != 1 || metadataInt(rows[0].Metadata, "active_jobs") != 2 {
		t.Fatalf("loaded heartbeat metadata = %+v", rows)
	}
	if vuln := metadataMap(rows[0].Metadata, "vulndb"); !metadataBool(vuln, "ready") || metadataString(vuln, "bundle_version") != "fixture" {
		t.Fatalf("loaded vulndb metadata = %+v", rows[0].Metadata)
	}
}

func tokenHashForTest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
