//go:build integration

package scanning

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestScannerCacheStatAndDataFromHeartbeatMetadata(t *testing.T) {
	t.Parallel()
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scanner Cache Test')`,
		orgID, "scanner-cache-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Scanner Cache Admin')`,
		userID, orgID, "scanner-cache-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'local', 'connected')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats (
    org_id, cluster_id, component, version, commit, hostname, uptime_seconds, restart_count, metadata, last_seen_at
) VALUES ($1,$2,'scanner','test','abc','scanner-0',120,0,$3::jsonb,NOW())`,
		orgID,
		clusterID,
		`{
		  "instance_id": "scanner-instance-1",
		  "cache_hits": 7,
		  "cache_misses": 3,
		  "cache_health": {
		    "syft": {
		      "path": "/cache/syft",
		      "configured": true,
		      "present": true,
		      "writable": true,
		      "status": "ready",
		      "record_count": 2,
		      "record_size_bytes": 3072,
		      "free_bytes": 0,
          "capacity_known": true,
          "capacity_bytes": 8388608,
          "filesystem_free_bytes": 4096,
          "inodes_known": true,
          "capacity_inodes": 100,
          "free_inodes": 0,
          "usage_complete": false,
          "usage_entries_visited": 2000,
          "records_truncated": true,
		      "records": [
		        {"layer":"sha256/a","size":2048,"ref_count":1,"ref_last":"2026-06-14T08:00:00Z"},
		        {"layer":"sha256/b","size":1024,"ref_count":1,"ref_last":"2026-06-14T08:01:00Z"}
		      ]
		    },
		    "grype": {
		      "path": "/cache/grype",
		      "configured": true,
		      "present": false,
		      "writable": false,
		      "status": "missing",
		      "error": "stat /cache/grype: no such file"
		    }
		  }
		}`); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	router := chi.NewRouter()
	cache := NewScannerCache(d)
	router.Get("/api/v1/scan/scanner", cache.List)
	router.Get("/api/v1/scan/cache_stat/{scanner_id}", cache.CompatStat)
	router.Get("/api/v1/scan/cache_data/{scanner_id}", cache.CompatData)
	router.Get("/api/v1/scanner-cache/{scanner_id}/stat", cache.Stat)
	router.Get("/api/v1/scanner-cache/{scanner_id}/data", cache.Data)

	listReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scan/scanner", nil)
	listReq = listReq.WithContext(authctx.WithSubject(listReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listResp.Code, listResp.Body.String())
	}
	var list scanScannerListDTO
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Scanners) != 1 || list.Scanners[0].ID != "scanner-instance-1" || list.Scanners[0].CVEDBVersion != "" {
		t.Fatalf("scanner list = %+v", list)
	}

	statReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scanner-cache/scanner-instance-1/stat", nil)
	statReq = statReq.WithContext(authctx.WithSubject(statReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	statResp := httptest.NewRecorder()
	router.ServeHTTP(statResp, statReq)
	if statResp.Code != http.StatusOK {
		t.Fatalf("stat status=%d body=%s", statResp.Code, statResp.Body.String())
	}
	var stat scannerCacheStatDTO
	if err := json.NewDecoder(statResp.Body).Decode(&stat); err != nil {
		t.Fatal(err)
	}
	if stat.ScannerID != "scanner-instance-1" || stat.Hostname != "scanner-0" || stat.ClusterName != "local" {
		t.Fatalf("stat identity = %+v", stat)
	}
	if stat.Status != "degraded" || stat.RecordCount != 2 || stat.RecordSizeBytes != 3072 || stat.CacheHits != 7 || stat.CacheMisses != 3 {
		t.Fatalf("stat = %+v", stat)
	}
	if len(stat.Caches) != 2 || stat.Caches[0].Name != "grype" || stat.Caches[1].Name != "syft" {
		t.Fatalf("caches should be sorted by name: %+v", stat.Caches)
	}

	cacheEntry := stat.Caches[1]
	if !cacheEntry.CapacityKnown || cacheEntry.CapacityBytes != 8388608 || cacheEntry.FreeBytes != 0 || cacheEntry.FilesystemFreeBytes != 4096 || !cacheEntry.InodesKnown || cacheEntry.CapacityInodes != 100 || cacheEntry.FreeInodes != 0 || cacheEntry.UsageComplete == nil || *cacheEntry.UsageComplete || cacheEntry.UsageEntriesVisited != 2000 || !cacheEntry.RecordsTruncated {
		t.Fatalf("heartbeat diagnostics lost through PostgreSQL/API: %+v", cacheEntry)
	}
	if stat.Caches[0].UsageComplete != nil || stat.Caches[0].CapacityKnown {
		t.Fatalf("missing cache gained invented capacity/completeness: %+v", stat.Caches[0])
	}

	dataReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scanner-cache/scanner-instance-1/data", nil)
	dataReq = dataReq.WithContext(authctx.WithSubject(dataReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	dataResp := httptest.NewRecorder()
	router.ServeHTTP(dataResp, dataReq)
	if dataResp.Code != http.StatusOK {
		t.Fatalf("data status=%d body=%s", dataResp.Code, dataResp.Body.String())
	}
	var data scannerCacheDataDTO
	if err := json.NewDecoder(dataResp.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if data.Status != "degraded" || len(data.CacheRecords) != 2 {
		t.Fatalf("data = %+v", data)
	}
	if data.CacheRecords[0].Cache != "syft" || data.CacheRecords[0].Layer != "sha256/a" || data.CacheRecords[0].Size != 2048 {
		t.Fatalf("cache records = %+v", data.CacheRecords)
	}

	compatStatReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scan/cache_stat/scanner-instance-1", nil)
	compatStatReq = compatStatReq.WithContext(authctx.WithSubject(compatStatReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	compatStatResp := httptest.NewRecorder()
	router.ServeHTTP(compatStatResp, compatStatReq)
	if compatStatResp.Code != http.StatusOK {
		t.Fatalf("compat stat status=%d body=%s", compatStatResp.Code, compatStatResp.Body.String())
	}
	var compatStat compatScanCacheStatDTO
	if err := json.NewDecoder(compatStatResp.Body).Decode(&compatStat); err != nil {
		t.Fatal(err)
	}
	if compatStat.RecordCount != 2 || compatStat.RecordTotalSize != 3072 || compatStat.CacheHits != 7 || compatStat.CacheMisses != 3 {
		t.Fatalf("compat stat = %+v", compatStat)
	}

	compatDataReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scan/cache_data/scanner-instance-1", nil)
	compatDataReq = compatDataReq.WithContext(authctx.WithSubject(compatDataReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	compatDataResp := httptest.NewRecorder()
	router.ServeHTTP(compatDataResp, compatDataReq)
	if compatDataResp.Code != http.StatusOK {
		t.Fatalf("compat data status=%d body=%s", compatDataResp.Code, compatDataResp.Body.String())
	}
	var compatData compatScanCacheDataDTO
	if err := json.NewDecoder(compatDataResp.Body).Decode(&compatData); err != nil {
		t.Fatal(err)
	}
	if compatData.RecordTotalSize != 3072 || len(compatData.CacheRecords) != 2 || compatData.CacheRecords[0].LayerID != "sha256/a" || compatData.CacheRecords[0].ReferenceCount != 1 {
		t.Fatalf("compat data = %+v", compatData)
	}
}
