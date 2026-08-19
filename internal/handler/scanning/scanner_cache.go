package scanning

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
)

type ScannerCache struct {
	db *db.DB
}

func NewScannerCache(database *db.DB) *ScannerCache {
	return &ScannerCache{db: database}
}

type scannerCacheStatDTO struct {
	ScannerID       string                 `json:"scanner_id"`
	Hostname        string                 `json:"hostname"`
	ClusterID       string                 `json:"cluster_id,omitempty"`
	ClusterName     string                 `json:"cluster_name,omitempty"`
	Status          string                 `json:"status"`
	LastSeenAt      string                 `json:"last_seen_at"`
	RecordCount     int64                  `json:"record_count"`
	RecordSizeBytes int64                  `json:"record_size_bytes"`
	CacheMisses     int64                  `json:"cache_misses"`
	CacheHits       int64                  `json:"cache_hits"`
	Caches          []scannerCacheEntryDTO `json:"caches"`
}

type scannerCacheDataDTO struct {
	ScannerID       string                  `json:"scanner_id"`
	Hostname        string                  `json:"hostname"`
	ClusterID       string                  `json:"cluster_id,omitempty"`
	ClusterName     string                  `json:"cluster_name,omitempty"`
	Status          string                  `json:"status"`
	LastSeenAt      string                  `json:"last_seen_at"`
	RecordSizeBytes int64                   `json:"record_size_bytes"`
	CacheMisses     int64                   `json:"cache_misses"`
	CacheHits       int64                   `json:"cache_hits"`
	CacheRecords    []scannerCacheRecordDTO `json:"cache_records"`
}

type scannerCacheEntryDTO struct {
	Name             string `json:"name"`
	Path             string `json:"path,omitempty"`
	Status           string `json:"status"`
	Configured       bool   `json:"configured"`
	Present          bool   `json:"present"`
	Writable         bool   `json:"writable"`
	RecordCount      int64  `json:"record_count"`
	RecordSizeBytes  int64  `json:"record_size_bytes"`
	FreeBytes        int64  `json:"free_bytes,omitempty"`
	RecordsTruncated bool   `json:"records_truncated,omitempty"`
	Error            string `json:"error,omitempty"`
}

type scannerCacheRecordDTO struct {
	Cache    string `json:"cache"`
	Layer    string `json:"layer"`
	Size     int64  `json:"size"`
	RefCount int64  `json:"ref_count"`
	RefLast  string `json:"ref_last,omitempty"`
}

type scanScannerListDTO struct {
	Scanners []scanScannerDTO `json:"scanners"`
}

type scanScannerDTO struct {
	ID                string `json:"id"`
	CVEDBVersion      string `json:"cvedb_version,omitempty"`
	CVEDBCreateTime   string `json:"cvedb_create_time,omitempty"`
	JoinedTimestamp   int64  `json:"joined_timestamp"`
	Server            string `json:"server"`
	Port              int    `json:"port"`
	ScannedContainers int64  `json:"scanned_containers"`
	ScannedHosts      int64  `json:"scanned_hosts"`
	ScannedImages     int64  `json:"scanned_images"`
	ScannedServerless int64  `json:"scanned_serverless"`
}

type compatScanCacheStatDTO struct {
	RecordCount     int64 `json:"record_count"`
	RecordTotalSize int64 `json:"record_total_size"`
	CacheMisses     int64 `json:"cache_misses"`
	CacheHits       int64 `json:"cache_hits"`
}

type compatScanCacheDataDTO struct {
	CacheRecords    []compatScanCacheRecordDTO `json:"cache_records"`
	RecordTotalSize int64                      `json:"record_total_size"`
	CacheMisses     int64                      `json:"cache_misses"`
	CacheHits       int64                      `json:"cache_hits"`
}

type compatScanCacheRecordDTO struct {
	LayerID        string `json:"layer_id"`
	Size           int64  `json:"size"`
	ReferenceCount int64  `json:"reference_count"`
	LastReferred   string `json:"last_referred,omitempty"`
}

func (h *ScannerCache) List(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "scanner-cache: db not wired")
		return
	}
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "missing subject")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT COALESCE(ch.metadata->>'instance_id', ch.hostname) AS scanner_id,
       ch.hostname,
       ch.first_seen_at,
       ch.metadata
  FROM component_heartbeats ch
 WHERE ch.org_id = $1
   AND ch.component = 'scanner'
   AND ch.last_seen_at > NOW() - INTERVAL '24 hours'
 ORDER BY scanner_id`, subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := scanScannerListDTO{Scanners: []scanScannerDTO{}}
	for rows.Next() {
		var (
			item      scanScannerDTO
			firstSeen time.Time
			raw       []byte
			metadata  map[string]any
		)
		if err := rows.Scan(&item.ID, &item.Server, &firstSeen, &raw); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &metadata)
		}
		vuln := handler.MetadataMap(metadata, "vulndb")
		item.CVEDBVersion = handler.MetadataString(vuln, "bundle_version")
		item.CVEDBCreateTime = handler.MetadataString(vuln, "exported_at")
		item.JoinedTimestamp = firstSeen.Unix()
		out.Scanners = append(out.Scanners, item)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *ScannerCache) Stat(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "scanner-cache: db not wired")
		return
	}
	row, ok := h.loadScannerCacheRow(w, r)
	if !ok {
		return
	}
	stat := row.stat()
	httpx.WriteJSON(w, http.StatusOK, stat)
}

func (h *ScannerCache) Data(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "scanner-cache: db not wired")
		return
	}
	row, ok := h.loadScannerCacheRow(w, r)
	if !ok {
		return
	}
	data := row.data()
	httpx.WriteJSON(w, http.StatusOK, data)
}

func (h *ScannerCache) CompatStat(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "scanner-cache: db not wired")
		return
	}
	row, ok := h.loadScannerCacheRow(w, r)
	if !ok {
		return
	}
	stat := row.stat()
	httpx.WriteJSON(w, http.StatusOK, compatScanCacheStatDTO{
		RecordCount:     stat.RecordCount,
		RecordTotalSize: stat.RecordSizeBytes,
		CacheMisses:     stat.CacheMisses,
		CacheHits:       stat.CacheHits,
	})
}

func (h *ScannerCache) CompatData(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "scanner-cache: db not wired")
		return
	}
	row, ok := h.loadScannerCacheRow(w, r)
	if !ok {
		return
	}
	data := row.data()
	out := compatScanCacheDataDTO{
		RecordTotalSize: data.RecordSizeBytes,
		CacheMisses:     data.CacheMisses,
		CacheHits:       data.CacheHits,
		CacheRecords:    []compatScanCacheRecordDTO{},
	}
	for _, record := range data.CacheRecords {
		out.CacheRecords = append(out.CacheRecords, compatScanCacheRecordDTO{
			LayerID:        record.Layer,
			Size:           record.Size,
			ReferenceCount: record.RefCount,
			LastReferred:   record.RefLast,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type scannerCacheRow struct {
	ScannerID   string
	Hostname    string
	ClusterID   string
	ClusterName string
	Status      string
	LastSeenAt  time.Time
	Metadata    map[string]any
}

func (h *ScannerCache) loadScannerCacheRow(w http.ResponseWriter, r *http.Request) (scannerCacheRow, bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "missing subject")
		return scannerCacheRow{}, false
	}
	scannerID := chi.URLParam(r, "scanner_id")
	if scannerID == "" {
		jsonError(w, http.StatusBadRequest, "missing scanner_id")
		return scannerCacheRow{}, false
	}
	row := scannerCacheRow{}
	var raw []byte
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT COALESCE(ch.metadata->>'instance_id', ch.hostname) AS scanner_id,
       ch.hostname,
       COALESCE(ch.cluster_id::text, ''),
       COALESCE(c.name, ''),
       CASE
         WHEN ch.last_seen_at <= NOW() - INTERVAL '2 minutes' THEN 'stale'
         WHEN COALESCE(ch.metadata->'vulndb'->>'enabled', 'false')::boolean
              AND NOT COALESCE(ch.metadata->'vulndb'->>'ready', 'false')::boolean THEN 'degraded'
         ELSE 'ready'
       END AS status,
       ch.last_seen_at,
       ch.metadata
  FROM component_heartbeats ch
  LEFT JOIN clusters c ON c.id = ch.cluster_id
 WHERE ch.org_id = $1
   AND ch.component = 'scanner'
   AND (
       ch.hostname = $2
       OR ch.metadata->>'instance_id' = $2
   )
 ORDER BY ch.last_seen_at DESC
 LIMIT 1`, subj.OrgID, scannerID).Scan(&row.ScannerID, &row.Hostname, &row.ClusterID, &row.ClusterName, &row.Status, &row.LastSeenAt, &raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "scanner cache not found")
			return scannerCacheRow{}, false
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return scannerCacheRow{}, false
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &row.Metadata)
	}
	return row, true
}

func (r scannerCacheRow) stat() scannerCacheStatDTO {
	out := scannerCacheStatDTO{
		ScannerID:   r.ScannerID,
		Hostname:    r.Hostname,
		ClusterID:   r.ClusterID,
		ClusterName: r.ClusterName,
		Status:      r.cacheStatus(),
		LastSeenAt:  r.LastSeenAt.UTC().Format(time.RFC3339),
		CacheMisses: int64(handler.MetadataInt(r.Metadata, "cache_misses")),
		CacheHits:   int64(handler.MetadataInt(r.Metadata, "cache_hits")),
	}
	for _, entry := range r.cacheEntries() {
		out.RecordCount += entry.RecordCount
		out.RecordSizeBytes += entry.RecordSizeBytes
		out.Caches = append(out.Caches, entry)
	}
	return out
}

func (r scannerCacheRow) data() scannerCacheDataDTO {
	stat := r.stat()
	out := scannerCacheDataDTO{
		ScannerID:       stat.ScannerID,
		Hostname:        stat.Hostname,
		ClusterID:       stat.ClusterID,
		ClusterName:     stat.ClusterName,
		Status:          stat.Status,
		LastSeenAt:      stat.LastSeenAt,
		RecordSizeBytes: stat.RecordSizeBytes,
		CacheMisses:     stat.CacheMisses,
		CacheHits:       stat.CacheHits,
	}
	cacheHealth := handler.MetadataMap(r.Metadata, "cache_health")
	names := make([]string, 0, len(cacheHealth))
	for name := range cacheHealth {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		item, _ := cacheHealth[name].(map[string]any)
		for _, raw := range metadataSlice(item, "records") {
			record, _ := raw.(map[string]any)
			if len(record) == 0 {
				continue
			}
			out.CacheRecords = append(out.CacheRecords, scannerCacheRecordDTO{
				Cache:    name,
				Layer:    handler.MetadataString(record, "layer"),
				Size:     int64(handler.MetadataInt(record, "size")),
				RefCount: int64(handler.MetadataInt(record, "ref_count")),
				RefLast:  handler.MetadataString(record, "ref_last"),
			})
		}
	}
	return out
}

func (r scannerCacheRow) cacheStatus() string {
	if r.Status == "stale" {
		return "stale"
	}
	for _, entry := range r.cacheEntries() {
		if entry.Configured && (!entry.Present || !entry.Writable || entry.Status != "ready") {
			return "degraded"
		}
	}
	return r.Status
}

func (r scannerCacheRow) cacheEntries() []scannerCacheEntryDTO {
	cacheHealth := handler.MetadataMap(r.Metadata, "cache_health")
	names := make([]string, 0, len(cacheHealth))
	for name := range cacheHealth {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]scannerCacheEntryDTO, 0, len(names))
	for _, name := range names {
		raw, _ := cacheHealth[name].(map[string]any)
		if len(raw) == 0 {
			continue
		}
		out = append(out, scannerCacheEntryDTO{
			Name:             name,
			Path:             handler.MetadataString(raw, "path"),
			Status:           handler.MetadataString(raw, "status"),
			Configured:       handler.MetadataBool(raw, "configured"),
			Present:          handler.MetadataBool(raw, "present"),
			Writable:         handler.MetadataBool(raw, "writable"),
			RecordCount:      int64(handler.MetadataInt(raw, "record_count")),
			RecordSizeBytes:  int64(handler.MetadataInt(raw, "record_size_bytes")),
			FreeBytes:        int64(handler.MetadataInt(raw, "free_bytes")),
			RecordsTruncated: handler.MetadataBool(raw, "records_truncated"),
			Error:            handler.MetadataString(raw, "error"),
		})
	}
	return out
}

func metadataSlice(source map[string]any, key string) []any {
	if len(source) == 0 {
		return nil
	}
	switch value := source[key].(type) {
	case []any:
		return value
	default:
		return nil
	}
}
