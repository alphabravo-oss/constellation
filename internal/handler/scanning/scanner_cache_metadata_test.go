package scanning

import (
	"encoding/json"
	"testing"
)

func TestScannerCacheMetadataPreservesUnknownAndZero(t *testing.T) {
	var metadata map[string]any
	err := json.Unmarshal([]byte(`{"cache_health":{"grype":{"capacity_known":true,"capacity_bytes":4096,"free_bytes":0,"filesystem_free_bytes":512,"inodes_known":true,"capacity_inodes":10,"free_inodes":0,"usage_complete":false,"usage_entries_visited":2000,"usage_error":"partial read","records_truncated":true},"legacy":{"free_bytes":12}}}`), &metadata)
	if err != nil {
		t.Fatal(err)
	}
	entries := (scannerCacheRow{Metadata: metadata}).cacheEntries()
	if len(entries) != 2 {
		t.Fatal(entries)
	}
	got := entries[0]
	if !got.CapacityKnown || got.CapacityBytes != 4096 || got.FreeBytes != 0 || got.FilesystemFreeBytes != 512 || !got.InodesKnown || got.CapacityInodes != 10 || got.FreeInodes != 0 || got.UsageComplete == nil || *got.UsageComplete || got.UsageEntriesVisited != 2000 || got.UsageError != "partial read" || !got.RecordsTruncated {
		t.Fatalf("metadata lost: %+v", got)
	}
	if entries[1].UsageComplete != nil || entries[1].CapacityKnown {
		t.Fatalf("legacy values invented: %+v", entries[1])
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["free_bytes"] != float64(0) || wire["free_inodes"] != float64(0) || wire["usage_complete"] != false {
		t.Fatalf("zero or partial values omitted: %s", data)
	}
}
