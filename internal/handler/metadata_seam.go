package handler

import "encoding/json"

// This file hosts the metadata JSON-map accessor seams shared between package
// handler and the extracted sub-packages. The canonical (unexported)
// declarations live here so the non-moved parent files that consume them
// (components_inventory, system_health) keep compiling unchanged, while exported
// wrappers let the handler sub-packages (handler/findings, handler/scanning,
// handler/compliance) reach the same logic without an import cycle.
//
// These formerly lived in connector_coverage.go (now relocated to the
// handler/compliance sub-package); kept here so the rest of package handler
// still resolves them.

func metadataMap(source map[string]any, key string) map[string]any {
	if source == nil {
		return nil
	}
	value, _ := source[key].(map[string]any)
	return value
}

// The Metadata* functions below are exported seams over the unexported
// metadata* JSON-map accessors, used by handler sub-packages (e.g.
// handler/findings) during the D2 god-package split.

// MetadataMap is the exported seam over metadataMap.
func MetadataMap(source map[string]any, key string) map[string]any { return metadataMap(source, key) }

// MetadataString is the exported seam over metadataString.
func MetadataString(source map[string]any, key string) string { return metadataString(source, key) }

// MetadataBool is the exported seam over metadataBool.
func MetadataBool(source map[string]any, key string) bool { return metadataBool(source, key) }

// MetadataInt is the exported seam over metadataInt.
func MetadataInt(source map[string]any, key string) int { return metadataInt(source, key) }

// ScannerHeartbeatDegradedReason is the exported seam over the unexported
// scannerHeartbeatDegradedReason in system_health.go. It is consumed by the
// handler/compliance sub-package (connector_coverage.go) to derive scanner pool
// health, while the canonical implementation stays in package handler alongside
// system_health.go.
func ScannerHeartbeatDegradedReason(metadata map[string]any) string {
	return scannerHeartbeatDegradedReason(metadata)
}

func metadataString(source map[string]any, key string) string {
	if source == nil {
		return ""
	}
	value, _ := source[key].(string)
	return value
}

func metadataBool(source map[string]any, key string) bool {
	if source == nil {
		return false
	}
	value, _ := source[key].(bool)
	return value
}

func metadataInt(source map[string]any, key string) int {
	if source == nil {
		return 0
	}
	switch value := source[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case int64:
		return int(value)
	case json.Number:
		n, _ := value.Int64()
		return int(n)
	default:
		return 0
	}
}
