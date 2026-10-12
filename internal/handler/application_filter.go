package handler

import "strings"

// ApplicationFilterPorts returns well-known ports for named traffic filters.
// This is a port-based hint, not verified application-protocol evidence.
func ApplicationFilterPorts(raw string) []int {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "http":
		return []int{80, 8080, 8000}
	case "https", "tls":
		return []int{443, 8443}
	case "dns":
		return []int{53}
	case "ssh":
		return []int{22}
	case "mysql":
		return []int{3306}
	case "postgres", "postgresql":
		return []int{5432}
	case "redis":
		return []int{6379}
	case "mongodb", "mongo":
		return []int{27017}
	default:
		return nil
	}
}
