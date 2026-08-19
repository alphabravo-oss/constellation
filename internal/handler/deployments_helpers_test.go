package handler

// containsString is a per-package test-helper copy (the canonical definition
// moved with the netpolicy domain tests in internal/handler/netpolicy). Each Go
// package owns its own small test helpers.
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
