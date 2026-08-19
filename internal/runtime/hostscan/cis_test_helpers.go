//go:build test_helpers || !test_helpers

package hostscan

import "os"

// osMkdirAll and writeFile centralize the os import for cis_test.go's
// writeTree helper. Kept in a regular .go file so it links cleanly
// regardless of build tags.
func osMkdirAll(dir string) error  { return os.MkdirAll(dir, 0o755) }
func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}
