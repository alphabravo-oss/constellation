package hostscan

import "os"

// These helpers create the readable host filesystem fixtures used by cis_test.go.
func osMkdirAll(dir string) error { return os.MkdirAll(dir, 0o755) }
func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}
