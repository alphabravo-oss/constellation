// Package socketfixture creates short, private Unix socket test directories.
package socketfixture

import (
	"os"
	"testing"
)

// Dir avoids the test name and GOTMPDIR prefix used by testing.T.TempDir, which
// can exceed the Unix socket address limit before the socket filename is added.
// /tmp is intentional: even TMPDIR can be longer than a socket address permits.
func Dir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}
