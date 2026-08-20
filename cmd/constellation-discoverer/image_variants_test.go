package main

import (
	"strings"
	"testing"
)

func TestImageRefRegistryVariants(t *testing.T) {
	cases := []struct {
		in   string
		want []string // must all be present
	}{
		// The core bug: K8s status form must also key under the bare spec ref.
		{"docker.io/constellation/api:gs17", []string{"docker.io/constellation/api:gs17", "constellation/api:gs17"}},
		{"index.docker.io/constellation/scanner:gs16", []string{"index.docker.io/constellation/scanner:gs16", "constellation/scanner:gs16"}},
		// Official images drop the library/ namespace too.
		{"docker.io/library/postgres:16", []string{"docker.io/library/postgres:16", "library/postgres:16", "postgres:16"}},
		// A private registry ref is unchanged (only itself).
		{"ghcr.io/acme/api:1.2", []string{"ghcr.io/acme/api:1.2"}},
		{"", nil},
	}
	for _, c := range cases {
		got := imageRefRegistryVariants(c.in)
		joined := strings.Join(got, ",")
		for _, w := range c.want {
			found := false
			for _, g := range got {
				if g == w {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%q: missing variant %q (got %s)", c.in, w, joined)
			}
		}
		// ghcr should not gain spurious stripped forms.
		if c.in == "ghcr.io/acme/api:1.2" && len(got) != 1 {
			t.Fatalf("private registry ref should be unchanged, got %s", joined)
		}
	}
}
