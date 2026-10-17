//go:build fips

package version

import (
	"crypto/fips140"
	"testing"
)

func TestFIPSRuntime(t *testing.T) {
	if !fips140.Enabled() || fips140.Version() != "v1.0.0" {
		t.Fatalf("FIPS runtime: enabled=%v module=%s", fips140.Enabled(), fips140.Version())
	}
	t.Logf("FIPS runtime enabled; Go Cryptographic Module %s", fips140.Version())
}
