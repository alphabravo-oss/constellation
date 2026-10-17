//go:build fips

package version

import "crypto/fips140"

// Every supported FIPS role imports version. Reject a disabled or different
// cryptographic module before main can serve requests or start agent work.
func init() {
	if !fips140.Enabled() || fips140.Version() != "v1.0.0" {
		panic("constellation: FIPS build requires enabled Go Cryptographic Module v1.0.0")
	}
}
