package auditarchive

import (
	"testing"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestArchiveTrustConfiguration(t *testing.T) {
	t.Parallel()
	valid := Config{Bucket: "test", BatchSize: 1, Signer: backup.SignerOptions{Mode: backup.SignModeStaticKey, KeyPath: "private"}, Verifier: backup.VerifierOptions{Mode: backup.SignModeStaticKey, KeyPath: "trusted-public"}}
	for _, tc := range []struct {
		name   string
		change func(*Config)
		valid  bool
	}{
		{"static", func(*Config) {}, true},
		{"unsigned", func(c *Config) { c.Signer.Mode = backup.SignModeNone }, false},
		{"unknown", func(c *Config) { c.Signer.Mode = "typo" }, false},
		{"missing trust", func(c *Config) { c.Verifier.KeyPath = "" }, false},
		{"mode mismatch", func(c *Config) { c.Verifier.Mode = backup.SignModeKeyless }, false},
		{"keyless wildcard", func(c *Config) { c.Signer.Mode = backup.SignModeKeyless; c.Verifier.Mode = backup.SignModeKeyless }, false},
		{"keyless identity", func(c *Config) {
			c.Signer.Mode = backup.SignModeKeyless
			c.Verifier.Mode = backup.SignModeKeyless
			c.Verifier.Identity = "expected"
		}, true},
		{"zero batch", func(c *Config) { c.BatchSize = 0 }, false},
		{"huge batch", func(c *Config) { c.BatchSize = MaxBatch + 1 }, false},
		{"no destination", func(c *Config) { c.Bucket = "" }, false},
		{"unsigned local", func(c *Config) {
			c.DryRun = true
			c.Bucket = ""
			c.Signer.Mode = backup.SignModeNone
			c.Verifier = backup.VerifierOptions{}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := valid
			tc.change(&c)
			if err := c.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
