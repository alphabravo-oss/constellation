package scanner

import (
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestImageConfigChecksRecognizeDigestPinning(t *testing.T) {
	for _, tc := range []struct{ ref, status string }{
		{"example.com/app@sha256:" + strings.Repeat("a", 64), "pass"},
		{"example.com/app:latest@sha256:" + strings.Repeat("a", 64), "pass"},
		{"example.com/app:latest", "warn"},
		{"example.com/app", "warn"},
		{"example.com/app:v1", "pass"},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			ref, err := name.ParseReference(tc.ref)
			if err != nil {
				t.Fatal(err)
			}
			report := imageConfigChecksFrom(tc.ref, "linux/amd64", ref, &v1.ConfigFile{})
			for _, check := range report.Checks {
				if check.ID == "image-latest-tag" {
					if check.Status != tc.status {
						t.Fatalf("pinning status=%s want %s", check.Status, tc.status)
					}
					return
				}
			}
			t.Fatal("missing pinning control")
		})
	}
}
