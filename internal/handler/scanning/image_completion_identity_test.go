package scanning

import (
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler"
)

func TestImageCompletionIdentityConsistency(t *testing.T) {
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct {
		name, target, ref, digest, cached string
		ok                                bool
	}{
		{"pinned match", "example.test/app@" + a, "example.test/app@" + a, a, "", true},
		{"pinned mismatch", "example.test/app@" + a, "example.test/app@" + a, b, "", false},
		{"ref conflicts with digest", "example.test/app:latest", "example.test/app@" + a, b, "", false},
		{"foreign repository", "example.test/app:latest", "example.test/other:latest", a, "", false},
		{"child repository", "example.test/app:latest", "example.test/app/child:latest", a, "", false},
		{"docker hub aliases", "alpine:3.21", "docker.io/library/alpine:3.21", a, "", true},
		{"tag moved", "example.test/app:latest", "example.test/app:latest", b, a, true},
		{"cached digest is not scan evidence", "example.test/app:latest", "example.test/app:latest", "", a, false},
		{"bare digest gets name", a, "example.test/app@" + a, a, "", true},
		{"bare digest cannot change", a, "example.test/app@" + b, b, "", false},
		{"pinned omitted response", "example.test/app@" + a, "", "", "", true},
		{"short digest", "example.test/app:latest", "", "sha256:abc", "", false},
		{"nonhex digest", "example.test/app:latest", "", "sha256:" + strings.Repeat("z", 64), "", false},
		{"invalid reference", "example.test/app:latest", "not an image", a, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanCompletionImageIdentity(handler.ScanTarget{Type: "image", Ref: tc.target, ImageDigest: tc.cached}, completeScanRequest{ImageRef: tc.ref, ImageDigest: tc.digest}, "")
			if (err == nil) != tc.ok {
				t.Fatalf("identity=%+v err=%v want ok=%v", got, err, tc.ok)
			}
			if tc.ok && normalizeSecretSHA256(got.Digest) == "" {
				t.Fatalf("invalid stored digest %+v", got)
			}
		})
	}
}
