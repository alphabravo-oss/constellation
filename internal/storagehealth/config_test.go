package storagehealth

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/auditarchive"
)

func TestArchiveDestinationMatchesPublisherWithEmptyAndDynamicEndpoints(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, explicit, s3, generic, want string }{
		{"explicit", "explicit", "s3", "generic", "explicit"},
		{"S3", "", "s3", "generic", "s3"},
		{"empty S3 secret", "", "", "generic", "generic"},
		{"AWS default", "", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := ArchiveDestination{Enabled: true, Endpoint: tc.explicit, EndpointS3: tc.s3, EndpointDefault: tc.generic, Bucket: "bucket", Prefix: " /audit/ "}
			want := auditarchive.DestinationID(tc.want, "bucket", "audit")
			if got := c.StreamID(); got != want {
				t.Fatalf("destination mismatch: %s != %s", got, want)
			}
			c.Enabled = false
			if c.StreamID() != "" {
				t.Fatal("disabled destination observed")
			}
		})
	}
}
