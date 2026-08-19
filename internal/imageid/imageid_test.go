package imageid

import "testing"

func TestParse(t *testing.T) {
	cases := map[string]Identity{
		"ubuntu": {
			Normalized: "docker.io/library/ubuntu:latest",
			Repository: "docker.io/library/ubuntu",
			Tag:        "latest",
		},
		"library/ubuntu": {
			Normalized: "docker.io/library/ubuntu:latest",
			Repository: "docker.io/library/ubuntu",
			Tag:        "latest",
		},
		"ghcr.io/acme/api:dev": {
			Normalized: "ghcr.io/acme/api:dev",
			Repository: "ghcr.io/acme/api",
			Tag:        "dev",
		},
		"repo/app@sha256:abc123": {
			Normalized: "docker.io/repo/app@sha256:abc123",
			Repository: "docker.io/repo/app",
			Digest:     "sha256:abc123",
		},
		"localhost:5000/repo/app:tag@sha256:def456": {
			Normalized: "localhost:5000/repo/app:tag@sha256:def456",
			Repository: "localhost:5000/repo/app",
			Tag:        "tag",
			Digest:     "sha256:def456",
		},
		"sha256:localonly": {
			Normalized: "sha256:localonly",
			Digest:     "sha256:localonly",
		},
	}
	for ref, want := range cases {
		got := Parse(ref)
		if got.Raw != ref || got.Normalized != want.Normalized || got.Repository != want.Repository || got.Tag != want.Tag || got.Digest != want.Digest {
			t.Fatalf("Parse(%q) = %+v, want %+v", ref, got, want)
		}
	}
}
