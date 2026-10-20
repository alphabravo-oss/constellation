package main

import "testing"

func TestInsecureRegistriesMatchHostOnly(t *testing.T) {
	t.Parallel()
	w := &worker{insecureRegistries: parseInsecureRegistries(" registry.airgap.svc:5000 ,LOCAL:5000")}
	cases := map[string]bool{
		"registry.airgap.svc:5000/team/app:v1": true,
		"local:5000/x@sha256:" + "a" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": true,
		"registry.airgap.svc/team/app:v1":             false,
		"ghcr.io/alphabravo-oss/constellation/api:v1": false,
		"docker.io/library/registry.airgap.svc:5000":  false,
	}
	for ref, want := range cases {
		if got := w.insecureFor(ref); got != want {
			t.Fatalf("insecureFor(%q) = %v, want %v", ref, got, want)
		}
	}
	if (&worker{}).insecureFor("local:5000/x:y") {
		t.Fatal("empty list must never mark a registry insecure")
	}
}
