package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/sigverify"
)

func TestSignatureVerificationUsesJobRegistryConfig(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	t.Setenv("DOCKER_AUTH_CONFIG", `{"auths":{"ambient":{"auth":"secret"}}}`)
	t.Setenv("TRIVY_PASSWORD", "ambient-secret")
	script := filepath.Join(t.TempDir(), "cosign")
	// The fake verifier refuses ambient credentials and checks the actual config.
	content := `#!/bin/sh
 test -z "$DOCKER_AUTH_CONFIG" && test -z "$TRIVY_PASSWORD" || exit 11
 test -f "$DOCKER_CONFIG/config.json" || exit 12
 grep -q 'private-secret' "$DOCKER_CONFIG/config.json" || exit 13
 echo '[{"optional":{}}]'
 `
	if err := os.WriteFile(script, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- executable test fixture, accessible only to its owner.
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	server := registryCredentialsServer(t, nil)
	defer server.Close()
	worker := &worker{controlPlane: server.URL, token: "scanner-token", logger: nopLogger{}}
	registryID := "private-secret"
	auth, cleanup, err := worker.resolveRegistryAuth(t.Context(), &scanJob{ID: "leased-job", RegistryID: &registryID}, "ghcr.io/team/app:latest")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	roots := sigverify.RootsOfTrust{{TrustPolicy: sigverify.TrustPolicy{Mode: "public-key", PublicKeyPEM: "test key"}}}
	result := verifyImageSignature(t.Context(), "ghcr.io/team/app@sha256:"+strings.Repeat("a", 64), script, roots, auth)
	if result.Status != "trusted" {
		t.Fatalf("signature verification did not use isolated config: %+v", result)
	}
	cleanup()
	assertRemoved(t, auth.DockerConfigDir)
}
