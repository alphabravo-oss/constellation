package scanner

import (
	"strings"
	"testing"
)

func TestRegistryEnvInheritsProcessEnvironmentAndAppendsCredentials(t *testing.T) {
	t.Setenv("CONSTELLATION_SCANNER_ENV_SENTINEL", "present")

	env := registryEnv(ScanOptions{
		Username:          "alice",
		Password:          "secret",
		RegistryAuthority: "ghcr.io",
		DockerConfigDir:   "/tmp/job-xyz",
	})

	if got := envValue(env, "CONSTELLATION_SCANNER_ENV_SENTINEL"); got != "present" {
		t.Fatalf("sentinel env=%q want present", got)
	}
	// The scan tools read these; DOCKER_USER/DOCKER_PASSWORD were dead and are gone.
	for key, want := range map[string]string{
		"TRIVY_USERNAME":               "alice",
		"TRIVY_PASSWORD":               "secret",
		"GRYPE_REGISTRY_AUTH_USERNAME": "alice",
		"GRYPE_REGISTRY_AUTH_PASSWORD": "secret",
		"SYFT_REGISTRY_AUTH_USERNAME":  "alice",
		"SYFT_REGISTRY_AUTH_PASSWORD":  "secret",
		"GRYPE_REGISTRY_AUTH_AUTHORITY": "ghcr.io",
		"SYFT_REGISTRY_AUTH_AUTHORITY":  "ghcr.io",
		"DOCKER_CONFIG":                 "/tmp/job-xyz",
	} {
		if got := envValue(env, key); got != want {
			t.Fatalf("%s=%q want %q", key, got, want)
		}
	}
	if got := envValue(env, "DOCKER_USER"); got != "" {
		t.Fatalf("DOCKER_USER should no longer be exported, got %q", got)
	}
}

func TestRegistryEnvOmitsCredentialVarsWithoutCredentials(t *testing.T) {
	env := registryEnv(ScanOptions{})
	for _, key := range []string{"TRIVY_USERNAME", "GRYPE_REGISTRY_AUTH_USERNAME", "SYFT_REGISTRY_AUTH_USERNAME", "DOCKER_CONFIG"} {
		if got := envValue(env, key); got != "" {
			t.Fatalf("%s should be unset without credentials, got %q", key, got)
		}
	}
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return strings.TrimPrefix(env[i], prefix)
		}
	}
	return ""
}
