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
		"TRIVY_USERNAME":                "alice",
		"TRIVY_PASSWORD":                "secret",
		"GRYPE_REGISTRY_AUTH_USERNAME":  "alice",
		"GRYPE_REGISTRY_AUTH_PASSWORD":  "secret",
		"SYFT_REGISTRY_AUTH_USERNAME":   "alice",
		"SYFT_REGISTRY_AUTH_PASSWORD":   "secret",
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

func TestRegistryEnvWithoutIsolatedConfigPreservesLegacyEnvironment(t *testing.T) {
	t.Setenv("TRIVY_USERNAME", "ambient-user")
	if got := envValue(registryEnv(ScanOptions{}), "TRIVY_USERNAME"); got != "ambient-user" {
		t.Fatalf("legacy ambient credentials changed: %q", got)
	}
}

func TestRegistryEnvIsolatedConfigExcludesAmbientRegistryCredentials(t *testing.T) {
	for _, key := range []string{
		"DOCKER_CONFIG", "DOCKER_AUTH_CONFIG", "TRIVY_USERNAME", "TRIVY_PASSWORD",
		"GRYPE_REGISTRY_AUTH_USERNAME", "GRYPE_REGISTRY_AUTH_PASSWORD", "GRYPE_REGISTRY_AUTH_AUTHORITY",
		"SYFT_REGISTRY_AUTH_USERNAME", "SYFT_REGISTRY_AUTH_PASSWORD", "SYFT_REGISTRY_AUTH_AUTHORITY",
	} {
		t.Setenv(key, "ambient-secret")
	}
	t.Setenv("CONSTELLATION_SCANNER_ENV_SENTINEL", "present")

	for _, testCase := range []struct {
		name     string
		options  ScanOptions
		wantUser string
	}{
		{name: "anonymous", options: ScanOptions{DockerConfigDir: "/tmp/anonymous"}},
		{name: "private", options: ScanOptions{DockerConfigDir: "/tmp/private", Username: "alice", Password: "private-secret", RegistryAuthority: "ghcr.io"}, wantUser: "alice"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			env := registryEnv(testCase.options)
			if got := envValue(env, "DOCKER_CONFIG"); got != testCase.options.DockerConfigDir {
				t.Fatalf("DOCKER_CONFIG=%q", got)
			}
			if got := envValue(env, "CONSTELLATION_SCANNER_ENV_SENTINEL"); got != "present" {
				t.Fatalf("unrelated environment lost: %q", got)
			}
			for _, key := range []string{"DOCKER_AUTH_CONFIG", "TRIVY_USERNAME", "GRYPE_REGISTRY_AUTH_USERNAME", "SYFT_REGISTRY_AUTH_USERNAME"} {
				if got := envValue(env, key); got == "ambient-secret" || (testCase.wantUser == "" && got != "") {
					t.Fatalf("%s inherited ambient credential: %q", key, got)
				}
			}
			if got := envValue(env, "TRIVY_USERNAME"); got != testCase.wantUser {
				t.Fatalf("TRIVY_USERNAME=%q, want %q", got, testCase.wantUser)
			}
			for _, entry := range env {
				if strings.HasSuffix(entry, "=ambient-secret") {
					t.Fatalf("ambient registry credential leaked: %q", entry)
				}
			}
		})
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
