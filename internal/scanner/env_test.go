package scanner

import (
	"strings"
	"testing"
)

func TestRegistryEnvInheritsProcessEnvironmentAndAppendsCredentials(t *testing.T) {
	t.Setenv("CONSTELLATION_SCANNER_ENV_SENTINEL", "present")

	env := registryEnv(ScanOptions{Username: "alice", Password: "secret"})

	if got := envValue(env, "CONSTELLATION_SCANNER_ENV_SENTINEL"); got != "present" {
		t.Fatalf("sentinel env=%q want present", got)
	}
	if got := envValue(env, "DOCKER_USER"); got != "alice" {
		t.Fatalf("DOCKER_USER=%q want alice", got)
	}
	if got := envValue(env, "DOCKER_PASSWORD"); got != "secret" {
		t.Fatalf("DOCKER_PASSWORD=%q want secret", got)
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
