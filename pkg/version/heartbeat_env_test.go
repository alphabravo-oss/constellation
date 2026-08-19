package version

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHeartbeatConfigFromEnvUsesDirectValues(t *testing.T) {
	cfg := HeartbeatConfigFromEnv("admission", HeartbeatEnvOptions{
		APIBaseURL:  "http://api.local/",
		Token:       "direct-token",
		ClusterID:   "cluster-id",
		ClusterName: "cluster-name",
	})
	if cfg.APIBaseURL != "http://api.local" || cfg.Token != "direct-token" ||
		cfg.Component != "admission" || cfg.ClusterID != "cluster-id" || cfg.ClusterName != "cluster-name" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestHeartbeatConfigFromEnvReadsTokenFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte(" file-token \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTELLATION_API_URL", "http://api")
	t.Setenv("RUNTIME_AGENT_TOKEN_FILE", tokenPath)
	t.Setenv("CONSTELLATION_CLUSTER_NAME", "local")

	cfg := HeartbeatConfigFromEnv("runtime-agent", HeartbeatEnvOptions{
		TokenEnv:     []string{"RUNTIME_AGENT_TOKEN"},
		TokenFileEnv: []string{"RUNTIME_AGENT_TOKEN_FILE"},
	})
	if cfg.APIBaseURL != "http://api" || cfg.Token != "file-token" || cfg.ClusterName != "local" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestHeartbeatConfigFromEnvUsesGenericToken(t *testing.T) {
	t.Setenv("CONSTELLATION_API_URL", "http://api")
	t.Setenv("CONSTELLATION_HEARTBEAT_TOKEN", "generic-token")
	t.Setenv("RUNTIME_AGENT_TOKEN", "role-token")

	cfg := HeartbeatConfigFromEnv("operator", HeartbeatEnvOptions{
		TokenEnv: []string{"RUNTIME_AGENT_TOKEN"},
	})
	if cfg.Token != "generic-token" {
		t.Fatalf("token = %q", cfg.Token)
	}
}

func TestHeartbeatConfigFromEnvRetriesTokenFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	t.Setenv("CONSTELLATION_API_URL", "http://api")
	t.Setenv("RUNTIME_AGENT_TOKEN_FILE", tokenPath)

	cfg := HeartbeatConfigFromEnv("operator", HeartbeatEnvOptions{
		TokenEnv:     []string{"RUNTIME_AGENT_TOKEN"},
		TokenFileEnv: []string{"RUNTIME_AGENT_TOKEN_FILE"},
	})
	if cfg.Token != "" {
		t.Fatalf("initial token = %q, want empty", cfg.Token)
	}
	if HeartbeatConfigured(cfg) {
		t.Fatalf("configured before token file exists")
	}
	if err := os.WriteFile(tokenPath, []byte("late-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cfg.TokenFn(); got != "late-token" {
		t.Fatalf("late token = %q", got)
	}
	if !HeartbeatConfigured(cfg) {
		t.Fatalf("configured = false after token file exists")
	}
}
