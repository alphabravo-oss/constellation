package version

import (
	"log/slog"
	"os"
	"strings"
	"time"
)

const defaultRuntimeAgentTokenFile = "/var/run/constellation/runtime-agent-token/token"

// HeartbeatEnvOptions maps the standard Helm/env wiring into a HeartbeatConfig.
// The direct fields win over environment variables, which lets binaries keep
// already-parsed flags while still sharing token/file fallback behavior.
type HeartbeatEnvOptions struct {
	APIBaseURL        string
	Token             string
	ClusterID         string
	ClusterName       string
	TokenEnv          []string
	TokenFileEnv      []string
	DefaultTokenFiles []string
	Interval          time.Duration
	Logger            *slog.Logger
	LastErrorFn       func() string
	MetadataFn        func() any
}

func HeartbeatConfigFromEnv(component string, opts HeartbeatEnvOptions) HeartbeatConfig {
	apiURL := strings.TrimSpace(opts.APIBaseURL)
	if apiURL == "" {
		apiURL = firstEnv("CONSTELLATION_API_URL", "CONSTELLATION_CONTROL_PLANE_URL")
	}
	tokenEnv := append([]string{"CONSTELLATION_HEARTBEAT_TOKEN"}, opts.TokenEnv...)
	tokenFileEnv := append([]string{"CONSTELLATION_HEARTBEAT_TOKEN_FILE"}, opts.TokenFileEnv...)
	tokenFn := func() string {
		token := strings.TrimSpace(opts.Token)
		if token != "" {
			return token
		}
		if token = firstEnv(tokenEnv...); token != "" {
			return token
		}
		return firstReadableToken(tokenFileCandidates(tokenFileEnv, opts.DefaultTokenFiles)...)
	}
	token := tokenFn()
	clusterID := strings.TrimSpace(opts.ClusterID)
	if clusterID == "" {
		clusterID = firstEnv("CONSTELLATION_CLUSTER_ID", "CLUSTER_ID")
	}
	clusterName := strings.TrimSpace(opts.ClusterName)
	if clusterName == "" {
		clusterName = firstEnv("CONSTELLATION_CLUSTER_NAME", "CLUSTER_NAME")
	}
	return HeartbeatConfig{
		APIBaseURL:  strings.TrimRight(apiURL, "/"),
		Token:       token,
		TokenFn:     tokenFn,
		Component:   component,
		ClusterID:   clusterID,
		ClusterName: clusterName,
		Interval:    opts.Interval,
		Logger:      opts.Logger,
		LastErrorFn: opts.LastErrorFn,
		MetadataFn:  opts.MetadataFn,
	}
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

func tokenFileCandidates(envKeys, defaults []string) []string {
	out := make([]string, 0, len(envKeys)+len(defaults)+1)
	for _, key := range envKeys {
		if path := strings.TrimSpace(os.Getenv(key)); path != "" {
			out = append(out, path)
		}
	}
	out = append(out, defaults...)
	out = append(out, defaultRuntimeAgentTokenFile)
	return out
}

func firstReadableToken(paths ...string) string {
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if token := strings.TrimSpace(string(raw)); token != "" {
			return token
		}
	}
	return ""
}
