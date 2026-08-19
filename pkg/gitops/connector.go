package gitops

// Git connector for config-as-code (roadmap B5).
//
// PushConfigToGit was a stub: config export produced a YAML artifact but nothing pushed
// it anywhere. This is the real connector. It commits the exported config (CRs/YAML) to a
// configured GitHub or Azure DevOps repository over the provider REST API using a personal
// access token, giving operators a git-tracked history of org configuration.
//
// Modeled on NeuVector's controller/remote_repository/{github.go,azure_devops.go}: same
// "GET current file SHA/ref, then PUT/POST new content" flow, adapted to Constellation's
// style (context-aware requests, an injectable *http.Client for tests, structured errors).
//
// SAFETY: this only ever WRITES to an operator-configured external repo using an
// operator-supplied PAT. It touches no cluster/dataplane state and is opt-in per org
// (git_connectors.enabled defaults false). A missing/disabled connector is a no-op.

import (
	"context"
	"errors"
	"net/http"
)

// Provider enumerates the supported git hosts.
type Provider string

const (
	ProviderGitHub      Provider = "github"
	ProviderAzureDevops Provider = "azure_devops"
)

// ErrConnectorDisabled is returned when a push is attempted against a connector that is
// not enabled or not fully configured. Callers treat it as a no-op, not a hard failure.
var ErrConnectorDisabled = errors.New("gitops: git connector disabled or unconfigured")

// ConnectorConfig is the decrypted, ready-to-use connector configuration. The PAT is
// plaintext here (the caller unseals it just-in-time); it is never logged.
type ConnectorConfig struct {
	Provider Provider

	// GitHub.
	GitHubOwner string
	GitHubRepo  string

	// Azure DevOps.
	AzureOrg     string
	AzureProject string
	AzureRepo    string

	// Common.
	Branch         string
	FilePath       string
	CommitterName  string
	CommitterEmail string
	PAT            string

	// Client is an optional override (tests inject a stub). Defaults to a 30s client.
	Client *http.Client
}

// httpClient returns the configured client or a sane default.
func (c ConnectorConfig) httpClient() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return defaultHTTPClient
}

// ready reports whether the connector has the minimum fields to attempt a push.
func (c ConnectorConfig) ready() bool {
	if c.PAT == "" || c.Branch == "" || c.FilePath == "" {
		return false
	}
	switch c.Provider {
	case ProviderGitHub:
		return c.GitHubOwner != "" && c.GitHubRepo != ""
	case ProviderAzureDevops:
		return c.AzureOrg != "" && c.AzureProject != "" && c.AzureRepo != ""
	default:
		return false
	}
}

// PushConfig commits fileContents to the connector's FilePath on its Branch with the
// given commit message. It creates the file if absent and updates it (idempotently) if
// present. Returns ErrConnectorDisabled when the connector isn't push-ready.
func PushConfig(ctx context.Context, cfg ConnectorConfig, fileContents []byte, commitMessage string) error {
	if !cfg.ready() {
		return ErrConnectorDisabled
	}
	if commitMessage == "" {
		commitMessage = "constellation: update " + cfg.FilePath
	}
	switch cfg.Provider {
	case ProviderGitHub:
		return pushGitHub(ctx, cfg, fileContents, commitMessage)
	case ProviderAzureDevops:
		return pushAzureDevops(ctx, cfg, fileContents, commitMessage)
	default:
		return ErrConnectorDisabled
	}
}
