// Package registry implements the v1 registry connector framework.
//
// Each connector knows how to:
//   - list repositories accessible to the configured credentials
//   - list tags + digests in a repository
//   - resolve a (repo, tag) to a fully-qualified digest reference for the scanner
//
// At v1 we ship connectors for Docker Hub, GHCR, ECR, Google Artifact Registry/GCR,
// ACR, Quay, Harbor, GitLab Container Registry, JFrog Artifactory, IBM Cloud
// Container Registry, and the RedHat/OpenShift internal image registry.
package registry

import (
	"context"
	"net/http"
	"time"
)

// Connector is the unified registry adapter.
type Connector interface {
	// Name returns the canonical connector name ("docker-hub" | "ghcr" | "ecr" | …).
	Name() string

	// ListImages enumerates repositories the credentials can see.
	ListImages(ctx context.Context) ([]Image, error)

	// ResolveDigest converts a tag-ref into a digest-ref the scanner can pin to.
	ResolveDigest(ctx context.Context, ref string) (string, error)
}

// Image is one bundle of repository metadata.
type Image struct {
	// Repository is the registry-qualified repo name, e.g. "ghcr.io/foo/bar".
	Repository string

	// Tags lists the tags currently published (best-effort; may be paginated).
	Tags []string

	// Digest is the canonical digest reference when available (sha256:…).
	Digest string

	// PushedAt is the registry-reported last-push timestamp (RFC3339 string; empty when unknown).
	PushedAt string
}

// Config describes the credentials a connector needs. Connectors only read the fields
// relevant to them; unused fields are ignored.
type Config struct {
	Username string
	Password string
	Token    string
	Region   string // ECR
	Endpoint string // Harbor / JFrog / IBM Cloud / OpenShift / private registries
	Insecure bool

	// Account is the IBM Cloud Container Registry account GUID, sent in the
	// "Account" header alongside the IAM bearer token (mirrors NeuVector's
	// CLUSRegistryConfig.IBMCloudAccount).
	Account string

	// TokenURL is the IBM Cloud IAM token-exchange endpoint used to swap an API
	// key for a short-lived OAuth token (mirrors CLUSRegistryConfig.IBMCloudTokenURL).
	// Defaults to https://iam.cloud.ibm.com/identity/token when empty.
	TokenURL string

	// HTTPClient, when non-nil, is the shared outbound client the connector must use for
	// all registry traffic. The server builds it from the LIVE system config
	// (syscfg.Provider.HTTPClient) so a PATCH to egress_proxy / tls_verify / ca_bundle_pem
	// takes effect on the next registry walk or test WITHOUT a restart. When nil the
	// connector falls back to a private default client (used by tests and the e2e binary).
	HTTPClient *http.Client
}

// httpClient returns the live shared client when the caller wired one (via the syscfg
// Provider), else a private default with the given timeout. Centralizing this means every
// connector honors the runtime egress-proxy / TLS knobs without per-connector branching.
func (c Config) httpClient(timeout time.Duration) *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{Timeout: timeout}
}

// All returns the v1 connector list given the supplied per-registry configs.
//
// Pass `nil` for registries you don't have credentials for; the caller drops nil-returning
// constructors so the surface is "configured registries only".
func All(cfg map[string]Config) []Connector {
	out := []Connector{}
	if c, ok := cfg["docker-hub"]; ok {
		out = append(out, NewDockerHub(c))
	}
	if c, ok := cfg["ghcr"]; ok {
		out = append(out, NewGHCR(c))
	}
	if c, ok := cfg["ecr"]; ok {
		out = append(out, NewECR(c))
	}
	if c, ok := cfg["artifact-registry"]; ok {
		out = append(out, NewArtifactRegistry(c))
	}
	if c, ok := cfg["acr"]; ok {
		out = append(out, NewACR(c))
	}
	if c, ok := cfg["quay"]; ok {
		out = append(out, NewQuay(c))
	}
	if c, ok := cfg["harbor"]; ok {
		out = append(out, NewHarbor(c))
	}
	if c, ok := cfg["gitlab"]; ok {
		out = append(out, NewGitLab(c))
	}
	if c, ok := cfg["jfrog"]; ok {
		out = append(out, NewJFrog(c))
	}
	if c, ok := cfg["ibmcloud"]; ok {
		out = append(out, NewIBMCloud(c))
	}
	if c, ok := cfg["openshift"]; ok {
		out = append(out, NewOpenShift(c))
	}
	return out
}
