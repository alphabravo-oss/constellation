package syscfg

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CONSUMER (a): shared outbound HTTP client.
//
// HTTPClient builds an *http.Client whose transport honors the LIVE egress proxy and
// TLS-verify / CA-bundle knobs for org. Callers that make outbound calls (federation
// peers, OIDC discovery, webhook receivers that want the shared egress policy, …)
// should build their client through here instead of http.DefaultClient so a PATCH to
// the proxy or TLS settings takes effect on their next request WITHOUT a restart.
//
// Because the client is rebuilt from the current config each call, it is cheap to call
// per request loop. The Provider's cache makes Get a memory read in the common case.
func (p *Provider) HTTPClient(ctx context.Context, orgID uuid.UUID, timeout time.Duration) *http.Client {
	cfg := p.Get(ctx, orgID)
	return cfg.HTTPClient(timeout)
}

// HTTPClient builds a client from a concrete Config (no Provider needed). Used by the
// Provider accessor above and directly in tests.
func (c Config) HTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{
		Proxy:                 c.proxyFunc(),
		TLSClientConfig:       c.tlsConfig(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// proxyFunc returns a per-request proxy resolver honoring HTTPSProxy + NoProxy from the
// live config. When no proxy is configured it returns nil (direct connections).
func (c Config) proxyFunc() func(*http.Request) (*url.URL, error) {
	proxy := strings.TrimSpace(c.EgressProxy.HTTPSProxy)
	if proxy == "" {
		return nil
	}
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil
	}
	noProxy := splitList(c.EgressProxy.NoProxy)
	return func(req *http.Request) (*url.URL, error) {
		if hostMatchesNoProxy(req.URL.Hostname(), noProxy) {
			return nil, nil
		}
		return proxyURL, nil
	}
}

// tlsConfig honors the live TLSVerify toggle + optional CA bundle. When verification is
// on and a CA bundle is set, the bundle is appended to the system roots so a private CA
// is trusted without disabling verification wholesale.
func (c Config) tlsConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if !c.TLSVerify {
		cfg.InsecureSkipVerify = true // operator opt-out; gated behind VerbManageSystemConfig
		return cfg
	}
	if pem := strings.TrimSpace(c.CABundlePEM); pem != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if pool.AppendCertsFromPEM([]byte(pem)) {
			cfg.RootCAs = pool
		}
	}
	return cfg
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hostMatchesNoProxy reports whether host should bypass the proxy per the NoProxy list.
// Supports exact matches and suffix matches (a leading "." or bare domain matches
// subdomains), mirroring the common NO_PROXY semantics.
func hostMatchesNoProxy(host string, noProxy []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, np := range noProxy {
		np = strings.ToLower(strings.TrimPrefix(np, "."))
		if np == "" {
			continue
		}
		if host == np || strings.HasSuffix(host, "."+np) {
			return true
		}
	}
	return false
}
