package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// The resolver and connector are paired: the connector receives only a checked
// numeric address, never a hostname it could resolve a second time.
type artifactTargetDialer struct {
	lookup func(context.Context, string, string) ([]net.IP, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

func defaultArtifactDialer() artifactTargetDialer {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return artifactTargetDialer{lookup: net.DefaultResolver.LookupIP, dial: dialer.DialContext}
}

func (d artifactTargetDialer) addresses(ctx context.Context, host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ips, err := d.lookup(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("serverless: resolve artifact host: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("serverless: artifact host has no addresses")
	}
	// Reject the whole answer, including mixed public/private DNS responses.
	for _, ip := range ips {
		if isDisallowedTargetIP(ip) {
			return nil, errors.New("serverless: artifact host resolves to a disallowed address")
		}
	}
	return ips, nil
}

func (d artifactTargetDialer) connect(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("serverless: invalid artifact address: %w", err)
	}
	ips, err := d.addresses(ctx, host)
	if err != nil {
		return nil, err
	}
	var failures []error
	for _, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
	}
	return nil, fmt.Errorf("serverless: connect artifact host: %w", errors.Join(failures...))
}

func isDisallowedTargetIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	// IsPrivate does not include shared address space or reserved IPv4 ranges.
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 0 || v4[0] >= 240 ||
			(v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127) ||
			(v4[0] == 198 && (v4[1] == 18 || v4[1] == 19))
	}
	return false
}

func validateArtifactURL(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return errors.New("serverless: artifact requires an HTTP(S) URL without user credentials")
	}
	return nil
}

type artifactTransport struct {
	transport *http.Transport
	dialer    artifactTargetDialer
	proxy     func(*http.Request) (*url.URL, error)
}

func (t artifactTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := validateArtifactURL(req.URL); err != nil {
		return nil, err
	}
	if t.proxy != nil {
		proxy, err := t.proxy(req)
		if err != nil {
			return nil, errors.New("serverless: artifact proxy configuration failed")
		}
		if proxy != nil {
			return t.proxyRoundTrip(req, proxy)
		}
	}
	return t.transport.RoundTrip(req)
}

// Proxy requests use a numeric CONNECT tunnel even for HTTP. Forward-proxy
// absolute-form requests use Request.Host, which would otherwise let the proxy
// resolve the original hostname again. A proxy refusing the tunnel fails closed.
func (t artifactTransport) proxyRoundTrip(req *http.Request, proxy *url.URL) (*http.Response, error) {
	if proxy.Scheme != "http" && proxy.Scheme != "https" {
		return nil, errors.New("serverless: artifact proxy requires HTTP or HTTPS CONNECT")
	}
	transport := t.transport.Clone()
	transport.DisableKeepAlives = true
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return t.dialer.connectProxy(ctx, network, address, proxy, t.transport.TLSClientConfig)
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	transport.TLSClientConfig.ServerName = req.URL.Hostname()
	defer transport.CloseIdleConnections()
	return transport.RoundTrip(req)
}

func restrictedArtifactClient(base *http.Client, dialer artifactTargetDialer) (*http.Client, func(), error) {
	configured := base.Transport
	if configured == nil {
		configured = http.DefaultTransport
	}
	settings, ok := configured.(*http.Transport)
	if !ok || settings == nil {
		return nil, nil, errors.New("serverless: custom artifact transports require trusted private-target mode")
	}
	// Start a fresh transport rather than cloning registered alternate protocols,
	// custom TLS dialers or pooled connections which could bypass checked dialing.
	transport := &http.Transport{
		DialContext: dialer.connect, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second,
		ResponseHeaderTimeout:  settings.ResponseHeaderTimeout,
		MaxResponseHeaderBytes: settings.MaxResponseHeaderBytes,
		DisableCompression:     settings.DisableCompression,
	}
	if settings.TLSClientConfig != nil {
		transport.TLSClientConfig = settings.TLSClientConfig.Clone()
	}
	client := *base
	client.Transport = artifactTransport{transport: transport, dialer: dialer, proxy: settings.Proxy}
	if client.Timeout <= 0 || client.Timeout > 5*time.Minute {
		client.Timeout = 5 * time.Minute
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("serverless: too many artifact redirects")
		}
		if err := validateArtifactURL(req.URL); err != nil {
			return err
		}
		if base.CheckRedirect != nil {
			return base.CheckRedirect(req, via)
		}
		return nil
	}
	return &client, transport.CloseIdleConnections, nil
}
