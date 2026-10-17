package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type artifactProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *artifactProxyConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (d artifactTargetDialer) connectProxy(ctx context.Context, network, address string, proxy *url.URL, config *tls.Config) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("serverless: invalid proxy destination")
	}
	ips, err := d.addresses(ctx, host)
	if err != nil {
		return nil, err
	}
	conn, err := d.proxySocket(ctx, network, proxy, config)
	if err != nil {
		return nil, err
	}
	tunnel, err := artifactConnectTunnel(ctx, conn, proxy, net.JoinHostPort(ips[0].String(), port))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tunnel, nil
}

func (d artifactTargetDialer) proxySocket(ctx context.Context, network string, proxy *url.URL, config *tls.Config) (net.Conn, error) {
	port := proxy.Port()
	if port == "" {
		port = "80"
		if proxy.Scheme == "https" {
			port = "443"
		}
	}
	if proxy.Hostname() == "" {
		return nil, errors.New("serverless: empty proxy host")
	}
	conn, err := d.dial(ctx, network, net.JoinHostPort(proxy.Hostname(), port))
	if err != nil || proxy.Scheme != "https" {
		return conn, err
	}
	proxyTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	if config != nil {
		proxyTLS = config.Clone()
	}
	proxyTLS.ServerName = proxy.Hostname()
	proxyTLS.NextProtos = []string{"http/1.1"}
	secure := tls.Client(conn, proxyTLS)
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := secure.HandshakeContext(handshakeCtx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("serverless: proxy TLS: %w", err)
	}
	return secure, nil
}

func artifactConnectTunnel(ctx context.Context, conn net.Conn, proxy *url.URL, target string) (net.Conn, error) {
	deadline := time.Now().Add(30 * time.Second)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: target}, Host: target, Header: make(http.Header)}
	if proxy.User != nil {
		password, _ := proxy.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(proxy.User.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("serverless: proxy CONNECT: %w", err)
	}
	// Bound CONNECT headers independently of the tunnel's eventual body size.
	headerReader := &io.LimitedReader{R: conn, N: 1 << 20}
	reader := bufio.NewReader(headerReader)
	status, err := artifactProxyStatus(reader, req)
	if err != nil {
		return nil, fmt.Errorf("serverless: proxy response: %w", err)
	}
	if status != http.StatusOK {
		// The caller closes the socket without draining an unbounded error body
		// or exposing proxy credentials in error text.
		return nil, fmt.Errorf("serverless: proxy CONNECT status %d", status)
	}
	headerReader.N = 1<<63 - 1
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !stop() {
		return nil, context.Canceled
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// Keep any bytes received with the CONNECT response for the tunneled stream.
	return &artifactProxyConn{Conn: conn, reader: reader}, nil
}

// artifactProxyStatus parses only the bounded CONNECT response headers. A
// successful CONNECT transfers the socket to a raw tunnel, so HTTP response
// body framing must never consume bytes belonging to that tunnel.
func artifactProxyStatus(reader *bufio.Reader, req *http.Request) (int, error) {
	var headers strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		headers.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(headers.String())), req)
	if err != nil {
		return 0, err
	}
	// This body belongs to the in-memory header parser, never the live socket.
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode, nil
}
