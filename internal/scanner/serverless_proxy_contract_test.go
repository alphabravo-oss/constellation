package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type artifactProxyResponseCase struct {
	name, response, expectedError string
	success                       bool
}

func TestArtifactProxyResponseBoundAndFailureClosure(t *testing.T) {
	payload := strings.Repeat("p", (1<<20)+64)
	for _, tc := range []artifactProxyResponseCase{
		{name: "large tunneled body remains complete", response: "HTTP/1.1 200 Connection Established\r\n\r\n" + payload, success: true},
		{name: "CONNECT content length cannot truncate tunnel", response: "HTTP/1.1 200 Connection Established\r\nContent-Length: 1\r\n\r\n" + payload, success: true},
		{name: "CONNECT chunked framing cannot decode tunnel", response: "HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: chunked\r\n\r\n" + payload, success: true},
		{name: "oversized response header", response: "HTTP/1.1 200 Connection Established\r\nX-Large: " + strings.Repeat("h", (1<<20)+64) + "\r\n\r\n", expectedError: "proxy response"},
		{name: "proxy authentication failure", response: "HTTP/1.1 407 Proxy Authentication Required\r\n\r\nprivate proxy diagnostic", expectedError: "proxy CONNECT status 407"},
	} {
		t.Run(tc.name, func(t *testing.T) { runArtifactProxyResponseCase(t, tc, payload) })
	}
}

func writeArtifactProxyTestResponse(server net.Conn, tc artifactProxyResponseCase) error {
	defer func() { _ = server.Close() }()
	req, err := http.ReadRequest(bufio.NewReader(server))
	if err != nil {
		return err
	}
	if req.Method != http.MethodConnect || req.Host != "8.8.8.8:8080" {
		return fmt.Errorf("unchecked CONNECT target: %s %s", req.Method, req.Host)
	}
	_, err = io.WriteString(server, tc.response)
	// Capped/failed CONNECT closes the socket instead of draining the error body.
	if tc.success {
		return err
	}
	return nil
}

func runArtifactProxyResponseCase(t *testing.T, tc artifactProxyResponseCase, payload string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()
	done := make(chan error, 1)
	go func() { done <- writeArtifactProxyTestResponse(server, tc) }()
	connects := 0
	d := artifactTargetDialer{
		lookup: func(context.Context, string, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil },
		dial: func(_ context.Context, _, address string) (net.Conn, error) {
			connects++
			if address != "proxy.example:3128" {
				t.Errorf("proxy bypass: %s", address)
			}
			return client, nil
		},
	}
	proxy, _ := url.Parse("http://proxy.example:3128")
	tunnel, err := d.connectProxy(ctx, "tcp", "artifact.example:8080", proxy, nil)
	assertArtifactProxyTunnel(t, tc, tunnel, err, payload)
	if connects != 1 {
		t.Fatalf("proxy failure retried or bypassed: %d connects", connects)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("proxy connection was not closed after CONNECT failure")
	}
}

func assertArtifactProxyTunnel(t *testing.T, tc artifactProxyResponseCase, tunnel net.Conn, connectErr error, payload string) {
	t.Helper()
	if !tc.success {
		if tunnel != nil || connectErr == nil || !strings.Contains(connectErr.Error(), tc.expectedError) || strings.Contains(connectErr.Error(), "private proxy diagnostic") {
			t.Fatalf("unsafe CONNECT failure tunnel=%v err=%v", tunnel, connectErr)
		}
		return
	}
	if connectErr != nil {
		t.Fatal(connectErr)
	}
	defer func() { _ = tunnel.Close() }()
	body, err := io.ReadAll(tunnel)
	if err != nil || string(body) != payload {
		t.Fatalf("tunnel body length=%d want=%d err=%v", len(body), len(payload), err)
	}
}
