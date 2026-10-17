package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/telemetryspool"
)

type uploadRedirectCaller struct {
	name string
	call func(context.Context, *http.Client, string) error
}

func uploadRedirectCallers() []uploadRedirectCaller {
	return []uploadRedirectCaller{
		{"telemetry", func(ctx context.Context, client *http.Client, endpoint string) error {
			return postTelemetry(ctx, client, endpoint, "isolated-fixture", []byte(`[{"kind":"exec"}]`), "fixture-producer", 7)
		}},
		{"threats", func(ctx context.Context, client *http.Client, endpoint string) error {
			return postThreatBatch(ctx, client, endpoint, "isolated-fixture", []threatIngestRow{{ThreatID: 1001}})
		}},
		{"sessions", func(ctx context.Context, client *http.Client, endpoint string) error {
			_, err := postSessionBatch(ctx, client, endpoint, "isolated-fixture", []sessionUploadRow{{ID: 1}})
			return err
		}},
	}
}

// All fake hostnames dial only the exact httptest listener. This exercises Go's
// real redirect and sensitive-header rules without DNS or external traffic.
func localUploadClient(t *testing.T, server *httptest.Server) (*http.Client, string) {
	t.Helper()
	client := *sharedUploadClient
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: time.Second}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	client.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Host = net.JoinHostPort("control.fixture.test", endpoint.Port())
	return &client, endpoint.String()
}

func TestUploadCallersRefuseSameOriginSubdomainAndCrossOriginRedirects(t *testing.T) {
	for _, caller := range uploadRedirectCallers() {
		t.Run(caller.name, func(t *testing.T) {
			for _, destination := range []string{"same-origin", "subdomain", "cross-origin"} {
				t.Run(destination, func(t *testing.T) {
					checkUploadRedirect(t, caller, destination)
				})
			}
		})
	}
}

func TestUploadCallersKeepDirectSuccess(t *testing.T) {
	for _, caller := range uploadRedirectCallers() {
		t.Run(caller.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(ackHeader, "7")
				_, _ = io.WriteString(w, `{}`)
			}))
			t.Cleanup(server.Close)
			client, endpoint := localUploadClient(t, server)
			if err := caller.call(t.Context(), client, endpoint); err != nil {
				t.Fatal("direct upload no longer succeeds")
			}
		})
	}
}

func checkUploadRedirect(t *testing.T, caller uploadRedirectCaller, destination string) {
	t.Helper()
	var source, redirected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sink" {
			redirected.Add(1)
			w.Header().Set(ackHeader, "7")
			_, _ = io.WriteString(w, `{}`)
			return
		}
		source.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) == 0 || r.Header.Get("Authorization") == "" {
			t.Error("original endpoint did not receive authenticated upload")
		}
		host := r.Host
		switch destination {
		case "subdomain":
			host = "child." + host
		case "cross-origin":
			_, port, err := net.SplitHostPort(host)
			if err != nil {
				t.Error("invalid local fixture host")
				return
			}
			host = net.JoinHostPort("unrelated.fixture.test", port)
		}
		w.Header().Set("Location", "http://"+host+"/sink")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	client, endpoint := localUploadClient(t, server)
	if err := caller.call(t.Context(), client, endpoint); err == nil {
		t.Error("redirect incorrectly confirmed upload")
	}
	if source.Load() == 0 || redirected.Load() != 0 {
		t.Fatal("upload was not confined to its original endpoint")
	}
}

func TestSharedUploadClientRefusesEveryRedirectStatusAndKeepsDirectSuccess(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var redirected atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sink" {
					redirected.Add(1)
				}
				w.Header().Set("Location", "/sink")
				w.Header().Set(ackHeader, "7")
				w.WriteHeader(status)
			}))
			t.Cleanup(server.Close)
			client, endpoint := localUploadClient(t, server)
			err := postTelemetry(t.Context(), client, endpoint, "isolated-fixture", []byte(`[]`), "fixture-producer", 7)
			if (err == nil) != (status == http.StatusOK) || redirected.Load() != 0 {
				t.Fatal("redirect policy lost direct-success or original-endpoint boundary")
			}
		})
	}
}

type uploadDeferredWriter struct{ cancel context.CancelFunc }

func (w uploadDeferredWriter) Write(body []byte) (int, error) {
	if strings.Contains(string(body), "telemetry delivery deferred") {
		w.cancel()
	}
	return len(body), nil
}

func TestDurableTelemetryRedirectCannotAcknowledgeOrDiscardRetainedBatch(t *testing.T) {
	var redirected atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(ackHeader, r.Header.Get(sequenceHeader))
		if r.URL.Path == "/sink" {
			redirected.Add(1)
			return
		}
		w.Header().Set("Location", "/sink")
		w.WriteHeader(http.StatusPermanentRedirect)
	}))
	t.Cleanup(server.Close)
	directory := filepath.Join(t.TempDir(), "spool")
	queue, err := telemetryspool.Open(directory, "isolated-fixture", 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close() })
	body := []byte(`[{"kind":"exec","workload_id":"fixture/pod/owned"}]`)
	if err := queue.Enqueue(body, 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(uploadDeferredWriter{cancel}, nil))
	var uploaded atomic.Uint64
	deliverTelemetry(ctx, logger, queue, server.URL, "isolated-fixture", &uploaded)
	if redirected.Load() != 0 || uploaded.Load() != 0 || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("redirect leaked an upload, confirmed an ACK, or failed to defer delivery")
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := telemetryspool.Open(directory, "isolated-fixture", 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	retained, err := reopened.Peek()
	if err != nil || retained == nil || retained.Sequence != 1 || !bytes.Equal(retained.Body, body) {
		t.Fatal("redirect discarded or changed the persisted telemetry batch")
	}
}
