//go:build integration

package handler

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/syscfg"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

const cacheCallerResource = "projects/cache-owner/locations/owned/repositories/owned"

type registryCacheProxyResponder func(stage string, status int, body string) (int, string)

type registryCacheProxy struct {
	respond     registryCacheProxyResponder
	t           *testing.T
	server      *httptest.Server
	cert        tls.Certificate
	mints       atomic.Int64
	catalog     atomic.Int64
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closing     bool
	tunnels     sync.WaitGroup
}

type registryCacheBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c registryCacheBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func newRegistryCacheProxy(t *testing.T, responses ...registryCacheProxyResponder) *registryCacheProxy {
	t.Helper()
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	fixture := &registryCacheProxy{t: t, cert: certificateSource.TLS.Certificates[0], connections: make(map[net.Conn]struct{})}
	certificateSource.Close()
	if len(responses) > 1 {
		t.Fatal("at most one owned response hook is supported")
	}
	if len(responses) == 1 {
		fixture.respond = responses[0]
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(fixture.close)
	return fixture
}

func (f *registryCacheProxy) close() {
	f.server.Close()
	f.mu.Lock()
	f.closing = true
	for conn := range f.connections {
		_ = conn.Close()
	}
	f.mu.Unlock()
	f.tunnels.Wait()
}

func (f *registryCacheProxy) track(conn net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing {
		_ = conn.Close()
		return false
	}
	f.connections[conn] = struct{}{}
	f.tunnels.Add(1)
	return true
}

func (f *registryCacheProxy) release(conn net.Conn) {
	f.mu.Lock()
	delete(f.connections, conn)
	_ = conn.Close()
	f.mu.Unlock()
	f.tunnels.Done()
}

func (f *registryCacheProxy) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if r.Host != "artifactregistry.googleapis.com:443" {
			f.t.Error("fixture refused unexpected CONNECT authority")
			http.Error(w, "unexpected fixture authority", http.StatusBadGateway)
			return
		}
		f.serveCatalogTunnel(w, r)
		return
	}
	if r.Method != http.MethodPost || r.Host != f.server.Listener.Addr().String() || r.URL.Path != "/token" {
		f.t.Error("fixture refused unexpected token authority/path")
		http.Error(w, "unexpected fixture request", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
	if err != nil || len(body) > 16<<10 || !strings.Contains(string(body), "assertion=") {
		f.t.Error("fixture received invalid owned token request")
		http.Error(w, "invalid fixture token request", http.StatusBadRequest)
		return
	}
	mint := f.mints.Add(1)
	w.Header().Set("Content-Type", "application/json")
	status, responseBody := fixtureRegistryCacheResponse(f, "token", fmt.Sprintf(`{"access_token":"owned-cache-token-%d","expires_in":3600}`, mint))
	w.WriteHeader(status)
	if _, err := io.WriteString(w, responseBody); err != nil {
		f.t.Error("fixture token response write failed")
	}
}

func closeRegistryCacheFixture(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil {
		t.Error("owned fixture close failed")
	}
}

func (f *registryCacheProxy) serveCatalogTunnel(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		f.t.Error("owned proxy does not support HTTP/1 CONNECT")
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		f.t.Error("owned CONNECT fixture failed")
		return
	}
	if !f.track(conn) {
		return
	}
	defer f.release(conn)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		f.t.Error("owned CONNECT deadline failed")
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		f.t.Error("owned CONNECT acknowledgement failed")
		return
	}
	if err := buffered.Flush(); err != nil {
		f.t.Error("owned CONNECT acknowledgement flush failed")
		return
	}
	// Terminate locally; never dial or resolve the CONNECT authority.
	secure := tls.Server(registryCacheBufferedConn{Conn: conn, reader: buffered.Reader}, &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{f.cert}, NextProtos: []string{"http/1.1"},
	})
	if err := secure.HandshakeContext(r.Context()); err != nil {
		f.t.Error("owned proxy TLS handshake failed")
		return
	}
	f.writeCatalog(secure)
}

func (f *registryCacheProxy) writeCatalog(conn net.Conn) {
	request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(conn, 16<<10)))
	if err != nil {
		f.t.Error("owned proxy catalog request failed")
		return
	}
	defer closeRegistryCacheFixture(f.t, request.Body)
	if request.Method != http.MethodGet || request.Host != "artifactregistry.googleapis.com" ||
		request.URL.Path != "/v1/"+cacheCallerResource+"/dockerImages" ||
		!strings.HasPrefix(request.Header.Get("Authorization"), "Bearer owned-cache-token-") {
		f.t.Error("fixture refused unexpected catalog authority/path/credential")
		return
	}
	f.catalog.Add(1)
	status, body := fixtureRegistryCacheResponse(f, "catalog", `{"dockerImages":[]}`)
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nConnection: close\r\n", status, http.StatusText(status)) +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body
	if _, err := io.WriteString(conn, response); err != nil {
		f.t.Error("owned proxy catalog response failed")
	}
}

func fixtureRegistryCacheResponse(f *registryCacheProxy, stage, body string) (int, string) {
	if f.respond != nil {
		return f.respond(stage, http.StatusOK, body)
	}
	return http.StatusOK, body
}

func registryCacheServiceAccount(t *testing.T, email, tokenURI string) string {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("owned signing-key fixture failed")
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("owned signing-key encoding failed")
	}
	body, err := json.Marshal(map[string]string{"client_email": email,
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":   tokenURI})
	if err != nil {
		t.Fatal("owned service-account fixture encoding failed")
	}
	return string(body)
}

type registryCacheCallerFixture struct {
	t        *testing.T
	database *db.DB
	proxy    *registryCacheProxy
	orgs     [2]uuid.UUID
	ids      [3]uuid.UUID
	account  string
	sealed   []byte
}

func newRegistryCacheCallerFixture(t *testing.T, database *db.DB, responses ...registryCacheProxyResponder) *registryCacheCallerFixture {
	t.Helper()
	fixture := &registryCacheCallerFixture{t: t, database: database, proxy: newRegistryCacheProxy(t, responses...),
		orgs: [2]uuid.UUID{uuid.New(), uuid.New()}, ids: [3]uuid.UUID{uuid.New(), uuid.New(), uuid.New()}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
		defer cancel()
		if _, err := database.Pool().Exec(ctx, `DELETE FROM orgs WHERE id=ANY($1)`, fixture.orgs[:]); err != nil {
			t.Error("owned cache fixture org cleanup failed")
		}
	})
	for _, org := range fixture.orgs {
		if _, err := database.Pool().Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "cache-callers-"+org.String()); err != nil {
			t.Fatal("owned cache fixture org creation failed")
		}
		config := syscfg.Default()
		// Only these newly owned fixture orgs trust the local TLS terminator.
		config.TLSVerify = false
		config.EgressProxy = syscfg.EgressProxy{HTTPSProxy: fixture.proxy.server.URL}
		if _, _, err := syscfg.Seed(t.Context(), database.Pool(), org, config); err != nil {
			t.Fatal("owned cache fixture outbound configuration failed")
		}
	}
	fixture.account = registryCacheServiceAccount(t, "owned-"+fixture.ids[0].String()+"@example.invalid", fixture.proxy.server.URL+"/token")
	fixture.replace(fixture.orgs[0], fixture.ids[0], fixture.account, true)
	fixture.replace(fixture.orgs[0], fixture.ids[1], fixture.account, true)
	fixture.replace(fixture.orgs[1], fixture.ids[2], fixture.account, true)
	return fixture
}

func (f *registryCacheCallerFixture) replace(org, id uuid.UUID, account string, insert bool) {
	f.t.Helper()
	spoof := registryCredentialCacheScope(f.orgs[0], f.ids[0])
	sealed, err := sealCredentials(f.t.Context(), f.database.Pool(), "gcp-service-account", map[string]string{
		"service_account_json": account, "resource_path": cacheCallerResource,
		"CredentialCacheScope": spoof, "credential_cache_scope": spoof, "cache_scope": spoof,
	})
	if err != nil {
		f.t.Fatal("owned cache fixture credential sealing failed")
	}
	f.sealed = sealed
	if insert {
		_, err = f.database.Pool().Exec(f.t.Context(), `INSERT INTO registries(id,org_id,name,kind,endpoint,auth_kind,auth_secret)
 VALUES($1,$2,$3,'gcr',$4,'gcp-service-account',$5)`, id, org, "cache-"+id.String(), cacheCallerResource, sealed)
	} else {
		_, err = f.database.Pool().Exec(f.t.Context(), `UPDATE registries SET auth_secret=$1 WHERE id=$2 AND org_id=$3`, sealed, id, org)
	}
	if err != nil {
		f.t.Fatal("owned cache fixture registry write failed")
	}
}

func (f *registryCacheCallerFixture) invoke(entrypoint string, org, id uuid.UUID) bool {
	f.t.Helper()
	if entrypoint == "sync" {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		result, err := SyncOnce(f.t.Context(), f.database.Pool(), logger, org, id)
		return err == nil && result != nil && result.Status == "ok" && result.ImagesSeen == 0 && result.JobsEnqueued == 0
	}
	request := httptest.NewRequestWithContext(f.t.Context(), http.MethodPost, "/registries/"+id.String()+"/test", nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("id", id.String())
	ctx := context.WithValue(request.Context(), chi.RouteCtxKey, route)
	request = request.WithContext(WithSubject(ctx, Subject{OrgID: org}))
	response := httptest.NewRecorder()
	NewRegistries(f.database, audit.New(f.database.Pool())).Test(response, request)
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		f.t.Fatal("owned registry test did not return JSON")
	}
	return response.Code == http.StatusOK && result.OK
}

func (f *registryCacheCallerFixture) requireCall(entrypoint string, org, id uuid.UUID, success bool, mints int64) {
	f.t.Helper()
	if f.invoke(entrypoint, org, id) != success || f.proxy.mints.Load() != mints {
		f.t.Fatal("actual registry caller borrowed another credential/owner or lost valid cache reuse")
	}
}

func exerciseRegistryCloudCacheCaller(t *testing.T, database *db.DB, entrypoint string) {
	t.Helper()
	f := newRegistryCacheCallerFixture(t, database)
	f.requireCall(entrypoint, f.orgs[0], f.ids[0], true, 1)
	f.requireCall(entrypoint, f.orgs[0], f.ids[0], true, 1)
	// Retain the original public identity while replacing only its private key.
	var bad map[string]string
	if err := json.Unmarshal([]byte(f.account), &bad); err != nil {
		t.Fatal("owned service-account fixture failed")
	}
	bad["private_key"] = "invalid-owned-key"
	badJSON, err := json.Marshal(bad)
	if err != nil {
		t.Fatal("owned service-account mutation failed")
	}
	f.replace(f.orgs[0], f.ids[0], string(badJSON), false)
	f.requireCall(entrypoint, f.orgs[0], f.ids[0], false, 1)
	rotated := registryCacheServiceAccount(t, bad["client_email"], f.proxy.server.URL+"/token")
	f.replace(f.orgs[0], f.ids[0], rotated, false)
	f.requireCall(entrypoint, f.orgs[0], f.ids[0], true, 2)
	f.replace(f.orgs[0], f.ids[1], rotated, false)
	f.requireCall(entrypoint, f.orgs[0], f.ids[1], true, 3)
	f.replace(f.orgs[1], f.ids[2], rotated, false)
	f.requireCall(entrypoint, f.orgs[1], f.ids[2], true, 4)
	f.requireCall(entrypoint, f.orgs[1], f.ids[0], false, 4)
	// Legacy builder knows org but not registry identity: authenticate, never share.
	for range 2 {
		connector, err := BuildConnector(t.Context(), database.Pool(), f.orgs[0], "gcr", cacheCallerResource, "gcp-service-account", f.sealed)
		if err != nil {
			t.Fatal("legacy owned builder failed")
		}
		if images, err := connector.ListImages(t.Context()); err != nil || len(images) != 0 {
			t.Fatal("legacy unscoped builder stopped authenticating")
		}
	}
	if f.proxy.mints.Load() != 6 || f.proxy.catalog.Load() != 7 {
		t.Fatal("legacy builder cached without registry identity or wrong-key request reached catalog")
	}
}

func TestRegistryCloudCacheActualTestAndSyncOwnerBoundaries(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	for _, entrypoint := range []string{"test", "sync"} {
		t.Run(entrypoint, func(t *testing.T) { exerciseRegistryCloudCacheCaller(t, database, entrypoint) })
	}
}
