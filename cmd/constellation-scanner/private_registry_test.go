package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestPrivateRegistryFileRiskAndConfigChecks(t *testing.T) {
	var forwarded atomic.Bool
	var crossHostRequests atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		crossHostRequests.Add(1)
		if request.Header.Get("Authorization") != "" {
			forwarded.Store(true)
		}
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer other.Close()
	otherAuthority := testRegistryAuthority(t, other, "other.example.test")
	var redirectBlobs atomic.Bool
	registryHandler := registry.New()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "alice" || password != "private-secret" {
			writer.Header().Set("Www-Authenticate", `Basic realm="registry"`)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if redirectBlobs.Load() && request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/blobs/") {
			http.Redirect(writer, request, "https://"+otherAuthority+"/blob", http.StatusTemporaryRedirect)
			return
		}
		registryHandler.ServeHTTP(writer, request)
	}))
	defer server.Close()
	authority := testRegistryAuthority(t, server, "registry.example.test")
	transport := testRegistryTransport(t, map[string]*httptest.Server{authority: server, otherAuthority: other})
	defer transport.CloseIdleConnections()
	auth := registryAuth{Username: "alice", Password: "private-secret", Authority: authority}
	ref := authority + "/team/app:latest"

	var tarBytes bytes.Buffer
	tarWriter := tar.NewWriter(&tarBytes)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "usr/bin/root-suid", Mode: 0o4755, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	layer, err := tarball.LayerFromReader(bytes.NewReader(tarBytes.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	image, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	config, err := image.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	config.Config.User = "1000"
	image, err = mutate.ConfigFile(image, config)
	if err != nil {
		t.Fatal(err)
	}
	reference, options, err := privateRegistryOptions(context.Background(), ref, auth, transport)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(reference, image, options...); err != nil {
		t.Fatal(err)
	}
	digest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	pinnedRef := authority + "/team/app@" + digest.String()

	fileRisks := inspectImageFileRisks(context.Background(), pinnedRef, "linux/amd64", 20, auth, transport)
	if fileRisks == nil || fileRisks.Status != "observed" || fileRisks.FindingCount != 1 || fileRisks.Findings[0].Path != "/usr/bin/root-suid" {
		t.Fatalf("private file risks = %+v", fileRisks)
	}
	checks := inspectImageConfigChecks(context.Background(), pinnedRef, "linux/amd64", auth, transport)
	if checks == nil || checks.Status != "ok" {
		t.Fatalf("private config checks = %+v", checks)
	}
	userCheckPassed := false
	for _, check := range checks.Checks {
		if check.ID == "image-runs-as-root" && check.Status == "pass" {
			userCheckPassed = true
		}
	}
	if !userCheckPassed {
		t.Fatalf("private config user check missing: %+v", checks.Checks)
	}

	configDir := t.TempDir()
	if err := writeDockerConfig(configDir, authority, "alice", "private-secret"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", configDir)
	wrongAuth := registryAuth{Username: "alice", Password: "wrong", Authority: authority}
	if report := inspectImageFileRisks(context.Background(), pinnedRef, "", 20, wrongAuth, transport); report == nil || report.Status != "error" {
		t.Fatalf("wrong credentials resolved file risks: %+v", report)
	}
	if report := inspectImageConfigChecks(context.Background(), pinnedRef, "", wrongAuth, transport); report == nil || report.Status != "error" {
		t.Fatalf("wrong credentials resolved config checks: %+v", report)
	}
	otherAuth := registryAuth{Username: "alice", Password: "private-secret", Authority: "other.example.test"}
	if report := inspectImageFileRisks(context.Background(), pinnedRef, "", 20, otherAuth, transport); report == nil || report.Status != "error" || !strings.Contains(report.Error, "do not match") {
		t.Fatalf("mismatched file-risk authority = %+v", report)
	}
	if report := inspectImageConfigChecks(context.Background(), pinnedRef, "", otherAuth, transport); report == nil || report.Status != "error" || !strings.Contains(report.Error, "do not match") {
		t.Fatalf("mismatched config-check authority = %+v", report)
	}
	plaintextRef := "localhost:5000/team/app@" + digest.String()
	if report := inspectImageFileRisks(context.Background(), plaintextRef, "", 20, registryAuth{Username: "alice", Password: "private-secret", Authority: "localhost:5000"}, transport); report == nil || report.Status != "error" || !strings.Contains(report.Error, "requires HTTPS") {
		t.Fatalf("plaintext file-risk registry = %+v", report)
	}
	if report := inspectImageConfigChecks(context.Background(), plaintextRef, "", registryAuth{Username: "alice", Password: "private-secret", Authority: "localhost:5000"}, transport); report == nil || report.Status != "error" || !strings.Contains(report.Error, "requires HTTPS") {
		t.Fatalf("plaintext config-check registry = %+v", report)
	}
	redirectBlobs.Store(true)
	if report := inspectImageFileRisks(context.Background(), pinnedRef, "", 20, auth, transport); report == nil || report.Status != "error" {
		t.Fatalf("cross-authority file-risk blob = %+v", report)
	}
	if report := inspectImageConfigChecks(context.Background(), pinnedRef, "", auth, transport); report == nil || report.Status != "error" {
		t.Fatalf("cross-authority config-check blob = %+v", report)
	}
	if crossHostRequests.Load() < 2 || forwarded.Load() {
		t.Fatalf("cross-host requests=%d, credentials forwarded=%t", crossHostRequests.Load(), forwarded.Load())
	}
}

func TestPrivateRegistryDigestAndManifest(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux","history":[{"created_by":"RUN build"}],"rootfs":{"type":"layers","diff_ids":["sha256:` + strings.Repeat("d", 64) + `"]}}`)
	configHash := sha256.Sum256(config)
	configDigest := "sha256:" + hex.EncodeToString(configHash[:])
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:%s","size":123}]}`, configDigest, len(config), strings.Repeat("c", 64)))
	digestBytes := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	var authorized atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "alice" || password != "private-secret" {
			writer.Header().Set("Www-Authenticate", `Basic realm="registry"`)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		authorized.Add(1)
		if request.URL.Path == "/v2/team/app/blobs/"+configDigest {
			writer.Header().Set("Content-Type", "application/vnd.oci.image.config.v1+json")
			writer.Header().Set("Content-Length", fmt.Sprint(len(config)))
			_, _ = writer.Write(config)
			return
		}
		if request.URL.Path != "/v2/" && request.URL.Path != "/v2/team/app/manifests/latest" && request.URL.Path != "/v2/team/app/manifests/"+digest {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Docker-Content-Digest", digest)
		writer.Header().Set("Content-Type", string(types.OCIManifestSchema1))
		writer.Header().Set("Content-Length", fmt.Sprint(len(manifest)))
		if request.Method != http.MethodHead {
			_, _ = writer.Write(manifest)
		}
	}))
	defer server.Close()
	authority := testRegistryAuthority(t, server, "registry.example.test")
	auth := registryAuth{Username: "alice", Password: "private-secret", Authority: authority}
	ref := authority + "/team/app:latest"
	transport := testRegistryTransport(t, map[string]*httptest.Server{authority: server})
	defer transport.CloseIdleConnections()
	resolved, err := resolvePrivateDigest(context.Background(), ref, auth, transport)
	if err != nil || resolved != authority+"/team/app@"+digest {
		t.Fatalf("resolvePrivateDigest = %q, %v", resolved, err)
	}
	metadata, err := inspectPrivateManifest(context.Background(), resolved, "", auth, transport)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ManifestDigest != digest || metadata.Config.SizeBytes != int64(len(config)) || len(metadata.Layers) != 1 || metadata.Layers[0].SizeBytes != 123 {
		t.Fatalf("unexpected manifest metadata: %+v", metadata)
	}
	history, diffIDs, err := fetchPrivateLayerHistory(context.Background(), resolved, "", auth, transport)
	if err != nil || len(history) != 1 || history[0].CreatedBy != "RUN build" || len(diffIDs) != 1 || diffIDs[0] != "sha256:"+strings.Repeat("d", 64) {
		t.Fatalf("private config history = %+v, %+v, %v", history, diffIDs, err)
	}
	if authorized.Load() < 2 {
		t.Fatalf("expected authenticated digest and manifest requests; got %d", authorized.Load())
	}
	badAuth := registryAuth{Username: "alice", Password: "wrong", Authority: authority}
	if _, err := resolvePrivateDigest(context.Background(), ref, badAuth, transport); err == nil {
		t.Fatal("wrong credentials resolved a private digest")
	}
	if _, err := inspectPrivateManifest(context.Background(), resolved, "", badAuth, transport); err == nil {
		t.Fatal("wrong credentials inspected a private manifest")
	}
	untrusted := transport.Clone()
	untrusted.TLSClientConfig = &tls.Config{ServerName: server.Certificate().DNSNames[0]}
	defer untrusted.CloseIdleConnections()
	if _, err := resolvePrivateDigest(context.Background(), ref, auth, untrusted); err == nil {
		t.Fatal("untrusted registry certificate was accepted")
	}
}

func TestPrivateRegistryMetadataRejectsPlaintext(t *testing.T) {
	auth := registryAuth{Username: "alice", Password: "private-secret", Authority: "localhost:5000"}
	_, err := resolvePrivateDigest(context.Background(), "localhost:5000/team/app:latest", auth, nil)
	if err == nil || !strings.Contains(err.Error(), "requires HTTPS") {
		t.Fatalf("expected plaintext registry rejection, got %v", err)
	}
}

func TestScopedRegistryTransportDropsCredentialsOnPlaintextSameHost(t *testing.T) {
	var forwarded atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		forwarded.Store(request.Header.Get("Authorization") != "")
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("alice", "private-secret")
	transport := scopedRegistryTransport{base: http.DefaultTransport, authority: request.URL.Host}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if forwarded.Load() {
		t.Fatal("credentials forwarded to plaintext registry endpoint")
	}
}

func TestPrivateRegistryCredentialsStayOnAuthority(t *testing.T) {
	var forwarded atomic.Bool
	var crossHostRequests atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		crossHostRequests.Add(1)
		if request.Header.Get("Authorization") != "" {
			forwarded.Store(true)
		}
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer other.Close()
	otherAuthority := testRegistryAuthority(t, other, "other.example.test")
	registryServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/" {
			writer.Header().Set("Www-Authenticate", `Basic realm="registry"`)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.URL.Path == "/v2/team/app/manifests/latest" {
			http.Redirect(writer, request, "https://"+otherAuthority+"/manifest", http.StatusTemporaryRedirect)
			return
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer registryServer.Close()
	authority := testRegistryAuthority(t, registryServer, "registry.example.test")
	transport := testRegistryTransport(t, map[string]*httptest.Server{authority: registryServer, otherAuthority: other})
	defer transport.CloseIdleConnections()
	auth := registryAuth{Username: "alice", Password: "private-secret", Authority: authority}
	_, err := resolvePrivateDigest(context.Background(), authority+"/team/app:latest", auth, transport)
	if err == nil {
		t.Fatal("redirect to another registry unexpectedly resolved")
	}
	if forwarded.Load() {
		t.Fatal("registry credentials forwarded to another authority")
	}
	if crossHostRequests.Load() == 0 {
		t.Fatal("cross-host redirect was not exercised")
	}
	if _, err := resolvePrivateDigest(context.Background(), otherAuthority+"/team/app:latest", auth, transport); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("expected authority mismatch, got %v", err)
	}
	if _, err := inspectPrivateManifest(context.Background(), otherAuthority+"/team/app@sha256:"+strings.Repeat("a", 64), "", auth, transport); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("expected manifest authority mismatch, got %v", err)
	}
}

func TestPrivateRegistryBearerRealmDoesNotReceiveCredentials(t *testing.T) {
	var realmRequests atomic.Int32
	var forwarded atomic.Bool
	realm := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		realmRequests.Add(1)
		if request.Header.Get("Authorization") != "" {
			forwarded.Store(true)
		}
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer realm.Close()
	realmAuthority := testRegistryAuthority(t, realm, "realm.example.test")
	registryServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Www-Authenticate", `Bearer realm="https://`+realmAuthority+`/token",service="registry",scope="repository:team/app:pull"`)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer registryServer.Close()
	authority := testRegistryAuthority(t, registryServer, "registry.example.test")
	transport := testRegistryTransport(t, map[string]*httptest.Server{authority: registryServer, realmAuthority: realm})
	defer transport.CloseIdleConnections()
	auth := registryAuth{Username: "alice", Password: "private-secret", Authority: authority}
	if _, err := resolvePrivateDigest(context.Background(), authority+"/team/app:latest", auth, transport); err == nil {
		t.Fatal("registry unexpectedly resolved without a token")
	}
	if realmRequests.Load() == 0 || forwarded.Load() {
		t.Fatalf("realm requests=%d, credentials forwarded=%t", realmRequests.Load(), forwarded.Load())
	}
}

func TestPrivateRegistrySelectsManifestPlatform(t *testing.T) {
	child := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:` + strings.Repeat("b", 64) + `","size":42},"layers":[]}`)
	childHash := sha256.Sum256(child)
	childDigest := "sha256:" + hex.EncodeToString(childHash[:])
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":1,"platform":{"os":"linux","architecture":"arm64"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d,"platform":{"os":"linux","architecture":"amd64"}}]}`, strings.Repeat("a", 64), childDigest, len(child)))
	indexHash := sha256.Sum256(index)
	indexDigest := "sha256:" + hex.EncodeToString(indexHash[:])
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "alice" || password != "private-secret" {
			writer.Header().Set("Www-Authenticate", `Basic realm="registry"`)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body []byte
		var mediaType types.MediaType
		switch request.URL.Path {
		case "/v2/team/app/manifests/" + indexDigest:
			body, mediaType = index, types.OCIImageIndex
		case "/v2/team/app/manifests/" + childDigest:
			body, mediaType = child, types.OCIManifestSchema1
		default:
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", string(mediaType))
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	authority := testRegistryAuthority(t, server, "registry.example.test")
	transport := testRegistryTransport(t, map[string]*httptest.Server{authority: server})
	defer transport.CloseIdleConnections()
	auth := registryAuth{Username: "alice", Password: "private-secret", Authority: authority}
	ref := authority + "/team/app@" + indexDigest
	metadata, err := inspectPrivateManifest(context.Background(), ref, "linux/amd64", auth, transport)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.IndexDigest != indexDigest || metadata.ManifestDigest != childDigest || metadata.SelectedPlatform != "linux/amd64" || len(metadata.Architectures) != 2 {
		t.Fatalf("unexpected selected manifest: %+v", metadata)
	}
	if _, err := inspectPrivateManifest(context.Background(), ref, "linux/s390x", auth, transport); err == nil {
		t.Fatal("missing platform unexpectedly selected a manifest")
	}
}

func testRegistryAuthority(t *testing.T, server *httptest.Server, hostname string) string {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host == "" {
		t.Fatal(fmt.Errorf("missing host in %q", server.URL))
	}
	return net.JoinHostPort(hostname, parsed.Port())
}

func testRegistryTransport(t *testing.T, servers map[string]*httptest.Server) *http.Transport {
	t.Helper()
	pool := x509.NewCertPool()
	var serverName string
	for _, server := range servers {
		pool.AddCert(server.Certificate())
		serverName = server.Certificate().DNSNames[0]
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: serverName}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		server := servers[address]
		if server == nil {
			return nil, fmt.Errorf("unexpected registry authority %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	return transport
}
