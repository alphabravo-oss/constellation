package bundle

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func testKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// pushRandom publishes a random image to the test registry and returns its ref.
func pushRandom(t *testing.T, host, repo string) string {
	t.Helper()
	img, err := random.Image(256, 2)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := name.ParseReference(host+"/"+repo+":v1", name.Insecure)
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	return ref.String()
}

func TestBuildVerifyLoadRoundTripWithLayeredResolver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	upstream := httptest.NewServer(registry.New())
	defer upstream.Close()
	local := httptest.NewServer(registry.New())
	defer local.Close()
	up := upstream.Listener.Addr().String()
	lo := local.Listener.Addr().String()
	api := pushRandom(t, up, "constellation/api")
	scanner := pushRandom(t, up, "constellation/scanner")

	key, pubPEM := testKey(t)
	pub, _ := ParsePublicKey(pubPEM)
	out := filepath.Join(t.TempDir(), "bundle")
	chart := filepath.Join(t.TempDir(), "chart")
	_ = os.MkdirAll(chart, 0o755)
	_ = os.WriteFile(filepath.Join(chart, "Chart.yaml"), []byte("name: constellation\nversion: 9.9.9\n"), 0o644)
	m, err := Build(ctx, BuildOptions{Out: out, Name: "constellation", Version: "9.9.9", Images: []string{api, scanner}, ChartDir: chart, SignKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Images) != 2 || m.Chart == nil || m.Chart.Version != "9.9.9" || len(m.Files) < 4 {
		t.Fatalf("manifest: %+v", m)
	}
	if _, err := Verify(out, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Wrong trust key: rejected before any payload is read.
	_, otherPEM := testKey(t)
	other, _ := ParsePublicKey(otherPEM)
	if _, err := Verify(out, other); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("foreign key accepted: %v", err)
	}
	// Tampered payload: rejected.
	chartYAML := filepath.Join(out, ChartDir, "Chart.yaml")
	orig, _ := os.ReadFile(chartYAML)
	_ = os.WriteFile(chartYAML, []byte("name: evil\n"), 0o644)
	if _, err := Verify(out, pub); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered payload accepted: %v", err)
	}
	_ = os.WriteFile(chartYAML, orig, 0o644)
	// A layout whose manifest points at a missing blob: rejected even though
	// every listed file still hashes correctly.
	victim := filepath.Join(out, ImagesDir, "blobs", "sha256", strings.TrimPrefix(m.Images[0].Digest, "sha256:"))
	manifestRaw, _ := os.ReadFile(victim)
	var man struct{ Config struct{ Digest string } }
	_ = json.Unmarshal(manifestRaw, &man)
	cfgPath := filepath.Join(out, ImagesDir, "blobs", "sha256", strings.TrimPrefix(man.Config.Digest, "sha256:"))
	_ = os.Rename(cfgPath, cfgPath+".gone")
	m2 := *m
	m2.Files = nil
	if err := checkLayout(filepath.Join(out, ImagesDir), &m2); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("missing config blob not detected: %v", err)
	}
	_ = os.Rename(cfgPath+".gone", cfgPath)
	// Unsigned: rejected.
	_ = os.Rename(filepath.Join(out, SignatureFile), filepath.Join(out, "bom.sig.bak"))
	if _, err := Load(ctx, LoadOptions{Dir: out, TrustKey: pub, Registry: lo, Insecure: true}); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned bundle loaded: %v", err)
	}
	_ = os.Rename(filepath.Join(out, "bom.sig.bak"), filepath.Join(out, SignatureFile))

	// Load into the cluster-local registry; the resolver must answer from "local".
	values := filepath.Join(t.TempDir(), "values-bundle.yaml")
	rep, err := Load(ctx, LoadOptions{Dir: out, TrustKey: pub, Registry: lo, Insecure: true, Fallback: up, ValuesOut: values})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Loaded) != 2 {
		t.Fatalf("loaded %d", len(rep.Loaded))
	}
	for _, li := range rep.Loaded {
		if li.Layer != LayerLocal {
			t.Fatalf("%s resolved from %s, want local", li.Source, li.Layer)
		}
		ref, _ := name.ParseReference(li.Target, name.Insecure)
		desc, err := remote.Head(ref)
		if err != nil || desc.Digest.String() != li.Digest {
			t.Fatalf("local registry does not serve %s: %v", li.Target, err)
		}
	}
	vals, _ := os.ReadFile(values)
	if string(vals) == "" || !contains(string(vals), "imageRegistry: "+lo) || !contains(string(vals), "digest: sha256:") || !contains(string(vals), "tag: v1") {
		t.Fatalf("values: %s", vals)
	}

	// Resolver layers: an image only upstream resolves from fallback; a
	// missing image fails closed; empty fallback fails closed after local.
	only := pushRandom(t, up, "constellation/only-upstream")
	r := &Resolver{Local: lo, Fallback: up, Insecure: true}
	if _, layer, err := r.Resolve(ctx, only); err != nil || layer != LayerFallback {
		t.Fatalf("fallback: %v %s", err, layer)
	}
	if _, _, err := r.Resolve(ctx, up+"/constellation/missing:v1"); !errors.Is(err, ErrFailClosed) {
		t.Fatalf("missing image did not fail closed: %v", err)
	}
	closed := &Resolver{Local: lo, Insecure: true}
	if _, _, err := closed.Resolve(ctx, only); !errors.Is(err, ErrFailClosed) {
		t.Fatalf("empty fallback did not fail closed: %v", err)
	}
}

func TestRetargetKeepsPathAndIdentifier(t *testing.T) {
	t.Parallel()
	ref, _ := name.ParseReference("ghcr.io/alphabravo-oss/constellation/api:v0.2.0")
	got, err := Retarget(ref, "registry.constellation-system.svc:5000", true)
	if err != nil || got.String() != "registry.constellation-system.svc:5000/alphabravo-oss/constellation/api:v0.2.0" {
		t.Fatalf("%v %v", got, err)
	}
	dig, _ := name.ParseReference("docker.io/library/postgres@sha256:" + stringsRepeat("a", 64))
	got, _ = Retarget(dig, "local:5000", true)
	if got.String() != "local:5000/library/postgres@sha256:"+stringsRepeat("a", 64) {
		t.Fatalf("digest retarget: %s", got)
	}
	if kebabToRole("runtime-agent") != "runtimeAgent" || kebabToRole("api") != "api" {
		t.Fatal("kebabToRole")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func stringsRepeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}
