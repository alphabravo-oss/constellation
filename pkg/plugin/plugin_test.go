package plugin

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeScanner struct{}

func (fakeScanner) Info(_ context.Context) (Manifest, error) {
	return Manifest{Name: "demo", Version: "1.0", Capabilities: []Capability{CapScanner}}, nil
}
func (fakeScanner) Scan(_ context.Context, req ScanRequest) (ScanResult, error) {
	return ScanResult{
		PluginName: "demo",
		Findings: []Finding{
			{VulnerabilityID: "CVE-2024-9999", Severity: "high", Title: "demo finding", Package: Package{Name: "x", Version: "1"}},
		},
		Duration: "5ms",
	}, nil
}

func TestPluginServerClient_RoundTrip(t *testing.T) {
	srv := httptest.NewServer((&Server{
		Manifest: Manifest{Name: "demo", Version: "1.0", Capabilities: []Capability{CapScanner}},
		Scanner:  fakeScanner{},
	}).Mux())
	defer srv.Close()

	c := NewClient(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m, err := c.HTTPInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "demo" || len(m.Capabilities) != 1 {
		t.Fatalf("manifest shape wrong: %+v", m)
	}

	res, err := c.HTTPScan(ctx, ScanRequest{Target: "alpine:3.18"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].VulnerabilityID != "CVE-2024-9999" {
		t.Fatalf("scan: %+v", res)
	}
}

func TestServer_ReturnsNotImplementedForMissingCaps(t *testing.T) {
	srv := httptest.NewServer((&Server{
		Manifest: Manifest{Name: "scanner-only", Version: "1.0", Capabilities: []Capability{CapScanner}},
		Scanner:  fakeScanner{},
		// Enricher / Exporter nil.
	}).Mux())
	defer srv.Close()
	c := NewClient(srv.URL)
	if _, err := c.HTTPEnrich(context.Background(), nil); err == nil {
		t.Fatal("expected 501 for unimplemented Enrich")
	}
}

func TestCheckOnce_RejectsBadManifest(t *testing.T) {
	if err := CheckOnce(Manifest{Name: ""}); err == nil {
		t.Fatal("empty Name should fail")
	}
	if err := CheckOnce(Manifest{Name: "x"}); err == nil {
		t.Fatal("zero capabilities should fail")
	}
	if err := CheckOnce(Manifest{Name: "x", Capabilities: []Capability{CapScanner}}); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
}
