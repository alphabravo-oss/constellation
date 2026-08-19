// Package plugin defines the Constellation plugin SDK contract.
//
// Plugins are out-of-process gRPC services that conform to one of three interfaces:
//
//	Scanner   — runs scans against an image / source / artifact, returns findings
//	Enricher  — accepts a finding stream, returns augmented findings (e.g. attribution)
//	Exporter  — accepts a finding stream, writes to an external system (SIEM, etc.)
//
// The contract here is the Go-side interface + a small wire shape, which is the source of
// truth for the plugin protocol. The Go HTTP fallback gives same-process tests a way to
// exercise plugins without spinning up a gRPC server.
//
// Reference impl: cmd/sample-scanner-plugin.
package plugin

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Capability declares what a plugin can do. A plugin can implement multiple capabilities.
type Capability string

const (
	CapScanner  Capability = "scanner"
	CapEnricher Capability = "enricher"
	CapExporter Capability = "exporter"
)

// Manifest describes a plugin. Returned by GET /v1/plugin/info.
type Manifest struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Capabilities []Capability `json:"capabilities"`
	Vendor       string       `json:"vendor,omitempty"`
	URL          string       `json:"url,omitempty"`

	// Endpoint is the plugin's reachable URL (filled by the loader, not the plugin).
	Endpoint string `json:"endpoint,omitempty"`
}

// Finding is the wire shape; mirrors internal/scanner.Finding but is purpose-shaped for
// plugins. Plugins don't depend on internal/scanner so we don't leak internals.
type Finding struct {
	VulnerabilityID string   `json:"vulnerability_id"`
	Severity        string   `json:"severity"`
	CVSSBase        float64  `json:"cvss_base"`
	CVSSVector      string   `json:"cvss_vector,omitempty"`
	Title           string   `json:"title"`
	Description     string   `json:"description,omitempty"`
	References      []string `json:"references,omitempty"`
	Package         Package  `json:"package"`
	FixedVersion    string   `json:"fixed_version,omitempty"`
	Confidence      float64  `json:"confidence"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Purl      string `json:"purl,omitempty"`
}

// ScanRequest is the input to a Scanner.Scan call.
type ScanRequest struct {
	Target   string            `json:"target"`   // image ref / path / artifact id
	Options  map[string]string `json:"options"`
}

// ScanResult is the response.
type ScanResult struct {
	PluginName string    `json:"plugin_name"`
	Findings   []Finding `json:"findings"`
	Duration   string    `json:"duration"` // human-readable, for logs
}

// Scanner is the Go-side interface a scanner plugin implements.
type Scanner interface {
	Info(ctx context.Context) (Manifest, error)
	Scan(ctx context.Context, req ScanRequest) (ScanResult, error)
}

// Enricher accepts a stream of findings and returns augmented findings.
type Enricher interface {
	Info(ctx context.Context) (Manifest, error)
	Enrich(ctx context.Context, in []Finding) ([]Finding, error)
}

// Exporter ships findings to an external system. Returns an opaque receipt the caller
// can use for audit ("posted-to-X with id=...").
type Exporter interface {
	Info(ctx context.Context) (Manifest, error)
	Export(ctx context.Context, in []Finding) (Receipt, error)
}

// Receipt is the export confirmation.
type Receipt struct {
	System   string    `json:"system"`
	ExportID string    `json:"export_id"`
	Count    int       `json:"count"`
	At       time.Time `json:"at"`
}

// ErrUnsupported is returned by Client methods when the loaded plugin doesn't advertise
// the requested capability.
var ErrUnsupported = errors.New("plugin: capability not advertised by plugin")

// Client is the host-side helper that talks to a plugin over HTTP (used by the gRPC
// fallback path + in-process tests). The Go types in this package are the source of truth
// for the wire format.
type Client struct {
	Endpoint string
	HTTP     *http.Client
}

// NewClient constructs an HTTP client for a plugin endpoint.
func NewClient(endpoint string) *Client {
	return &Client{Endpoint: endpoint, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Compile-time interface assertions so refactors of the wire-shape break the build
// instead of silently breaking plugins.
var (
	_ Scanner  = (*nopScanner)(nil)
	_ Enricher = (*nopEnricher)(nil)
	_ Exporter = (*nopExporter)(nil)
)

type nopScanner  struct{}
type nopEnricher struct{}
type nopExporter struct{}

func (nopScanner) Info(context.Context) (Manifest, error) { return Manifest{}, ErrUnsupported }
func (nopScanner) Scan(context.Context, ScanRequest) (ScanResult, error) {
	return ScanResult{}, ErrUnsupported
}
func (nopEnricher) Info(context.Context) (Manifest, error) { return Manifest{}, ErrUnsupported }
func (nopEnricher) Enrich(context.Context, []Finding) ([]Finding, error) {
	return nil, ErrUnsupported
}
func (nopExporter) Info(context.Context) (Manifest, error) { return Manifest{}, ErrUnsupported }
func (nopExporter) Export(context.Context, []Finding) (Receipt, error) {
	return Receipt{}, ErrUnsupported
}
