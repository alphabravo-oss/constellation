// sample-scanner-plugin is a reference implementation of the Constellation plugin SDK.
//
// It implements the Scanner capability and returns one synthetic finding per scan call.
// Customers who want to extend Constellation with a custom scanner copy this directory and
// replace the Scan() body with their engine logic.
//
// Run:   go run ./cmd/sample-scanner-plugin --listen :9091
// Test:  curl -s http://localhost:9091/v1/plugin/info | jq
//
//	curl -s -X POST http://localhost:9091/v1/plugin/scan -d '{"target":"alpine:3.18"}' | jq
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/pkg/plugin"
)

type sampleScanner struct{}

func (sampleScanner) Info(_ context.Context) (plugin.Manifest, error) {
	return plugin.Manifest{
		Name:         "sample-scanner",
		Version:      "0.1.0",
		Vendor:       "AlphaBravo",
		URL:          "https://constellation.alphabravo.io/plugins/sample-scanner",
		Capabilities: []plugin.Capability{plugin.CapScanner},
	}, nil
}

func (sampleScanner) Scan(_ context.Context, req plugin.ScanRequest) (plugin.ScanResult, error) {
	start := time.Now()
	// Real scanners would shell out to their engine here. We emit one synthetic finding
	// so consumers can validate the wire shape without an actual CVE DB.
	return plugin.ScanResult{
		PluginName: "sample-scanner",
		Findings: []plugin.Finding{
			{
				VulnerabilityID: "SDK-SMOKE-0001",
				Severity:        "low",
				CVSSBase:        3.1,
				Title:           "Sample scanner SDK smoke-test finding",
				Description:     "This reference finding is emitted by the sample scanner plugin to validate the plugin SDK wire shape.",
				Package:         plugin.Package{Ecosystem: "sdk", Name: "sample-package", Version: "1.0.0"},
				References:      []string{"https://constellation.alphabravo.io/plugins/sample-scanner"},
				Confidence:      1.0,
			},
		},
		Duration: time.Since(start).String(),
	}, nil
}

func main() {
	listen := flag.String("listen", ":9091", "Listen address")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "sample-scanner-plugin")

	srv := &plugin.Server{
		Manifest: plugin.Manifest{
			Name:         "sample-scanner",
			Version:      "0.1.0",
			Vendor:       "AlphaBravo",
			Capabilities: []plugin.Capability{plugin.CapScanner},
		},
		Scanner: sampleScanner{},
	}
	logger.Info("listening", "addr", *listen)
	if err := http.ListenAndServe(*listen, srv.Mux()); err != nil {
		logger.Error("serve", "err", err.Error())
		os.Exit(1)
	}
}
