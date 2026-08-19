// checkov-plugin is a reference Constellation plugin that shells out to Checkov for
// IaC scanning. Demonstrates how third-party scanner vendors plug into the platform
// without forcing Python into the core build (Python lives in this plugin's image only).
//
// Build:  go run ./cmd/checkov-plugin --listen :9092
// Test:   curl -s http://localhost:9092/v1/plugin/info
//
//	Scan:   curl -s -X POST http://localhost:9092/v1/plugin/scan \
//	            -d '{"target":"/path/to/terraform/dir"}'
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/pkg/plugin"
)

type checkov struct{}

func (checkov) Info(_ context.Context) (plugin.Manifest, error) {
	return plugin.Manifest{
		Name:         "checkov",
		Version:      "0.1.0",
		Vendor:       "Constellation reference",
		URL:          "https://github.com/bridgecrewio/checkov",
		Capabilities: []plugin.Capability{plugin.CapScanner},
	}, nil
}

// Scan runs `checkov --quiet --output json --directory <target>` and converts the result
// to a plugin.ScanResult. Returns the wire-shape findings.
func (checkov) Scan(ctx context.Context, req plugin.ScanRequest) (plugin.ScanResult, error) {
	bin, err := exec.LookPath("checkov")
	if err != nil {
		return plugin.ScanResult{}, errors.New("checkov-plugin: checkov binary not on PATH (install: pip install checkov)")
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	args := []string{"--quiet", "--output", "json", "--directory", req.Target}
	if framework := req.Options["framework"]; framework != "" {
		args = append(args, "--framework", framework)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// checkov exits 1 when findings exist; treat that as success if stdout has JSON.
		if stdout.Len() == 0 {
			return plugin.ScanResult{}, fmt.Errorf("checkov: %w (stderr=%s)", err,
				strings.TrimSpace(stderr.String()))
		}
	}

	var doc struct {
		Results struct {
			FailedChecks []struct {
				CheckID       string `json:"check_id"`
				CheckName     string `json:"check_name"`
				CheckClass    string `json:"check_class"`
				Severity      string `json:"severity"`
				Resource      string `json:"resource"`
				FileLineRange [2]int `json:"file_line_range"`
				FilePath      string `json:"file_path"`
				Guideline     string `json:"guideline"`
			} `json:"failed_checks"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		return plugin.ScanResult{}, fmt.Errorf("checkov: decode json: %w", err)
	}

	findings := make([]plugin.Finding, 0, len(doc.Results.FailedChecks))
	for _, fc := range doc.Results.FailedChecks {
		findings = append(findings, plugin.Finding{
			VulnerabilityID: fc.CheckID,
			Severity:        normSeverity(fc.Severity),
			Title:           fc.CheckName,
			Description:     fmt.Sprintf("%s at %s:%d", fc.CheckClass, fc.FilePath, fc.FileLineRange[0]),
			References:      []string{fc.Guideline},
			Package:         plugin.Package{Ecosystem: "iac", Name: fc.Resource, Version: "n/a"},
			Confidence:      1.0,
		})
	}
	return plugin.ScanResult{
		PluginName: "checkov",
		Findings:   findings,
		Duration:   time.Since(start).String(),
	}, nil
}

func normSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	case "":
		return "medium"
	}
	return s
}

func main() {
	listen := flag.String("listen", ":9092", "Listen address")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "checkov-plugin")
	srv := &plugin.Server{
		Manifest: plugin.Manifest{
			Name:         "checkov",
			Version:      "0.1.0",
			Vendor:       "Constellation reference",
			Capabilities: []plugin.Capability{plugin.CapScanner},
		},
		Scanner: checkov{},
	}
	logger.Info("listening", "addr", *listen)
	if err := http.ListenAndServe(*listen, srv.Mux()); err != nil {
		logger.Error("serve", "err", err.Error())
		os.Exit(1)
	}
}
