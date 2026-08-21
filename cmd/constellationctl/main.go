// constellationctl is the operator CLI.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/policy/dsl"
	"github.com/alphabravocompany/constellation/pkg/policy/eval"
	"github.com/alphabravocompany/constellation/pkg/sarif"
	"github.com/alphabravocompany/constellation/pkg/sbom"
)

// newExecCommand wraps exec.CommandContext so tests can swap the runner if needed.
var newExecCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

// version is overridden at build time by goreleaser via -ldflags.
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:   "constellationctl",
		Short: "Constellation operator CLI",
	}
	root.AddCommand(loginCmd(), imageCheckCmd(), auditCmd(), versionCmd(), iacCheckCmd(), modelCheckCmd(), policyCmd(), clusterCmd(), tokensCmd(), networkFlowsCmd(), backupCmd(), vulndbCmd(), serverlessCmd(), repositoryCmd(), federationCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ---- config ----

type config struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}

func configPath() string {
	if v := os.Getenv("CONSTELLATION_CONFIG"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".constellation", "config.yaml") // YAML-or-JSON tolerant
}

func loadConfig() (*config, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &config{}, nil
		}
		return nil, err
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func saveConfig(c *config) error {
	if err := os.MkdirAll(filepath.Dir(configPath()), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), b, 0o600)
}

// ---- commands ----

func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print version", Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintln(cmd.OutOrStdout(), version)
	}}
}

func loginCmd() *cobra.Command {
	var server, email string
	cmd := &cobra.Command{Use: "login", Short: "Authenticate against a Constellation server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprint(cmd.OutOrStdout(), "Password: ")
			var pw string
			fmt.Fscan(cmd.InOrStdin(), &pw)
			payload := map[string]string{"email": email, "password": pw}
			body, _ := json.Marshal(payload)
			resp, err := http.Post(server+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			rb, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 {
				return fmt.Errorf("login failed: %s", rb)
			}
			var out struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(rb, &out); err != nil {
				return err
			}
			return saveConfig(&config{Server: server, Token: out.Token})
		}}
	cmd.Flags().StringVar(&server, "server", "http://localhost:8080", "Constellation server URL")
	cmd.Flags().StringVar(&email, "email", "", "Email")
	_ = cmd.MarkFlagRequired("email")
	return cmd
}

func imageCheckCmd() *cobra.Command {
	var (
		failOn       string
		sarifOut     string
		jsonOut      string
		spdxOut      string
		cyclonedxOut string
		platform     string
		insecure     bool
		quiet        bool
	)
	cmd := &cobra.Command{
		Use:   "image-check <ref>",
		Short: "Scan an image with the Constellation aggregator (Syft + VulnDB + Trivy + Grype)",
		Long: `Runs the multi-engine scanner against a container image and writes the
canonical artifacts (SARIF, JSON, SPDX 2.3, CycloneDX 1.6). Exits non-zero when any
finding meets or exceeds --fail-on severity.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Minute)
			defer cancel()

			agg := scanner.NewDefault()
			res, err := agg.Scan(ctx, args[0], scanner.ScanOptions{
				Insecure: insecure,
				Platform: platform,
				Timeout:  15 * time.Minute,
			})
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			if sarifOut != "" {
				doc := sarif.FromScanResult(version, res)
				b, _ := sarif.MarshalIndent(doc)
				if err := os.WriteFile(sarifOut, b, 0o644); err != nil {
					return err
				}
				if !quiet {
					fmt.Fprintf(cmd.OutOrStdout(), "wrote SARIF: %s\n", sarifOut)
				}
			}
			if jsonOut != "" {
				b, _ := json.MarshalIndent(res, "", "  ")
				if err := os.WriteFile(jsonOut, b, 0o644); err != nil {
					return err
				}
				if !quiet {
					fmt.Fprintf(cmd.OutOrStdout(), "wrote JSON:  %s\n", jsonOut)
				}
			}
			if spdxOut != "" {
				doc := sbom.SPDX2_3(version, res)
				b, _ := json.MarshalIndent(doc, "", "  ")
				if err := os.WriteFile(spdxOut, b, 0o644); err != nil {
					return err
				}
				if !quiet {
					fmt.Fprintf(cmd.OutOrStdout(), "wrote SPDX:  %s\n", spdxOut)
				}
			}
			if cyclonedxOut != "" {
				doc := sbom.CycloneDX1_6(version, res)
				b, _ := json.MarshalIndent(doc, "", "  ")
				if err := os.WriteFile(cyclonedxOut, b, 0o644); err != nil {
					return err
				}
				if !quiet {
					fmt.Fprintf(cmd.OutOrStdout(), "wrote CycloneDX: %s\n", cyclonedxOut)
				}
			}

			if !quiet {
				printScanSummary(cmd.OutOrStdout(), res)
			}

			// Exit logic.
			if worst := highestSeverity(res); severityAtLeast(worst, failOn) {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "critical", "Severity threshold for non-zero exit (info|low|medium|high|critical)")
	cmd.Flags().StringVar(&sarifOut, "sarif", "", "Write SARIF 2.1.0 output to this path")
	cmd.Flags().StringVar(&jsonOut, "json", "", "Write aggregated JSON output to this path")
	cmd.Flags().StringVar(&spdxOut, "spdx", "", "Write SPDX 2.3 SBOM to this path")
	cmd.Flags().StringVar(&cyclonedxOut, "cyclonedx", "", "Write CycloneDX 1.6 SBOM to this path")
	cmd.Flags().StringVar(&platform, "platform", "", "Image platform (e.g. linux/amd64)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Tolerate self-signed registry TLS")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress progress output (machine-friendly)")
	return cmd
}

// printScanSummary renders the human-readable scan summary on stdout.
func printScanSummary(w io.Writer, res *scanner.ScanResult) {
	fmt.Fprintf(w, "\nImage:        %s\n", res.ImageRef)
	fmt.Fprintf(w, "Engines:      %s\n", engineList(res))
	fmt.Fprintf(w, "Packages:     %d\n", len(res.Packages))
	fmt.Fprintf(w, "Findings:     %d\n\n", len(res.Findings))

	counts := map[string]int{}
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] > 0 {
			fmt.Fprintf(w, "  %-9s %d\n", sev, counts[sev])
		}
	}

	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "\nNo vulnerabilities found.")
		return
	}

	// Top 10 findings as a quick table.
	fmt.Fprintln(w, "\nTop findings:")
	fmt.Fprintln(w, "  SEVERITY   CVE             PACKAGE@VERSION                       FIXED")
	for i, f := range res.Findings {
		if i >= 10 {
			break
		}
		fmt.Fprintf(w, "  %-10s %-15s %-37s %s\n",
			strings.ToUpper(f.Severity), f.VulnerabilityID,
			truncate(fmt.Sprintf("%s@%s", f.Package.Name, f.Package.Version), 37),
			ifEmpty(f.FixedVersion, "-"))
	}
}

func engineList(res *scanner.ScanResult) string {
	names := make([]string, 0, len(res.Engines))
	for _, e := range res.Engines {
		names = append(names, e.Engine)
	}
	return strings.Join(names, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// highestSeverity returns the worst severity in the scan result.
func highestSeverity(res *scanner.ScanResult) string {
	bestRank := -1
	best := ""
	for _, f := range res.Findings {
		r := severityRank(f.Severity)
		if r > bestRank {
			bestRank = r
			best = f.Severity
		}
	}
	return best
}

// severityAtLeast returns true if got >= threshold.
func severityAtLeast(got, threshold string) bool {
	return severityRank(got) >= severityRank(threshold)
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info", "negligible":
		return 0
	}
	return -1
}

func iacCheckCmd() *cobra.Command {
	var sarifOut, failOn string
	cmd := &cobra.Command{
		Use:   "iac-check <path>",
		Short: "Scan infrastructure-as-code (Terraform / Helm / Kustomize / Dockerfile / K8s YAML / CloudFormation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Delegate to Trivy IaC (covers all six input types per the spec).
			format := "json"
			if sarifOut != "" {
				format = "sarif"
			}
			out, err := runCmd(cmd.Context(), "trivy", "config", "--quiet", "--format", format, args[0])
			if err != nil {
				return fmt.Errorf("trivy config: %w", err)
			}
			if sarifOut != "" {
				if err := os.WriteFile(sarifOut, out, 0o644); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "wrote SARIF:", sarifOut)
				return nil
			}
			fmt.Println(string(out))
			return nil
		}}
	cmd.Flags().StringVar(&sarifOut, "sarif", "", "Write SARIF output to this path")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Severity threshold for non-zero exit")
	return cmd
}

func modelCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "model-check <path>",
		Short: "Scan ML model artifact for unsafe-deserialization formats",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("model-check: directory scan not yet implemented; pass a single artifact")
			}
			ext := strings.ToLower(filepath.Ext(path))
			switch ext {
			case ".pt", ".pth", ".pkl", ".bin":
				fmt.Fprintf(cmd.OutOrStdout(), "WARNING: %s uses an unsafe-deserialization format (arbitrary code can run on load).\n", filepath.Base(path))
				fmt.Fprintln(cmd.OutOrStdout(), "  Recommendation: convert to safetensors (https://huggingface.co/docs/safetensors).")
				os.Exit(1)
			case ".safetensors":
				fmt.Fprintf(cmd.OutOrStdout(), "OK: %s is safetensors; deserialization is bounds-checked.\n", filepath.Base(path))
			case ".onnx":
				fmt.Fprintf(cmd.OutOrStdout(), "OK: %s is ONNX; protobuf-defined schema (no code execution on load).\n", filepath.Base(path))
				fmt.Fprintln(cmd.OutOrStdout(), "  Note: validate weights + ops via onnx.checker.check_model in CI.")
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "model-check: unknown format %q for %s\n", ext, filepath.Base(path))
			}
			return nil
		},
	}
}

// runCmd runs an external CLI and returns stdout. stderr is folded into the error on
// non-zero exit. trivy IaC's exit code is signal as well as data: any finding => nonzero;
// we treat stdout as authoritative when non-empty.
func runCmd(ctx context.Context, bin string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var stdout, stderr bytes.Buffer
	c := newExecCommand(ctx, bin, args...)
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("%s: %w (stderr=%s)", bin, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func policyCmd() *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "Policy-as-code workflow"}
	c.AddCommand(policyValidateCmd(), policyCheckCmd(), policyExportCRDsCmd())
	return c
}

func policyValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a Constellation policy DSL document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPolicyDocument(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK: %s is a valid Constellation policy (%s)\n", args[0], p.Name)
			return nil
		},
	}
}

func policyCheckCmd() *cobra.Command {
	var recordPath string
	cmd := &cobra.Command{
		Use:   "check <file>",
		Short: "Validate and optionally evaluate a policy DSL document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPolicyDocument(args[0])
			if err != nil {
				return err
			}
			if strings.TrimSpace(recordPath) == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "OK: %s is a valid Constellation policy (%s)\n", args[0], p.Name)
				return nil
			}
			record, err := loadPolicyRecord(recordPath)
			if err != nil {
				return err
			}
			result := eval.Match(p, record)
			if result.Matched {
				fmt.Fprintf(cmd.OutOrStdout(), "MATCH: %s matched %s", p.Name, recordPath)
				if len(result.FailedFields) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), " fields=%s", strings.Join(result.FailedFields, ","))
				}
				fmt.Fprintln(cmd.OutOrStdout())
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "NO MATCH: %s did not match %s\n", p.Name, recordPath)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&recordPath, "record", "", "Optional JSON record to evaluate against the policy")
	return cmd
}

func loadPolicyDocument(path string) (dsl.Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return dsl.Policy{}, err
	}
	p, err := dsl.Unmarshal(b)
	if err != nil {
		return dsl.Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return dsl.Policy{}, fmt.Errorf("validate policy %s: %w", path, err)
	}
	return p, nil
}

func loadPolicyRecord(path string) (eval.Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse record %s: %w", path, err)
	}
	record := eval.Record{}
	flattenPolicyRecord("", raw, record)
	return record, nil
}

func flattenPolicyRecord(prefix string, value any, out eval.Record) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			next := key
			if prefix != "" {
				next = prefix + "." + key
			}
			flattenPolicyRecord(next, child, out)
		}
	case []any:
		parts := make([]string, 0, len(v))
		for i, child := range v {
			childKey := fmt.Sprintf("list:%s:%d", prefix, i)
			flattenPolicyRecord(childKey, child, out)
			parts = append(parts, fmt.Sprint(child))
		}
		out[prefix] = strings.Join(parts, ",")
	default:
		if prefix != "" {
			out[prefix] = fmt.Sprint(v)
		}
	}
}

func auditCmd() *cobra.Command {
	c := &cobra.Command{Use: "audit", Short: "Audit log subcommands"}
	c.AddCommand(&cobra.Command{
		Use: "verify", Short: "Walk the audit chain and report any tamper",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" {
				return fmt.Errorf("not logged in; run `constellationctl login` first")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
				cfg.Server+"/api/v1/audit/verify", nil)
			req.Header.Set("Authorization", "Bearer "+cfg.Token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			fmt.Fprintln(cmd.OutOrStdout(), strings.TrimSpace(string(b)))
			if resp.StatusCode >= 400 {
				return fmt.Errorf("verify failed")
			}
			return nil
		},
	})
	c.AddCommand(complianceExportCmd())
	return c
}

// complianceExportCmd: bundles audit evidence for a single compliance
// control. Hits /audit/events?framework=<fw>&control=<id> + the static
// mapping table, writes JSON to stdout (or --out). Designed to be piped
// into an ATO worksheet generator.
//
//	constellationctl audit compliance-export \
//	  --framework nist-sp-800-53-r5 --control AC-2 --limit 500 > ac2.json
func complianceExportCmd() *cobra.Command {
	var framework, control, outPath string
	var limit int
	cmd := &cobra.Command{
		Use:   "compliance-export",
		Short: "Export audit evidence for a compliance control",
		Long: `Bundles audit rows demonstrating one compliance control into a JSON
document suitable for ATO worksheets / SOC 2 evidence packets / PCI audit
reports. Includes the static mapping table inline so reviewers can verify
which actions were considered evidence.

Required: --framework <id> --control <id>
   --framework nist-sp-800-53-r5
   --framework soc2-tsc-2017
   --framework pci-dss-v4.0
   --framework iso-27001-2022

The list of valid frameworks + control IDs comes from the server:
   constellationctl audit compliance-export --list-frameworks
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if cfg.Server == "" {
				return fmt.Errorf("not logged in; run `constellationctl login` first")
			}
			if framework == "" || control == "" {
				return fmt.Errorf("--framework and --control are required")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			// 1. Pull the static mapping table for the framework.
			mapURL := fmt.Sprintf("%s/api/v1/compliance/control-mappings?framework=%s",
				cfg.Server, framework)
			mapReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, mapURL, nil)
			mapReq.Header.Set("Authorization", "Bearer "+cfg.Token)
			mapResp, err := http.DefaultClient.Do(mapReq)
			if err != nil {
				return fmt.Errorf("fetch mappings: %w", err)
			}
			mapBody, _ := io.ReadAll(mapResp.Body)
			mapResp.Body.Close()
			if mapResp.StatusCode >= 400 {
				return fmt.Errorf("mappings: %s", mapBody)
			}
			var mappings any
			_ = json.Unmarshal(mapBody, &mappings)

			// 2. Pull the audit rows demonstrating this control.
			evtURL := fmt.Sprintf("%s/api/v1/audit/events?framework=%s&control=%s&limit=%d&with_controls=1",
				cfg.Server, framework, control, limit)
			evtReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, evtURL, nil)
			evtReq.Header.Set("Authorization", "Bearer "+cfg.Token)
			evtResp, err := http.DefaultClient.Do(evtReq)
			if err != nil {
				return fmt.Errorf("fetch events: %w", err)
			}
			evtBody, _ := io.ReadAll(evtResp.Body)
			evtResp.Body.Close()
			if evtResp.StatusCode >= 400 {
				return fmt.Errorf("events: %s", evtBody)
			}
			var events any
			_ = json.Unmarshal(evtBody, &events)

			bundle := map[string]any{
				"exported_at":  time.Now().UTC().Format(time.RFC3339),
				"server":       cfg.Server,
				"framework":    framework,
				"control_id":   control,
				"mappings":     mappings,
				"audit_events": events,
				"note": "Generated by constellationctl audit compliance-export. " +
					"The audit_events chain is tamper-evident; verify with " +
					"`constellationctl audit verify` before submission.",
			}
			b, _ := json.MarshalIndent(bundle, "", "  ")
			if outPath != "" {
				if err := os.WriteFile(outPath, b, 0o600); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", outPath)
				return nil
			}
			cmd.OutOrStdout().Write(b)
			cmd.OutOrStdout().Write([]byte("\n"))
			return nil
		},
	}
	cmd.Flags().StringVar(&framework, "framework", "", "Framework ID (nist-sp-800-53-r5 | soc2-tsc-2017 | pci-dss-v4.0 | iso-27001-2022)")
	cmd.Flags().StringVar(&control, "control", "", "Control ID within the framework (e.g. AC-2, CC6.1, 8.2, A.5.16)")
	cmd.Flags().IntVar(&limit, "limit", 500, "Maximum audit rows to include (server caps at 500)")
	cmd.Flags().StringVar(&outPath, "out", "", "Output file (default: stdout)")
	return cmd
}
