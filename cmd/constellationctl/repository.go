package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

func repositoryCmd() *cobra.Command {
	var (
		serverFlag string
		email      string
	)
	c := &cobra.Command{
		Use:   "repository",
		Short: "Report repository package evidence",
	}
	c.PersistentFlags().StringVar(&serverFlag, "server", "", "Override Constellation server URL")
	c.PersistentFlags().StringVar(&email, "email", "", "Email to log into if not already authenticated")
	c.AddCommand(repositoryScanCmd(&serverFlag, &email))
	return c
}

func repositoryScanCmd(serverFlag *string, email *string) *cobra.Command {
	var (
		scanPath      string
		repositoryRef string
		repositoryURL string
		sourceType    string
		sourceRef     string
		commitSHA     string
		branch        string
		workflow      string
		runID         string
		packageSource string
		syftBinary    string
		timeout       time.Duration
		jsonOut       bool
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Catalog a repository checkout and queue a repository scan",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cli, err := resolveClient(*serverFlag, *email)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			remoteURL := strings.TrimSpace(repositoryURL)
			if remoteURL == "" {
				remoteURL = inferGitValue(ctx, scanPath, "config", "--get", "remote.origin.url")
			}
			if repositoryRef == "" {
				repositoryRef = normalizeRepositoryRemoteRef(remoteURL)
			}
			repositoryRef = strings.TrimSpace(repositoryRef)
			if repositoryRef == "" {
				return fmt.Errorf("repository ref not resolved; pass --repo")
			}
			if commitSHA == "" {
				commitSHA = inferGitValue(ctx, scanPath, "rev-parse", "HEAD")
			}
			if branch == "" {
				branch = inferGitBranch(ctx, scanPath)
			}
			if sourceRef == "" {
				sourceRef = firstNonEmpty(strings.TrimSpace(commitSHA), strings.TrimSpace(branch), repositoryRef)
			}
			if workflow == "" {
				workflow = strings.TrimSpace(os.Getenv("GITHUB_WORKFLOW"))
			}
			if runID == "" {
				runID = strings.TrimSpace(os.Getenv("GITHUB_RUN_ID"))
			}

			res, err := (&scanner.SyftEngine{Binary: syftBinary}).Scan(ctx, scanPath, scanner.ScanOptions{
				SBOMOnly: true,
				Timeout:  timeout,
			})
			if err != nil {
				return fmt.Errorf("catalog repository packages: %w", err)
			}
			packages := normalizeRepositoryEvidencePackages(res.Packages)
			if len(packages) == 0 {
				return fmt.Errorf("catalog repository packages: syft returned no packages")
			}

			payload := repositoryPackageReport{
				RepositoryRef: repositoryRef,
				RepositoryURL: remoteURL,
				SourceType:    sourceType,
				SourceRef:     sourceRef,
				CommitSHA:     strings.TrimSpace(commitSHA),
				Branch:        strings.TrimSpace(branch),
				Path:          strings.TrimSpace(scanPath),
				Workflow:      workflow,
				RunID:         runID,
				PackageSource: packageSource,
				Packages:      packages,
			}
			var out repositoryReportResponse
			if err := (repositoryPackageReporter{client: cli}).Report(ctx, payload, &out); err != nil {
				return err
			}
			if jsonOut {
				raw, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(raw))
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "reported repository=%s source_ref=%s packages=%d scan_target=%s evidence=%s",
				repositoryRef, sourceRef, out.PackageCount, out.ScanTargetID, out.ScanEvidenceID)
			if out.ScanJobID != "" {
				fmt.Fprintf(cmd.OutOrStdout(), " scan_job=%s", out.ScanJobID)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			return nil
		},
	}
	cmd.Flags().StringVar(&scanPath, "path", ".", "Repository checkout path to catalog")
	cmd.Flags().StringVar(&repositoryRef, "repo", "", "Repository identity, for example github.com/acme/app")
	cmd.Flags().StringVar(&repositoryURL, "repository-url", "", "Repository URL; defaults to git remote.origin.url")
	cmd.Flags().StringVar(&sourceType, "source-type", "repository", "Scan source type")
	cmd.Flags().StringVar(&sourceRef, "source-ref", "", "Source reference; defaults to commit SHA, then branch")
	cmd.Flags().StringVar(&commitSHA, "commit-sha", "", "Commit SHA for this package evidence")
	cmd.Flags().StringVar(&branch, "branch", "", "Branch name for this package evidence")
	cmd.Flags().StringVar(&workflow, "workflow", "", "CI workflow name; defaults to GITHUB_WORKFLOW")
	cmd.Flags().StringVar(&runID, "run-id", "", "CI run id; defaults to GITHUB_RUN_ID")
	cmd.Flags().StringVar(&packageSource, "package-source", "syft", "Package inventory source")
	cmd.Flags().StringVar(&syftBinary, "syft-binary", "syft", "Syft binary path")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Repository package catalog timeout")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON response")
	return cmd
}

type repositoryPackageReport struct {
	RepositoryRef string            `json:"repository_ref"`
	RepositoryURL string            `json:"repository_url,omitempty"`
	SourceType    string            `json:"source_type,omitempty"`
	SourceRef     string            `json:"source_ref,omitempty"`
	CommitSHA     string            `json:"commit_sha,omitempty"`
	Branch        string            `json:"branch,omitempty"`
	Path          string            `json:"path,omitempty"`
	Workflow      string            `json:"workflow,omitempty"`
	RunID         string            `json:"run_id,omitempty"`
	PackageSource string            `json:"package_source,omitempty"`
	Packages      []scanner.Package `json:"packages,omitempty"`
}

type repositoryReportResponse struct {
	OK               bool   `json:"ok"`
	ScanTargetID     string `json:"scan_target_id"`
	ScanEvidenceID   string `json:"scan_evidence_id"`
	InventoryHash    string `json:"inventory_hash"`
	PackageCount     int    `json:"package_count"`
	ScanJobEnqueued  bool   `json:"scan_job_enqueued"`
	ScanJobID        string `json:"scan_job_id,omitempty"`
	ScannerSource    string `json:"scanner_source,omitempty"`
	ScannerTargetRef string `json:"scanner_target_ref,omitempty"`
}

type repositoryPackageReporter struct {
	client *authedClient
}

func (r repositoryPackageReporter) Report(_ context.Context, payload repositoryPackageReport, out *repositoryReportResponse) error {
	if r.client == nil {
		return fmt.Errorf("constellation client required")
	}
	return r.client.postJSON("/api/v1/repository-packages:report", payload, out)
}

func normalizeRepositoryEvidencePackages(packages []scanner.Package) []scanner.Package {
	out := make([]scanner.Package, 0, len(packages))
	for _, pkg := range packages {
		pkg.Name = strings.TrimSpace(pkg.Name)
		pkg.Version = strings.TrimSpace(pkg.Version)
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		pkg.Ecosystem = strings.TrimSpace(pkg.Ecosystem)
		pkg.Purl = strings.TrimSpace(pkg.Purl)
		if pkg.NamespaceKind == "" && pkg.Ecosystem != "" {
			pkg.NamespaceKind = "language"
		}
		if pkg.NamespaceName == "" && pkg.Ecosystem != "" {
			pkg.NamespaceName = pkg.Ecosystem
		}
		out = append(out, pkg)
	}
	return out
}

func inferGitValue(ctx context.Context, repoPath string, args ...string) string {
	allArgs := append([]string{"-C", repoPath}, args...)
	cmd := newExecCommand(ctx, "git", allArgs...)
	raw, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func inferGitBranch(ctx context.Context, repoPath string) string {
	branch := inferGitValue(ctx, repoPath, "rev-parse", "--abbrev-ref", "HEAD")
	if branch == "HEAD" {
		return ""
	}
	return branch
}

func normalizeRepositoryRemoteRef(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimSuffix(raw, ".git")
	if host, path, ok := strings.Cut(raw, ":"); ok && strings.Contains(host, "@") && !strings.Contains(host, "://") {
		_, host, _ = strings.Cut(host, "@")
		return strings.Trim(host+"/"+strings.TrimPrefix(path, "/"), "/")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return strings.Trim(raw, "/")
	}
	host := parsed.Host
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	return strings.Trim(host+"/"+strings.TrimPrefix(parsed.Path, "/"), "/")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
