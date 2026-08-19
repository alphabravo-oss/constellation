// scanner-driver is a short-term out-of-cluster scanner harness used in the Wave I
// e2e environment. It exists because the in-cluster e2e-scanner Deployment is missing a
// CONSTELLATION_SCANNER_TOKEN environment variable, so it cannot authenticate to the
// control plane's worker endpoints. Reprovisioning the operator-managed Deployment +
// rebuilding the scanner image to fix this is high-cost; this driver delivers the same
// behavior (claim a pending scan_jobs row, run trivy/syft/grype, POST results) from the
// developer host while the longer-term operator change is sequenced separately.
//
// What it does:
//
//  1. Connects to Postgres directly to enumerate orgs that have at least one pending
//     scan_jobs row.
//  2. Mints a scanner_tokens row per org (via handler.IssueScannerToken) so subsequent
//     HTTP calls authenticate against the existing ScannerTokenMiddleware.
//  3. Per org, polls POST /api/v1/scan-jobs/claim, runs scanner.Aggregator.Scan against
//     the image_ref, POSTs results to /complete. Failures hit /fail.
//
// Run it from the repo root:
//
//	DATABASE_URL=postgres://... API_URL=http://localhost:18080 \
//	  go run ./deploy/e2e/scanner-driver --max 8
//
// Flags + env vars:
//
//	--api / API_URL           base URL of constellation-api (default http://localhost:18080)
//	--db  / DATABASE_URL      Postgres URL (required)
//	--max                     max jobs to process across all orgs (default 50)
//	--job-timeout             per-image scan timeout (default 8m)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/scanner"
)

func main() {
	var (
		apiURL     = flag.String("api", envOr("API_URL", "http://localhost:18080"), "constellation-api base URL")
		dbURL      = flag.String("db", envOr("DATABASE_URL", ""), "Postgres URL")
		maxJobs    = flag.Int("max", 50, "max jobs to process across all orgs")
		jobTimeout = flag.Duration("job-timeout", 8*time.Minute, "per-image scan timeout")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *dbURL == "" {
		logger.Error("DATABASE_URL or --db is required")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	d, err := db.Connect(ctx, *dbURL)
	if err != nil {
		logger.Error("db connect", "err", err)
		os.Exit(1)
	}
	defer d.Close()
	pool := d.Pool()

	// Find orgs with pending scan_jobs rows. This driver is scoped to clearing the queue;
	// orgs added after start will not be picked up.
	rows, err := pool.Query(ctx, `
SELECT DISTINCT org_id FROM scan_jobs WHERE status = 'pending'`)
	if err != nil {
		logger.Error("list pending orgs", "err", err)
		os.Exit(1)
	}
	var orgs []uuid.UUID
	for rows.Next() {
		var oid uuid.UUID
		if err := rows.Scan(&oid); err != nil {
			rows.Close()
			logger.Error("scan org", "err", err)
			os.Exit(1)
		}
		orgs = append(orgs, oid)
	}
	rows.Close()
	if len(orgs) == 0 {
		logger.Info("no orgs have pending jobs; exiting")
		return
	}
	logger.Info("orgs with pending jobs", "count", len(orgs))

	agg := scanner.NewDefault()
	api := strings.TrimRight(*apiURL, "/")
	processed, failed := 0, 0

	for _, org := range orgs {
		if processed+failed >= *maxJobs {
			break
		}
		// Mint a per-run scanner token. Short TTL keeps it self-cleaning.
		tok, _, err := handler.IssueScannerToken(ctx, pool, org, "scanner-driver", 2*time.Hour)
		if err != nil {
			logger.Error("issue scanner token", "org", org, "err", err)
			continue
		}
		logger.Info("scanner token issued", "org", org)

		for {
			if processed+failed >= *maxJobs {
				break
			}
			job, err := claim(ctx, api, tok)
			if err != nil {
				logger.Warn("claim", "org", org, "err", err)
				break
			}
			if job == nil {
				logger.Info("no more pending jobs", "org", org)
				break
			}
			logger.Info("claimed job", "job_id", job.ID, "image", job.ImageRef)

			scanCtx, scanCancel := context.WithTimeout(ctx, *jobTimeout)
			res, err := agg.Scan(scanCtx, job.ImageRef, scanner.ScanOptions{Timeout: *jobTimeout})
			scanCancel()
			if err != nil {
				logger.Error("scan failed", "job_id", job.ID, "image", job.ImageRef, "err", err)
				_ = postFail(ctx, api, tok, job.ID, err.Error())
				failed++
				continue
			}
			if err := postComplete(ctx, api, tok, job.ID, res); err != nil {
				logger.Error("post complete", "job_id", job.ID, "err", err)
				_ = postFail(ctx, api, tok, job.ID, "report: "+err.Error())
				failed++
				continue
			}
			logger.Info("completed",
				"job_id", job.ID,
				"image", job.ImageRef,
				"packages", len(res.Packages),
				"findings", len(res.Findings),
			)
			processed++
		}
	}

	fmt.Printf("\nDONE: processed=%d failed=%d\n", processed, failed)
	if processed == 0 && failed > 0 {
		os.Exit(1)
	}
}

type claimedJob struct {
	ID       string `json:"id"`
	OrgID    string `json:"org_id"`
	ImageRef string `json:"image_ref"`
	Platform string `json:"platform,omitempty"`
}

func claim(ctx context.Context, api, token string) (*claimedJob, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, api+"/api/v1/scan-jobs/claim", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("claim: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var j claimedJob
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return nil, err
	}
	return &j, nil
}

type completePayload struct {
	PackageCount   int                     `json:"package_count"`
	Findings       []scanner.Finding       `json:"findings"`
	BundleMetadata *scanner.BundleMetadata `json:"bundle_metadata,omitempty"`
}

func postComplete(ctx context.Context, api, token, jobID string, res *scanner.ScanResult) error {
	body, _ := json.Marshal(completePayload{
		PackageCount:   len(res.Packages),
		Findings:       res.Findings,
		BundleMetadata: res.BundleMetadata,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		api+"/api/v1/scan-jobs/"+jobID+"/complete", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("complete: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func postFail(ctx context.Context, api, token, jobID, errMsg string) error {
	body, _ := json.Marshal(map[string]string{"error": errMsg})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		api+"/api/v1/scan-jobs/"+jobID+"/fail", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
