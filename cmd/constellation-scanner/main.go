// constellation-scanner is the scaling-unit scanner worker.
//
// It pulls scan jobs from the control plane, runs the multi-engine aggregator
// (Syft package inventory + VulnDB matching, with optional Trivy/Grype evidence),
// and persists results back via the API. The image bundles the upstream scanner
// CLIs (see deploy/docker/Dockerfile.scanner).
//
// Why it's a separate binary (not embedded in constellation-api):
//   - CPU + memory profile diverges sharply (multi-GB Trivy DB loads, image layer extracts).
//   - Trivy DB refreshes daily — we want scanner pods to roll without touching the API.
//   - Lets us scale horizontally by queue depth without over-provisioning the API.
//
// Two execution modes:
//
//  1. Queue mode (default in cluster): polls /api/v1/scan-jobs?status=pending, claims one,
//     runs the aggregator, POSTs results, repeats. Honors max-concurrent-jobs.
//  2. CLI mode (--ref ghcr.io/foo/bar:1): one-shot scan, prints/writes artifacts, exits.
//     Useful for ad-hoc CLI work + the docker-compose dev loop.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alphabravocompany/constellation/internal/imageid"
	"github.com/alphabravocompany/constellation/internal/registry"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/observability"
	"github.com/alphabravocompany/constellation/pkg/sigverify"
	"github.com/alphabravocompany/constellation/pkg/version"
)

func main() {
	var (
		controlPlaneURL       = flag.String("control-plane", envOr("CONSTELLATION_CONTROL_PLANE_URL", ""), "Control-plane base URL")
		token                 = flag.String("token", envOr("CONSTELLATION_SCANNER_TOKEN", ""), "Scanner service token (registered with the API)")
		instanceID            = flag.String("instance-id", envOr("CONSTELLATION_SCANNER_INSTANCE_ID", ""), "Stable scanner instance ID for job lease ownership")
		maxConcurrent         = flag.Int("max-concurrent", envInt("CONSTELLATION_SCANNER_MAX_CONCURRENT", runtime.NumCPU()), "Max concurrent scans per worker")
		targetCapacity        = flag.String("target-capacity", envOr("CONSTELLATION_SCANNER_TARGET_CAPACITY", ""), "Comma-separated target-type scan credits, for example image=2,host=8,platform=4")
		pollInterval          = flag.Duration("poll-interval", 15*time.Second, "How often to poll for new jobs")
		jobTimeout            = flag.Duration("job-timeout", 15*time.Minute, "Per-job timeout")
		leaseRenewInterval    = flag.Duration("lease-renew-interval", 5*time.Minute, "How often to renew claimed job leases")
		oneShotRef            = flag.String("ref", "", "If set: run a single scan against this image ref and exit (CLI mode)")
		oneShotSARIF          = flag.String("sarif", "", "CLI mode: write SARIF to this path")
		oneShotJSON           = flag.String("json", "", "CLI mode: write JSON to this path")
		listenAddr            = flag.String("listen", ":8090", "Health + metrics listen address")
		enableSyft            = flag.Bool("syft-enabled", envBool("CONSTELLATION_SCANNER_SYFT_ENABLED", true), "Enable Syft package inventory")
		enableTrivy           = flag.Bool("trivy-enabled", envBool("CONSTELLATION_SCANNER_TRIVY_ENABLED", true), "Enable Trivy vulnerability evidence engine")
		enableGrype           = flag.Bool("grype-enabled", envBool("CONSTELLATION_SCANNER_GRYPE_ENABLED", true), "Enable Grype vulnerability evidence engine")
		verifySignatures      = flag.Bool("signature-enabled", envBool("CONSTELLATION_SCANNER_SIGNATURE_ENABLED", true), "Enable cosign image signature verification")
		signatureMode         = flag.String("signature-mode", envOr("CONSTELLATION_SCANNER_SIGNATURE_MODE", "keyless"), "Signature verification mode: keyless or public-key")
		signatureRequireRekor = flag.Bool("signature-rekor-required", envBool("CONSTELLATION_SCANNER_SIGNATURE_REKOR_REQUIRED", false), "Require Rekor transparency log entries for signature verification")
		signatureIdentities   = flag.String("signature-identities", envOr("CONSTELLATION_SCANNER_SIGNATURE_IDENTITIES", ""), "Comma-separated certificate identity regexes trusted for image signatures")
		signatureIssuers      = flag.String("signature-issuers", envOr("CONSTELLATION_SCANNER_SIGNATURE_ISSUERS", ""), "Comma-separated OIDC issuer regexes trusted for image signatures")
		signaturePublicKey    = flag.String("signature-public-key", envOr("CONSTELLATION_SCANNER_SIGNATURE_PUBLIC_KEY_PATH", ""), "Cosign public key path for public-key image signature verification")
		signatureRoots        = flag.String("signature-roots", envOr("CONSTELLATION_SCANNER_SIGNATURE_ROOTS", ""), "Additional named roots-of-trust as a JSON array of {Name,Mode,Identities,Issuers,RekorURL,TUFMirror,TUFRootPath,TUFRootJSON} objects (or @path to a JSON file). An image is trusted if ANY configured root verifies it.")
		cosignBin             = flag.String("cosign-bin", envOr("CONSTELLATION_COSIGN_BIN", "cosign"), "Cosign binary path for image signature verification")
		fileRiskEnabled       = flag.Bool("file-risk-enabled", envBool("CONSTELLATION_SCANNER_FILE_RISK_ENABLED", true), "Enable image filesystem metadata risk scanning")
		fileRiskMaxFindings   = flag.Int("file-risk-max-findings", envInt("CONSTELLATION_SCANNER_FILE_RISK_MAX_FINDINGS", 500), "Max image file-risk findings retained per scan")
		iacEnabled            = flag.Bool("iac-enabled", envBool("CONSTELLATION_SCANNER_IAC_ENABLED", false), "Enable Trivy IaC / config misconfiguration scanning on image targets (opt-in)")
		goReachabilityEnabled = flag.Bool("go-reachability-enabled", envBool("CONSTELLATION_SCANNER_GO_REACHABILITY_ENABLED", false), "Enable govulncheck binary-mode reachability analysis for Go-binary findings (opt-in; requires govulncheck on PATH)")
		tlsSkipVerify         = flag.Bool("tls-skip-verify", envBool("CONSTELLATION_SCANNER_TLS_SKIP_VERIFY", false), "Skip TLS certificate verification for outbound artifact downloads (serverless). Mirrors the org egress tls_verify=false opt-out; the proxy honors HTTPS_PROXY/NO_PROXY from the environment.")
		dbRefreshInterval     = flag.Duration("db-refresh-interval", envDuration("CONSTELLATION_SCANNER_DB_REFRESH_INTERVAL", 6*time.Hour), "Default cadence to refresh Trivy/Grype vuln DBs; overridable at runtime via the UI (system_config scanner_db_refresh_minutes).")
		offlineDB             = flag.Bool("offline-db", envBool("CONSTELLATION_SCANNER_OFFLINE_DB", false), "Air-gapped mode: never pull Trivy/Grype DBs from the internet (operators pre-load them).")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	tel, err := observability.Init(ctx, "constellation-scanner")
	if err != nil {
		fmt.Fprintln(os.Stderr, "observability init:", err)
		os.Exit(1)
	}
	defer func() {
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = tel.Shutdown(sctx)
	}()
	logger := tel.Logger
	version.LogStartup(logger, "scanner")

	agg := scanner.NewDefaultWithConfig(scanner.AggregatorConfig{
		DisableSyft:  !*enableSyft,
		DisableTrivy: !*enableTrivy,
		DisableGrype: !*enableGrype,
	})

	// One-shot CLI mode.
	if *oneShotRef != "" {
		res, err := agg.Scan(ctx, *oneShotRef, scanner.ScanOptions{Timeout: *jobTimeout, GoReachability: *goReachabilityEnabled})
		if err != nil {
			logger.Error("scan", "err", err)
			os.Exit(1)
		}
		if *verifySignatures {
			roots, err := buildSignatureRoots(sigverify.TrustPolicy{
				Mode:          *signatureMode,
				Identities:    splitCSV(*signatureIdentities),
				Issuers:       splitCSV(*signatureIssuers),
				RequireRekor:  *signatureRequireRekor,
				PublicKeyPath: *signaturePublicKey,
			}, *signatureRoots)
			if err != nil {
				logger.Error("signature-roots", "err", err)
				os.Exit(1)
			}
			res.Signature = verifyImageSignature(ctx, *oneShotRef, *cosignBin, roots)
		}
		res.Layers = inspectImageLayers(ctx, *oneShotRef, "")
		scanner.AttributeLayers(res.Layers, res.Packages, res.Findings)
		if *fileRiskEnabled {
			res.FileRisks = inspectImageFileRisks(ctx, *oneShotRef, "", *fileRiskMaxFindings)
			res.ConfigChecks = inspectImageConfigChecks(ctx, *oneShotRef, "")
		}
		if *oneShotJSON != "" {
			b, _ := json.MarshalIndent(res, "", "  ")
			_ = os.WriteFile(*oneShotJSON, b, 0o644)
		}
		if *oneShotSARIF != "" {
			// SARIF emission happens client-side from JSON; the worker keeps the dep surface small.
			logger.Info("CLI mode: SARIF emission expected to be done by constellationctl; use that for SARIF output")
		}
		logger.Info("scan complete",
			"image", res.ImageRef,
			"packages", len(res.Packages),
			"findings", len(res.Findings))
		return
	}

	// Service mode requires a control plane.
	if *controlPlaneURL == "" {
		fmt.Fprintln(os.Stderr, "--control-plane (or CONSTELLATION_CONTROL_PLANE_URL) required for service mode")
		os.Exit(2)
	}
	normalizedMaxConcurrent := normalizeMaxConcurrent(*maxConcurrent)
	capacities := parseTargetCapacities(*targetCapacity, normalizedMaxConcurrent)

	signatureRootsCfg, err := buildSignatureRoots(sigverify.TrustPolicy{
		Mode:          *signatureMode,
		Identities:    splitCSV(*signatureIdentities),
		Issuers:       splitCSV(*signatureIssuers),
		RequireRekor:  *signatureRequireRekor,
		PublicKeyPath: *signaturePublicKey,
	}, *signatureRoots)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid --signature-roots:", err)
		os.Exit(2)
	}

	w := &worker{
		controlPlane:     strings.TrimRight(*controlPlaneURL, "/"),
		token:            *token,
		instanceID:       scannerInstanceID(*instanceID),
		agg:              agg,
		maxConcurrent:    normalizedMaxConcurrent,
		targetCapacity:   capacities,
		activeByType:     map[string]int{},
		jobTimeout:       *jobTimeout,
		leaseRenewPeriod: *leaseRenewInterval,
		engines: map[string]bool{
			"syft":  *enableSyft,
			"trivy": *enableTrivy,
			"grype": *enableGrype,
		},
		cacheDirs: map[string]string{
			"xdg":   envOr("XDG_CACHE_HOME", ""),
			"syft":  envOr("SYFT_CACHE_DIR", ""),
			"grype": envOr("GRYPE_DB_CACHE_DIR", ""),
			"trivy": envOr("TRIVY_CACHE_DIR", ""),
		},
		signatureEnabled: *verifySignatures,
		cosignBin:        *cosignBin,
		signatureRoots:   signatureRootsCfg,
		fileRiskEnabled:       *fileRiskEnabled,
		fileRiskMaxFindings:   *fileRiskMaxFindings,
		iacEnabled:            *iacEnabled,
		goReachabilityEnabled: *goReachabilityEnabled,
		artifactHTTPClient:    newArtifactHTTPClient(*tlsSkipVerify),
		logger:                logger,
	}

	// Health / metrics server runs alongside the polling loop.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("/readyz", w.handleReadyz)
	mux.Handle("/metrics", tel.MetricsHandler())
	httpServer := &http.Server{Addr: *listenAddr, Handler: tel.HTTPMiddleware(mux), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Info("scanner listening", "addr", *listenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen", "err", err)
		}
	}()
	defer func() {
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = httpServer.Shutdown(sctx)
	}()

	// Wave N6: heartbeat loop. Reuses the scanner-token for /api/v1/heartbeats.
	go version.HeartbeatLoop(ctx, version.HeartbeatConfigFromEnv("scanner", version.HeartbeatEnvOptions{
		APIBaseURL:   w.controlPlane,
		Token:        w.token,
		TokenEnv:     []string{"CONSTELLATION_SCANNER_TOKEN", "SCANNER_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_SCANNER_TOKEN_FILE", "SCANNER_TOKEN_FILE"},
		Logger:       logger,
		LastErrorFn:  w.lastError,
		MetadataFn:   func() any { return w.statusSnapshot() },
	}))

	// Keep Trivy/Grype vuln DBs fresh on a schedule (UI-overridable), so connected
	// scanners auto-update without a per-scan pull or a redeploy.
	go w.dbRefreshLoop(ctx, *dbRefreshInterval, *offlineDB)

	w.run(ctx, *pollInterval)
}

// worker polls the control plane for jobs and runs them on a bounded goroutine pool.
type worker struct {
	controlPlane          string
	token                 string
	instanceID            string
	maxConcurrent         int
	targetCapacity        map[string]int
	activeMu              sync.Mutex
	activeByType          map[string]int
	jobTimeout            time.Duration
	leaseRenewPeriod      time.Duration
	agg                   *scanner.Aggregator
	engines               map[string]bool
	cacheDirs             map[string]string
	lastErrMu             sync.Mutex
	lastErr               string
	signatureEnabled      bool
	cosignBin             string
	signatureRoots        sigverify.RootsOfTrust
	fileRiskEnabled       bool
	fileRiskMaxFindings   int
	iacEnabled            bool
	goReachabilityEnabled bool
	// artifactHTTPClient is the outbound client used for serverless artifact
	// downloads. It honors HTTPS_PROXY/NO_PROXY from the environment (the egress
	// proxy injected into the scanner pod) and the -tls-skip-verify TLS opt-out,
	// so downloads obey the same proxy/TLS policy as the rest of the platform
	// rather than falling back to a bare default transport.
	artifactHTTPClient *http.Client
	logger             interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
		Error(msg string, args ...any)
	}
}

func (w *worker) run(ctx context.Context, interval time.Duration) {
	sem := make(chan struct{}, w.maxConcurrent)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

	fillSlots:
		for {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			default:
				break fillSlots
			}

			eligibleTypes := w.availableTargetTypes()
			if w.targetCapacity != nil && len(eligibleTypes) == 0 {
				<-sem
				break fillSlots
			}
			job, err := w.claimJob(ctx, eligibleTypes)
			if err != nil {
				<-sem
				w.logger.Warn("claim job", "err", err)
				w.setLastError("claim job: " + err.Error())
				break
			}
			if job == nil {
				<-sem
				break
			}
			w.reserveTarget(job.TargetType)
			go func(j *scanJob) {
				defer func() {
					w.releaseTarget(j.TargetType)
					<-sem
				}()
				jobCtx, timeoutCancel := context.WithTimeout(ctx, w.jobTimeout)
				jobCtx, cancel := context.WithCancel(jobCtx)
				defer timeoutCancel()
				defer cancel()
				renewDone := make(chan struct{})
				go w.renewJobLease(jobCtx, j.ID, cancel, renewDone)
				w.executeJob(jobCtx, j)
				cancel()
				<-renewDone
			}(job)
		}
	}
}

// scanJob mirrors the API's scan-job envelope (kept narrow on purpose).
type scanJob struct {
	ID              string  `json:"id"`
	OrgID           string  `json:"org_id"`
	TargetID        string  `json:"target_id"`
	TargetType      string  `json:"target_type"`
	TargetRef       string  `json:"target_ref"`
	TargetClusterID *string `json:"target_cluster_id,omitempty"`
	SourceType      string  `json:"source_type,omitempty"`
	SourceRef       string  `json:"source_ref,omitempty"`
	RegistryID      *string `json:"registry_id,omitempty"`
	ImageDigest     string  `json:"image_digest,omitempty"`
	Platform        string  `json:"platform,omitempty"`
	InventoryHash   string  `json:"inventory_hash,omitempty"`
	EvidenceID      *string `json:"evidence_id,omitempty"`
	LeaseExpiresAt  string  `json:"lease_expires_at,omitempty"`
	AttemptCount    int     `json:"attempt_count,omitempty"`
	MaxAttempts     int     `json:"max_attempts,omitempty"`
	// SignatureRoots are this job's org's DB-managed sigstore roots-of-trust, delivered on the
	// job envelope by the server (handler.RootsForOrg). They are unioned onto the static
	// flag-configured roots for THIS job only, so org A's roots never leak into org B's scans.
	SignatureRoots []sigverify.RootOfTrust `json:"signature_roots,omitempty"`
}

type scanEvidence struct {
	ID            string            `json:"id"`
	TargetID      string            `json:"target_id"`
	TargetType    string            `json:"target_type"`
	TargetRef     string            `json:"target_ref"`
	EvidenceType  string            `json:"evidence_type"`
	InventoryHash string            `json:"inventory_hash"`
	PackageCount  int               `json:"package_count"`
	Packages      []scanner.Package `json:"packages"`
}

type scanResultPayload struct {
	JobID          string                       `json:"job_id"`
	ImageRef       string                       `json:"image_ref"`
	ImageDigest    string                       `json:"image_digest,omitempty"`
	Platform       string                       `json:"platform,omitempty"`
	ScannerProfile string                       `json:"scanner_profile,omitempty"`
	PackageCount   int                          `json:"package_count"`
	Packages       []scanner.Package            `json:"packages,omitempty"`
	Secrets        []scanner.SecretFinding      `json:"secrets,omitempty"`
	Misconfigs     []scanner.MisconfigFinding   `json:"misconfigs,omitempty"`
	Signature      *scanner.SignatureResult     `json:"signature,omitempty"`
	Layers         *scanner.ImageLayerMetadata  `json:"layers,omitempty"`
	FileRisks      *scanner.ImageFileRiskReport `json:"file_risks,omitempty"`
	ConfigChecks   *scanner.ImageConfigCheckReport `json:"config_checks,omitempty"`
	Findings       []scanner.Finding            `json:"findings"`
	Engines        []engineSummary              `json:"engines"`
	BundleMetadata *scanner.BundleMetadata      `json:"bundle_metadata,omitempty"`
	StartedAt      time.Time                    `json:"started_at"`
	EndedAt        time.Time                    `json:"ended_at"`
}

type engineSummary struct {
	Engine   string        `json:"engine"`
	Duration time.Duration `json:"duration_ns"`
	Error    string        `json:"error,omitempty"`
}

func (w *worker) claimJob(ctx context.Context, targetTypes []string) (*scanJob, error) {
	url := w.controlPlane + "/api/v1/scan-jobs/claim"
	if len(targetTypes) > 0 {
		parts := make([]string, 0, len(targetTypes))
		for _, targetType := range targetTypes {
			parts = append(parts, "target_type="+targetType)
		}
		url += "?" + strings.Join(parts, "&")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	w.setScannerHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("claim: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var j scanJob
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return nil, err
	}
	return &j, nil
}

func (w *worker) availableTargetTypes() []string {
	if w.targetCapacity == nil {
		return nil
	}
	w.activeMu.Lock()
	defer w.activeMu.Unlock()
	out := make([]string, 0, len(w.targetCapacity))
	for _, targetType := range scannerTargetTypes() {
		capacity := w.targetCapacity[targetType]
		if capacity > 0 && w.activeByType[targetType] < capacity {
			out = append(out, targetType)
		}
	}
	return out
}

func (w *worker) reserveTarget(targetType string) {
	if strings.TrimSpace(targetType) == "" {
		targetType = "image"
	}
	w.activeMu.Lock()
	defer w.activeMu.Unlock()
	w.activeByType[targetType]++
}

func (w *worker) releaseTarget(targetType string) {
	if strings.TrimSpace(targetType) == "" {
		targetType = "image"
	}
	w.activeMu.Lock()
	defer w.activeMu.Unlock()
	if w.activeByType[targetType] > 0 {
		w.activeByType[targetType]--
	}
}

func (w *worker) statusSnapshot() map[string]any {
	return w.statusSnapshotWithCacheUsage(true)
}

func (w *worker) statusSnapshotWithCacheUsage(includeCacheUsage bool) map[string]any {
	w.activeMu.Lock()
	activeByType := make(map[string]int, len(w.activeByType))
	activeJobs := 0
	for targetType, count := range w.activeByType {
		activeByType[targetType] = count
		activeJobs += count
	}
	capacityByType := map[string]int{}
	if w.targetCapacity != nil {
		for targetType, capacity := range w.targetCapacity {
			capacityByType[targetType] = capacity
		}
	}
	w.activeMu.Unlock()

	idle := w.maxConcurrent - activeJobs
	if idle < 0 {
		idle = 0
	}
	return map[string]any{
		"instance_id":                w.instanceID,
		"max_concurrent":             w.maxConcurrent,
		"active_jobs":                activeJobs,
		"idle_capacity":              idle,
		"target_capacity":            capacityByType,
		"active_jobs_by_target_type": activeByType,
		"engines":                    w.engines,
		"cache_dirs":                 w.cacheDirs,
		"cache_health":               scannerCacheHealth(w.cacheDirs, includeCacheUsage),
	}
}

func (w *worker) handleReadyz(rw http.ResponseWriter, _ *http.Request) {
	status := w.statusSnapshotWithCacheUsage(false)
	status["status"] = "ready"
	writeScannerJSON(rw, http.StatusOK, status)
}

func (w *worker) setLastError(message string) {
	w.lastErrMu.Lock()
	defer w.lastErrMu.Unlock()
	w.lastErr = strings.TrimSpace(message)
}

func (w *worker) lastError() string {
	w.lastErrMu.Lock()
	defer w.lastErrMu.Unlock()
	return w.lastErr
}

func (w *worker) executeJob(ctx context.Context, j *scanJob) {
	w.logger.Info("scan start", "job_id", j.ID, "target_id", j.TargetID, "target_type", j.TargetType, "target_ref", j.TargetRef)
	var (
		res *scanner.ScanResult
		err error
	)
	switch j.TargetType {
	case "image":
		imageRef := strings.TrimSpace(j.TargetRef)
		if imageRef == "" {
			_ = w.reportFailure(ctx, j.ID, "missing_target_ref")
			return
		}
		// REG-PRIVAUTH-11: a registry-scoped job carries the credentials needed
		// to pull from a private registry. Fetch + materialize them (per-job
		// docker config.json + TRIVY_/GRYPE_/SYFT_ env) for the scan tools, and
		// clean them up when the job returns. Best-effort: a fetch failure logs
		// and proceeds unauthenticated (public images still scan).
		regAuth, releaseRegAuth := w.resolveRegistryAuth(ctx, j, imageRef)
		defer releaseRegAuth()
		hasEvidence := j.EvidenceID != nil && strings.TrimSpace(*j.EvidenceID) != ""
		// scanFromEvidence scans the image's pre-collected package inventory
		// (no registry pull). It sets res/err and returns true when it handled
		// the job; returns false only when no evidence is available.
		scanFromEvidence := func(reason string) bool {
			if !hasEvidence {
				return false
			}
			evidence, fetchErr := w.fetchEvidence(ctx, strings.TrimSpace(*j.EvidenceID))
			if fetchErr != nil {
				w.logger.Error("fetch image evidence failed", "job_id", j.ID, "evidence_id", *j.EvidenceID, "err", fetchErr)
				w.setLastError(fetchErr.Error())
				err = fetchErr
				return true
			}
			if j.InventoryHash != "" && evidence.InventoryHash != "" && j.InventoryHash != evidence.InventoryHash {
				err = errors.New("stale_package_evidence")
				return true
			}
			if reason != "" {
				w.logger.Info("scanning image from collected package evidence", "job_id", j.ID, "image", imageRef, "reason", reason)
			}
			res, err = w.agg.ScanPackages(ctx, imageRef, evidence.Packages, scanner.ScanOptions{Platform: j.Platform, Timeout: w.jobTimeout, GoReachability: w.goReachabilityEnabled})
			if err == nil && res != nil && strings.TrimSpace(res.ImageRef) == "" {
				res.ImageRef = imageRef
			}
			return true
		}
		// runtime-agent image targets carry package evidence collected off the
		// running container — scan that directly, never a registry pull.
		if j.SourceType == "runtime-agent" && scanFromEvidence("") {
			break
		}
		// Otherwise prefer a full registry scan; fall back to collected package
		// evidence when the image can't be resolved from a registry — e.g. a
		// node-local image built on the cluster and never pushed anywhere.
		pinnedRef, digest, resolveErr := resolveImageDigestRef(ctx, imageRef)
		if resolveErr != nil {
			if scanFromEvidence("image not resolvable from registry: " + resolveErr.Error()) {
				break
			}
			w.logger.Error("resolve image digest failed", "job_id", j.ID, "image", imageRef, "err", resolveErr)
			w.setLastError(resolveErr.Error())
			_ = w.reportFailure(ctx, j.ID, resolveErr.Error())
			return
		}
		imageRef = pinnedRef
		j.TargetRef = pinnedRef
		res, err = w.agg.Scan(ctx, imageRef, scanner.ScanOptions{
			Platform:          j.Platform,
			Timeout:           w.jobTimeout,
			IncludeIaC:        w.iacEnabled,
			GoReachability:    w.goReachabilityEnabled,
			Username:          regAuth.Username,
			Password:          regAuth.Password,
			RegistryAuthority: regAuth.Authority,
			DockerConfigDir:   regAuth.DockerConfigDir,
		})
		if err != nil && scanFromEvidence("registry scan failed: "+err.Error()) {
			// Node-local images (e.g. a bare sha256: ref that resolves but syft
			// can't pull) fall back to collected package evidence.
			break
		}
		if err == nil && digest != "" && res != nil && strings.TrimSpace(res.ImageRef) == "" {
			res.ImageRef = pinnedRef
		}
	case "serverless":
		// Prefer a real artifact scan (download + unzip the function bundle + Syft)
		// when the job carries an artifact source and no pre-collected evidence. This
		// runs independent of any deployed runtime-agent. Fall back to the evidence
		// path (agent/discoverer-collected package inventory) otherwise.
		hasEvidence := j.EvidenceID != nil && strings.TrimSpace(*j.EvidenceID) != ""
		artifactSrc := serverlessArtifactSource(j)
		if artifactSrc != "" && !hasEvidence {
			res, err = w.scanServerlessArtifact(ctx, j, artifactSrc)
			break
		}
		if !hasEvidence {
			_ = w.reportFailure(ctx, j.ID, "missing_package_evidence")
			return
		}
		evidence, fetchErr := w.fetchEvidence(ctx, strings.TrimSpace(*j.EvidenceID))
		if fetchErr != nil {
			w.logger.Error("fetch evidence failed", "job_id", j.ID, "evidence_id", *j.EvidenceID, "err", fetchErr)
			w.setLastError(fetchErr.Error())
			_ = w.reportFailure(ctx, j.ID, fetchErr.Error())
			return
		}
		if j.InventoryHash != "" && evidence.InventoryHash != "" && j.InventoryHash != evidence.InventoryHash {
			_ = w.reportFailure(ctx, j.ID, "stale_package_evidence")
			return
		}
		res, err = w.agg.ScanPackages(ctx, j.TargetRef, evidence.Packages, scanner.ScanOptions{Platform: j.Platform, Timeout: w.jobTimeout, GoReachability: w.goReachabilityEnabled})
	case "host", "workload", "platform", "repository":
		if j.EvidenceID == nil || strings.TrimSpace(*j.EvidenceID) == "" {
			_ = w.reportFailure(ctx, j.ID, "missing_package_evidence")
			return
		}
		evidence, fetchErr := w.fetchEvidence(ctx, strings.TrimSpace(*j.EvidenceID))
		if fetchErr != nil {
			w.logger.Error("fetch evidence failed", "job_id", j.ID, "evidence_id", *j.EvidenceID, "err", fetchErr)
			w.setLastError(fetchErr.Error())
			_ = w.reportFailure(ctx, j.ID, fetchErr.Error())
			return
		}
		if j.InventoryHash != "" && evidence.InventoryHash != "" && j.InventoryHash != evidence.InventoryHash {
			_ = w.reportFailure(ctx, j.ID, "stale_package_evidence")
			return
		}
		res, err = w.agg.ScanPackages(ctx, j.TargetRef, evidence.Packages, scanner.ScanOptions{Platform: j.Platform, Timeout: w.jobTimeout, GoReachability: w.goReachabilityEnabled})
	default:
		errMsg := "unsupported_target_type:" + j.TargetType
		w.logger.Warn("scan target unsupported", "job_id", j.ID, "target_type", j.TargetType)
		_ = w.reportFailure(ctx, j.ID, errMsg)
		return
	}
	if err != nil {
		w.logger.Error("scan failed", "job_id", j.ID, "err", err)
		w.setLastError(err.Error())
		_ = w.reportFailure(ctx, j.ID, err.Error())
		return
	}
	imageRef, imageDigest := scanResultIdentity(j, res)
	if w.signatureEnabled && j.TargetType == "image" {
		res.Signature = verifyImageSignature(ctx, imageRef, w.cosignBin, signatureRootsForJob(w.signatureRoots, j.SignatureRoots))
	}
	if j.TargetType == "image" {
		res.Layers = inspectImageLayers(ctx, imageRef, j.Platform)
		scanner.AttributeLayers(res.Layers, res.Packages, res.Findings)
		if w.fileRiskEnabled {
			res.FileRisks = inspectImageFileRisks(ctx, imageRef, j.Platform, w.fileRiskMaxFindings)
			res.ConfigChecks = inspectImageConfigChecks(ctx, imageRef, j.Platform)
		}
	}
	payload := scanResultPayload{
		JobID:          j.ID,
		ImageRef:       imageRef,
		ImageDigest:    imageDigest,
		Platform:       j.Platform,
		ScannerProfile: "default",
		PackageCount:   len(res.Packages),
		Packages:       res.Packages,
		Secrets:        res.Secrets,
		Misconfigs:     res.Misconfigs,
		Signature:      res.Signature,
		Layers:         res.Layers,
		FileRisks:      res.FileRisks,
		ConfigChecks:   res.ConfigChecks,
		Findings:       res.Findings,
		BundleMetadata: res.BundleMetadata,
		StartedAt:      res.StartedAt,
		EndedAt:        res.EndedAt,
	}
	for _, e := range res.Engines {
		payload.Engines = append(payload.Engines, engineSummary{Engine: e.Engine, Duration: e.Duration, Error: e.Error})
	}
	if err := w.reportSuccess(ctx, payload); err != nil {
		w.logger.Error("report", "job_id", j.ID, "err", err)
		w.setLastError(err.Error())
		return
	}
	w.setLastError("")
	w.logger.Info("scan complete", "job_id", j.ID, "packages", len(res.Packages), "findings", len(res.Findings))
}

// newArtifactHTTPClient builds the outbound client used for serverless artifact
// downloads. It honors HTTPS_PROXY/HTTP_PROXY/NO_PROXY from the environment via
// http.ProxyFromEnvironment (the egress proxy injected into the scanner pod) and
// the TLS-verify opt-out, so a download obeys the same proxy/TLS policy the rest
// of the platform applies through syscfg rather than using a bare default client.
func newArtifactHTTPClient(tlsSkipVerify bool) *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if tlsSkipVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	return &http.Client{Timeout: 5 * time.Minute, Transport: tr}
}

// serverlessArtifactSource returns the location of a serverless function bundle to
// download + unzip, or "" when the job is not artifact-based. The control plane points
// the scanner at the artifact via source_ref (a presigned https URL, a file:// URL, or a
// local path). target_ref is used as a fallback when it itself looks like an artifact
// location (URL or *.zip path) rather than a function ARN/identifier.
func serverlessArtifactSource(j *scanJob) string {
	if src := strings.TrimSpace(j.SourceRef); looksLikeArtifactSource(src) {
		return src
	}
	if ref := strings.TrimSpace(j.TargetRef); looksLikeArtifactSource(ref) {
		return ref
	}
	return ""
}

func looksLikeArtifactSource(s string) bool {
	if s == "" {
		return false
	}
	switch {
	case strings.HasPrefix(s, "http://"), strings.HasPrefix(s, "https://"), strings.HasPrefix(s, "file://"):
		return true
	case strings.HasSuffix(strings.ToLower(s), ".zip"):
		return true
	default:
		return false
	}
}

// scanServerlessArtifact downloads + unzips the function bundle and runs the full
// aggregator over the extracted directory (Syft SBOM + vuln matching), with no deployed
// agent. The scratch directory is always cleaned up.
func (w *worker) scanServerlessArtifact(ctx context.Context, j *scanJob, source string) (*scanner.ScanResult, error) {
	w.logger.Info("serverless artifact scan", "job_id", j.ID, "source", source)
	unpacked, err := scanner.FetchServerlessArtifact(ctx, scanner.ServerlessArtifact{
		Source:     source,
		HTTPClient: w.artifactHTTPClient,
	})
	if err != nil {
		return nil, fmt.Errorf("serverless artifact: %w", err)
	}
	defer unpacked.Close()
	w.logger.Info("serverless artifact unpacked", "job_id", j.ID, "files", unpacked.Files, "bytes", unpacked.Bytes)

	res, err := w.agg.Scan(ctx, unpacked.Ref(), scanner.ScanOptions{
		Timeout:        w.jobTimeout,
		GoReachability: w.goReachabilityEnabled,
	})
	if err != nil {
		return res, err
	}
	// Report the function identity, not the scratch dir path.
	if ref := strings.TrimSpace(j.TargetRef); ref != "" {
		res.ImageRef = ref
	}
	return res, nil
}

func resolveImageDigestRef(ctx context.Context, ref string) (string, string, error) {
	identity := imageid.Parse(ref)
	if identity.Digest != "" {
		return identity.Normalized, identity.Digest, nil
	}
	resolveRef := identity.Normalized
	if resolveRef == "" {
		resolveRef = strings.TrimSpace(ref)
	}
	resolvedRef, err := registry.ResolveDigestReference(ctx, resolveRef)
	if err != nil {
		return "", "", fmt.Errorf("resolve image digest for %s: %w", ref, err)
	}
	resolved := imageid.Parse(resolvedRef)
	if resolved.Digest == "" {
		return "", "", fmt.Errorf("resolve image digest for %s: registry returned unpinned ref", ref)
	}
	return resolved.Normalized, resolved.Digest, nil
}

func scanResultIdentity(j *scanJob, res *scanner.ScanResult) (string, string) {
	ref := ""
	if res != nil {
		ref = strings.TrimSpace(res.ImageRef)
	}
	if ref == "" {
		ref = strings.TrimSpace(j.TargetRef)
	}
	identity := imageid.Parse(ref)
	digest := identity.Digest
	if digest == "" {
		digest = imageid.Parse(j.TargetRef).Digest
	}
	if digest == "" {
		digest = strings.TrimSpace(j.ImageDigest)
	}
	if identity.Normalized != "" {
		ref = identity.Normalized
	}
	return ref, digest
}

// buildSignatureRoots assembles the ordered roots-of-trust used for image signature
// verification. The flag-configured trust policy is always the default (first) root; any
// additional named roots supplied via --signature-roots (a JSON array, or @path to a JSON
// file) are appended, giving air-gapped / multi-tenant installs the "trusted if ANY root
// verifies" semantics. With no extra roots this is the legacy single-policy case.
func buildSignatureRoots(policy sigverify.TrustPolicy, rootsConfig string) (sigverify.RootsOfTrust, error) {
	roots := sigverify.SingleRoot(policy)
	rootsConfig = strings.TrimSpace(rootsConfig)
	if rootsConfig == "" {
		return roots, nil
	}
	raw := []byte(rootsConfig)
	if path := strings.TrimPrefix(rootsConfig, "@"); path != rootsConfig {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read signature-roots config: %w", err)
		}
		raw = b
	}
	var extra []sigverify.RootOfTrust
	if err := json.Unmarshal(raw, &extra); err != nil {
		return nil, fmt.Errorf("parse signature-roots config: %w", err)
	}
	return append(roots, extra...), nil
}

// signatureRootsForJob unions the per-job org's DB-managed roots onto the static
// flag-configured roots, returning a fresh slice so the static roots are never mutated and one
// org's roots never leak into another org's scan. Verification trusts an image if ANY root
// verifies it, so appending the job roots is purely additive. With no job roots the static
// roots are returned unchanged (legacy behaviour).
func signatureRootsForJob(static sigverify.RootsOfTrust, jobRoots []sigverify.RootOfTrust) sigverify.RootsOfTrust {
	if len(jobRoots) == 0 {
		return static
	}
	out := make(sigverify.RootsOfTrust, 0, len(static)+len(jobRoots))
	out = append(out, static...)
	out = append(out, jobRoots...)
	return out
}

func verifyImageSignature(ctx context.Context, imageRef, cosignBin string, roots sigverify.RootsOfTrust) *scanner.SignatureResult {
	ref := strings.TrimSpace(imageRef)
	identity := imageid.Parse(ref)
	if identity.Repository == "" || identity.Digest == "" {
		return &scanner.SignatureResult{
			ImageRef: ref,
			Status:   "skipped",
			Reason:   "signature verification requires a registry digest reference",
		}
	}
	if identity.Normalized != "" {
		ref = identity.Normalized
	}
	verifier := sigverify.New()
	if cosignBin != "" {
		verifier.CosignBinary = cosignBin
	}
	result, err := verifier.VerifyWithRoots(ctx, ref, roots)
	out := &scanner.SignatureResult{ImageRef: ref}
	if result != nil {
		out.Signed = result.Signed
		out.Trusted = result.Trusted
		out.Identity = result.Identity
		out.Issuer = result.Issuer
		out.RekorLog = result.RekorLog
		out.Attestations = append([]string(nil), result.Attestations...)
		out.Reason = strings.TrimSpace(result.Reason)
	}
	switch {
	case err != nil && errors.Is(err, sigverify.ErrCosignMissing):
		out.Status = "unavailable"
		out.Error = err.Error()
		if out.Reason == "" {
			out.Reason = "cosign binary not available"
		}
	case err != nil:
		out.Status = "error"
		out.Error = err.Error()
		if out.Reason == "" {
			out.Reason = err.Error()
		}
	case out.Trusted:
		out.Status = "trusted"
	case out.Signed:
		out.Status = "untrusted"
	default:
		out.Status = "unsigned"
	}
	return out
}

func inspectImageLayers(ctx context.Context, imageRef, platform string) *scanner.ImageLayerMetadata {
	ref := strings.TrimSpace(imageRef)
	identity := imageid.Parse(ref)
	if identity.Repository == "" || identity.Digest == "" {
		return nil
	}
	if identity.Normalized != "" {
		ref = identity.Normalized
	}
	meta, err := registry.InspectManifestReference(ctx, ref, platform)
	if err != nil {
		return &scanner.ImageLayerMetadata{
			ImageRef: ref,
			Status:   "error",
			Reason:   "registry manifest metadata unavailable",
			Error:    err.Error(),
		}
	}
	out := &scanner.ImageLayerMetadata{
		ImageRef:         meta.ImageRef,
		ManifestDigest:   meta.ManifestDigest,
		IndexDigest:      meta.IndexDigest,
		MediaType:        meta.MediaType,
		Architectures:    append([]string(nil), meta.Architectures...),
		SelectedPlatform: meta.SelectedPlatform,
		TotalSizeBytes:   meta.TotalSizeBytes,
		Status:           "observed",
	}
	if meta.Config != nil {
		out.ConfigDigest = meta.Config.Digest
		out.ConfigMediaType = meta.Config.MediaType
		out.ConfigSizeBytes = meta.Config.SizeBytes
	}
	for _, layer := range meta.Layers {
		out.Layers = append(out.Layers, scanner.ImageLayer{
			MediaType:   layer.MediaType,
			Digest:      layer.Digest,
			SizeBytes:   layer.SizeBytes,
			Annotations: layer.Annotations,
		})
	}
	// Fold OCI config history (build instructions) + rootfs diff_ids onto the
	// layers so each layer carries its Dockerfile instruction and the diff_id
	// used to join packages/vulns. This reads only the small config object, no
	// layer blobs; a failure here is non-fatal (layers keep manifest-only data).
	if history, diffIDs, err := scanner.FetchLayerHistory(ctx, ref, platform, false); err == nil {
		scanner.EnrichLayerHistory(out, history, diffIDs)
	} else if out.Reason == "" {
		out.Reason = "config history unavailable"
	}
	return out
}

// inspectImageConfigChecks evaluates the CIS-Docker image-config controls. Cheap (config
// only, no layer walk) so it always runs alongside the file-risk pass.
func inspectImageConfigChecks(ctx context.Context, imageRef, platform string) *scanner.ImageConfigCheckReport {
	ref := strings.TrimSpace(imageRef)
	identity := imageid.Parse(ref)
	if identity.Repository == "" {
		return nil
	}
	if identity.Normalized != "" {
		ref = identity.Normalized
	}
	report, err := scanner.ScanImageConfigChecks(ctx, ref, platform, false)
	if err != nil {
		return &scanner.ImageConfigCheckReport{ImageRef: ref, Platform: strings.TrimSpace(platform), Status: "error", Reason: "image config unavailable", Error: err.Error()}
	}
	return report
}

func inspectImageFileRisks(ctx context.Context, imageRef, platform string, maxFindings int) *scanner.ImageFileRiskReport {
	ref := strings.TrimSpace(imageRef)
	identity := imageid.Parse(ref)
	if identity.Repository == "" || identity.Digest == "" {
		return nil
	}
	if identity.Normalized != "" {
		ref = identity.Normalized
	}
	report, err := scanner.ScanImageFileRisks(ctx, ref, scanner.FileRiskOptions{
		Platform:    platform,
		MaxFindings: maxFindings,
	})
	if err != nil {
		return &scanner.ImageFileRiskReport{
			ImageRef:     ref,
			Platform:     strings.TrimSpace(platform),
			Status:       "error",
			Reason:       "image filesystem metadata unavailable",
			Error:        err.Error(),
			MaxFindings:  maxFindings,
			FindingCount: 0,
		}
	}
	return report
}

func (w *worker) fetchEvidence(ctx context.Context, evidenceID string) (*scanEvidence, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.controlPlane+"/api/v1/scan-evidence/"+evidenceID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	w.setScannerHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("fetch evidence: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var evidence scanEvidence
	if err := json.NewDecoder(resp.Body).Decode(&evidence); err != nil {
		return nil, err
	}
	if len(evidence.Packages) != evidence.PackageCount && evidence.PackageCount > 0 {
		return nil, fmt.Errorf("fetch evidence: package count mismatch")
	}
	return &evidence, nil
}

// registryCredentials mirrors the control-plane RegistryCredentialsDTO
// (internal/handler/registry_credentials.go). Kept narrow on purpose.
type registryCredentials struct {
	RegistryID string `json:"registry_id"`
	Kind       string `json:"kind"`
	AuthKind   string `json:"auth_kind"`
	Endpoint   string `json:"endpoint,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Token      string `json:"token,omitempty"`
}

// registryAuth is the materialized, ready-to-use credential set for one scan.
type registryAuth struct {
	Username        string
	Password        string
	Authority       string // registry host the credentials apply to
	DockerConfigDir string // dir holding a per-job docker config.json, or ""
}

// resolveRegistryAuth fetches per-registry credentials for a registry-scoped job
// (REG-PRIVAUTH-11) and materializes them for the scan tools: it writes a
// per-job temporary docker config.json (DOCKER_CONFIG) and returns the
// username/password/authority the aggregator threads into TRIVY_/GRYPE_/SYFT_
// env. The returned cleanup func removes the temp dir; it is always non-nil and
// safe to call. On any error (no registry_id, fetch failure, empty creds) it
// returns a zero registryAuth and a no-op cleanup so the scan proceeds
// unauthenticated — public images still scan.
func (w *worker) resolveRegistryAuth(ctx context.Context, j *scanJob, imageRef string) (registryAuth, func()) {
	noop := func() {}
	if j == nil || j.RegistryID == nil || strings.TrimSpace(*j.RegistryID) == "" {
		return registryAuth{}, noop
	}
	registryID := strings.TrimSpace(*j.RegistryID)

	creds, err := w.fetchRegistryCredentials(ctx, registryID)
	if err != nil {
		w.logger.Warn("fetch registry credentials", "job_id", j.ID, "registry_id", registryID, "err", err)
		w.setLastError("fetch registry credentials: " + err.Error())
		return registryAuth{}, noop
	}
	// Token-only auth (e.g. GHCR PAT, bearer) is delivered as the password with
	// a conventional username; static user/pass passes through unchanged.
	username, password := creds.Username, creds.Password
	if password == "" && creds.Token != "" {
		password = creds.Token
		if username == "" {
			username = "x-access-token"
		}
	}
	if username == "" && password == "" {
		// Registry configured with auth_kind=none (or empty secret): nothing to do.
		return registryAuth{}, noop
	}

	authority := registryAuthority(imageRef, creds.Endpoint)

	dir, err := os.MkdirTemp("", "constellation-scan-dockercfg-")
	if err != nil {
		w.logger.Warn("create docker config dir", "job_id", j.ID, "err", err)
		// Still hand back the env-var credentials; only the config.json is lost.
		return registryAuth{Username: username, Password: password, Authority: authority}, noop
	}
	cleanup := func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			w.logger.Warn("cleanup docker config dir", "job_id", j.ID, "dir", dir, "err", rmErr)
		}
	}
	if err := writeDockerConfig(dir, authority, username, password); err != nil {
		w.logger.Warn("write docker config", "job_id", j.ID, "err", err)
		cleanup()
		return registryAuth{Username: username, Password: password, Authority: authority}, noop
	}

	return registryAuth{
		Username:        username,
		Password:        password,
		Authority:       authority,
		DockerConfigDir: dir,
	}, cleanup
}

// fetchRegistryCredentials calls the control-plane endpoint that unseals the
// registry's stored credentials for this scanner's org (scanner-token auth).
func (w *worker) fetchRegistryCredentials(ctx context.Context, registryID string) (*registryCredentials, error) {
	url := w.controlPlane + "/api/v1/scanner/registry-credentials?registry_id=" + neturl.QueryEscape(registryID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	w.setScannerHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var creds registryCredentials
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

// registryAuthority derives the registry host the credentials apply to. It
// prefers the host embedded in the (normalized) image ref and falls back to the
// configured registry endpoint. Docker Hub refs normalize to the docker.io host.
func registryAuthority(imageRef, endpoint string) string {
	repo := imageid.Parse(imageRef).Repository
	if repo != "" {
		if host := repo[:strings.IndexByte(repo+"/", '/')]; host != "" {
			return host
		}
	}
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	if slash := strings.IndexByte(endpoint, '/'); slash >= 0 {
		endpoint = endpoint[:slash]
	}
	return endpoint
}

// writeDockerConfig writes a per-job docker config.json into dir, keyed by the
// registry authority. This is the credential channel go-containerregistry
// (Syft/Grype/Trivy image pulls) reads via DOCKER_CONFIG. For Docker Hub the
// legacy index host is added too so refs under either key authenticate.
func writeDockerConfig(dir, authority, username, password string) error {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	auths := map[string]any{
		authority: map[string]string{
			"auth":     auth,
			"username": username,
			"password": password,
		},
	}
	if authority == "docker.io" {
		auths["https://index.docker.io/v1/"] = map[string]string{
			"auth":     auth,
			"username": username,
			"password": password,
		}
	}
	body, err := json.Marshal(map[string]any{"auths": auths})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), body, 0o600)
}

func (w *worker) reportSuccess(ctx context.Context, p scanResultPayload) error {
	body, _ := json.Marshal(p)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		w.controlPlane+"/api/v1/scan-jobs/"+p.JobID+"/complete", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/json")
	w.setScannerHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("report: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (w *worker) reportFailure(ctx context.Context, jobID, errMsg string) error {
	body, _ := json.Marshal(map[string]any{"error": errMsg, "retryable": retryableScanFailure(errMsg)})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		w.controlPlane+"/api/v1/scan-jobs/"+jobID+"/fail", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/json")
	w.setScannerHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("fail: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (w *worker) renewJobLease(ctx context.Context, jobID string, cancel context.CancelFunc, done chan<- struct{}) {
	defer close(done)
	interval := w.leaseRenewPeriod
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := w.renewOnce(ctx, jobID); err != nil {
			w.logger.Warn("renew scan job lease", "job_id", jobID, "err", err)
			if errors.Is(err, errLeaseNotOwned) {
				cancel()
				return
			}
		}
	}
}

var errLeaseNotOwned = errors.New("scan job lease not owned by this worker")

func (w *worker) renewOnce(ctx context.Context, jobID string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		w.controlPlane+"/api/v1/scan-jobs/"+jobID+"/renew", nil)
	req.Header.Set("Authorization", "Bearer "+w.token)
	w.setScannerHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusNotFound {
		return errLeaseNotOwned
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("renew: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (w *worker) setScannerHeaders(req *http.Request) {
	if w.instanceID != "" {
		req.Header.Set("X-Constellation-Scanner-Instance", w.instanceID)
	}
}

func scannerInstanceID(configured string) string {
	configured = strings.TrimSpace(configured)
	if configured != "" {
		return configured
	}
	host, _ := os.Hostname()
	host = strings.TrimSpace(host)
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	suffix := hex.EncodeToString(buf[:])
	if host == "" {
		return suffix
	}
	return host + "-" + suffix
}

func normalizeMaxConcurrent(value int) int {
	if value <= 0 {
		return runtime.NumCPU()
	}
	return value
}

func parseTargetCapacities(value string, maxConcurrent int) map[string]int {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	out := map[string]int{}
	for _, targetType := range scannerTargetTypes() {
		out[targetType] = maxConcurrent
	}
	for _, part := range strings.Split(value, ",") {
		key, raw, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if !knownScannerTargetType(key) {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(raw), "%d", &n); err != nil {
			continue
		}
		if n < 0 {
			n = 0
		}
		if n > maxConcurrent {
			n = maxConcurrent
		}
		out[key] = n
	}
	return out
}

func scannerTargetTypes() []string {
	return []string{"image", "workload", "host", "platform", "serverless", "repository"}
}

func knownScannerTargetType(targetType string) bool {
	for _, known := range scannerTargetTypes() {
		if targetType == known {
			return true
		}
	}
	return false
}

func scannerCacheHealth(dirs map[string]string, includeUsage bool) map[string]any {
	out := map[string]any{}
	for name, path := range dirs {
		out[name] = scannerCacheDirHealth(path, includeUsage)
	}
	return out
}

const (
	scannerCacheRecordLimit = 20
	scannerCacheWalkLimit   = 2000
)

var errScannerCacheWalkLimit = errors.New("scanner cache walk limit reached")

func scannerCacheDirHealth(path string, includeUsage bool) map[string]any {
	path = strings.TrimSpace(path)
	out := map[string]any{
		"path":       path,
		"configured": path != "",
	}
	if path == "" {
		out["present"] = false
		out["writable"] = false
		out["status"] = "not-configured"
		return out
	}
	info, err := os.Stat(path)
	if err != nil {
		out["present"] = false
		out["writable"] = false
		out["status"] = "missing"
		out["error"] = err.Error()
		return out
	}
	out["present"] = true
	out["is_dir"] = info.IsDir()
	if !info.IsDir() {
		out["writable"] = false
		out["status"] = "not-directory"
		return out
	}
	testPath := filepath.Join(path, fmt.Sprintf(".constellation-cache-health-%d", os.Getpid()))
	if err := os.WriteFile(testPath, []byte("ok"), 0o600); err != nil {
		out["writable"] = false
		out["status"] = "read-only"
		out["error"] = err.Error()
	} else {
		_ = os.Remove(testPath)
		out["writable"] = true
		out["status"] = "ready"
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err == nil {
		out["free_bytes"] = int64(stat.Bavail) * int64(stat.Bsize)
	}
	if includeUsage {
		addScannerCacheUsage(out, path)
	}
	return out
}

func addScannerCacheUsage(out map[string]any, root string) {
	var (
		visited     int
		recordCount int64
		totalBytes  int64
		truncated   bool
		records     []map[string]any
	)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == root {
			return nil
		}
		visited++
		if visited > scannerCacheWalkLimit {
			truncated = true
			return errScannerCacheWalkLimit
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		recordCount++
		size := info.Size()
		totalBytes += size
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = entry.Name()
		}
		records = append(records, map[string]any{
			"layer":     filepath.ToSlash(rel),
			"size":      size,
			"ref_count": 1,
			"ref_last":  info.ModTime().UTC().Format(time.RFC3339),
		})
		sort.Slice(records, func(i, j int) bool {
			left, _ := records[i]["size"].(int64)
			right, _ := records[j]["size"].(int64)
			return left > right
		})
		if len(records) > scannerCacheRecordLimit {
			records = records[:scannerCacheRecordLimit]
		}
		return nil
	})
	if err != nil && !errors.Is(err, errScannerCacheWalkLimit) {
		out["usage_error"] = err.Error()
	}
	out["record_count"] = recordCount
	out["record_size_bytes"] = totalBytes
	out["records_truncated"] = truncated || recordCount > int64(len(records))
	out["records"] = records
}

func writeScannerJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func retryableScanFailure(errMsg string) bool {
	errMsg = strings.ToLower(strings.TrimSpace(errMsg))
	if errMsg == "" {
		return false
	}
	terminalPrefixes := []string{
		"unsupported_target_type:",
		"missing_target_ref",
		"missing_package_evidence",
		"stale_package_evidence",
	}
	for _, prefix := range terminalPrefixes {
		if strings.HasPrefix(errMsg, prefix) {
			return false
		}
	}
	return true
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return def
	case "1", "true", "t", "yes", "y", "on", "enabled":
		return true
	case "0", "false", "f", "no", "n", "off", "disabled":
		return false
	default:
		return def
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
