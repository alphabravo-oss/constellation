// constellation-compliance-scheduler is the cron-driven daemon that fires
// scheduled compliance evidence runs (migration 039) and delivers the
// cosign-signed PDF (or JSON / CSV / SARIF) artifact to the operator-configured
// targets — email, S3, webhook, or a local file:// drop.
//
// Lifecycle (every 30s):
//
//  1. SELECT * FROM compliance_schedules
//     WHERE enabled AND (next_run_at <= NOW() OR next_run_at IS NULL);
//  2. For each due schedule, atomically insert a compliance_runs row with
//     status=running and update next_run_at = cron.Next(now), so a parallel
//     scheduler can't double-fire (the row update is the lock).
//  3. Render the compliance report for the target (org + cluster + framework)
//     using pkg/report, signing the rendered bytes with cosign 2.x.
//  4. Push the artifact + signature to every delivery target. Failures are
//     logged but do not fail the run — the artifact is still on disk.
//  5. UPDATE compliance_runs SET status='succeeded'|'failed', artifact_uri,
//     artifact_signature, completed_at, summary.
//
// Env:
//
//	DATABASE_URL                Postgres DSN (required)
//	POLL_INTERVAL               default 30s
//	REPORT_OUT_DIR              local fallback dir for rendered artifacts; default /tmp/compliance-out
//	COSIGN_BIN                  path to cosign binary; default `cosign` from PATH
//	COSIGN_KEY                  path to a cosign key file; if empty we generate an
//	                            ephemeral key in REPORT_OUT_DIR/.cosign and re-use it
//	COSIGN_PASSWORD             passphrase for the cosign key (default empty)
//	SMTP_HOST/SMTP_USER/SMTP_PASS/SMTP_FROM   SMTP for email delivery (optional)
//	AWS_REGION + standard AWS creds           S3 delivery (optional)
//
// The daemon is safe to run as a single replica; in HA you'd add a
// SELECT ... FOR UPDATE SKIP LOCKED to allow multiple replicas to share work
// (left as a future enhancement — single replica is enough for v1).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	evidence "github.com/alphabravocompany/constellation/internal/complianceevidence"
	compliancehandler "github.com/alphabravocompany/constellation/internal/handler/compliance"
	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/pkg/compliance"
	"github.com/alphabravocompany/constellation/pkg/report"
	"github.com/alphabravocompany/constellation/pkg/version"
)

func main() {
	var (
		pollInterval = flag.Duration("interval", env("POLL_INTERVAL", 30*time.Second), "How often to scan for due schedules")
		outDir       = flag.String("out-dir", envStr("REPORT_OUT_DIR", "/tmp/compliance-out"), "Local dir for rendered artifacts")
		oneShot      = flag.Bool("one-shot", false, "Process the queue once and exit (used by tests)")
	)
	flag.Parse()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", *outDir, err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).With("svc", "constellation-compliance-scheduler")
	version.LogStartup(logger, "compliance-scheduler")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		logger.Error("pgxpool", "err", err.Error())
		os.Exit(1)
	}
	defer pool.Close()

	signer, err := ensureCosignKey(*outDir, logger)
	if err != nil {
		logger.Warn("cosign key bootstrap failed; signatures will be empty", "err", err.Error())
	}

	d := &daemon{pool: pool, logger: logger, outDir: *outDir, signer: signer, http: &http.Client{Timeout: 30 * time.Second}}
	hbCfg := version.HeartbeatConfigFromEnv("compliance-scheduler", version.HeartbeatEnvOptions{
		TokenEnv:     []string{"CONSTELLATION_COMPLIANCE_SCHEDULER_TOKEN", "SCANNER_TOKEN", "RUNTIME_AGENT_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_COMPLIANCE_SCHEDULER_TOKEN_FILE", "SCANNER_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE"},
		Logger:       logger,
		MetadataFn: func() any {
			return map[string]any{
				"interval_seconds": pollInterval.Seconds(),
				"out_dir":          *outDir,
				"one_shot":         *oneShot,
				"signing_enabled":  signer != nil,
			}
		},
	})

	if *oneShot {
		d.tick(ctx)
		if version.HeartbeatConfigured(hbCfg) {
			if err := version.SendOnceExternal(ctx, hbCfg); err != nil {
				logger.Warn("heartbeat failed", "err", err.Error())
			}
		}
		return
	}

	go version.HeartbeatLoop(ctx, hbCfg)

	logger.Info("scheduler started", "interval", pollInterval.String(), "out_dir", *outDir)
	ticker := time.NewTicker(*pollInterval)
	defer ticker.Stop()
	d.tick(ctx) // run once at boot
	for {
		select {
		case <-ctx.Done():
			logger.Info("scheduler stopping")
			return
		case <-ticker.C:
			d.tick(ctx)
		}
	}
}

type daemon struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	outDir string
	signer *cosignSigner
	http   *http.Client
}

// dueSchedule is the minimal projection scanned out of compliance_schedules. It
// mirrors the handler row but stays internal to the worker.
type dueSchedule struct {
	ID             uuid.UUID
	OrgID          uuid.UUID
	ClusterID      *uuid.UUID
	Name           string
	Framework      string
	CronExpression string
	Timezone       string
	Delivery       []compliancehandler.DeliveryTarget
	ReportFormat   string
	ReportTemplate string
}

// tick processes one batch of due schedules. Errors per-schedule are logged and
// the next schedule continues — a single bad row should not stall the queue.
func (d *daemon) tick(ctx context.Context) {
	rows, err := d.pool.Query(ctx, `
SELECT id, org_id, cluster_id, name, framework, cron_expression, timezone,
       COALESCE(delivery,'[]'::jsonb), report_format, report_template
  FROM compliance_schedules
 WHERE enabled
   AND (next_run_at <= NOW() OR next_run_at IS NULL)
 ORDER BY COALESCE(next_run_at, '1970-01-01'::timestamptz)
 LIMIT 16`)
	if err != nil {
		d.logger.Error("tick: query", "err", err.Error())
		return
	}
	defer rows.Close()

	due := []dueSchedule{}
	for rows.Next() {
		var s dueSchedule
		var clusterID *uuid.UUID
		var deliveryRaw []byte
		if err := rows.Scan(&s.ID, &s.OrgID, &clusterID, &s.Name, &s.Framework, &s.CronExpression,
			&s.Timezone, &deliveryRaw, &s.ReportFormat, &s.ReportTemplate); err != nil {
			d.logger.Error("tick: scan", "err", err.Error())
			continue
		}
		s.ClusterID = clusterID
		_ = json.Unmarshal(deliveryRaw, &s.Delivery)
		due = append(due, s)
	}
	rows.Close()

	for _, s := range due {
		// Compute the next cron tick and claim the schedule by advancing next_run_at.
		// If the UPDATE finds 0 rows (another worker won the race) we skip the schedule.
		next, err := compliancehandler.NextRunFromCron(s.CronExpression, s.Timezone, time.Now())
		if err != nil {
			d.logger.Error("cron parse", "schedule", s.Name, "err", err.Error())
			continue
		}
		ct, err := d.pool.Exec(ctx, `
UPDATE compliance_schedules
   SET next_run_at = $1, updated_at = NOW()
 WHERE id = $2 AND enabled
   AND (next_run_at <= NOW() OR next_run_at IS NULL)`, next, s.ID)
		if err != nil {
			d.logger.Error("claim: update", "err", err.Error())
			continue
		}
		if ct.RowsAffected() == 0 {
			continue // someone else claimed it
		}

		if err := d.run(ctx, s); err != nil {
			d.logger.Error("run failed", "schedule", s.Name, "err", err.Error())
		}
	}
}

// run executes one schedule end-to-end: insert run row, render+sign, deliver, finalize.
func (d *daemon) run(ctx context.Context, s dueSchedule) error {
	d.logger.Info("run start", "schedule", s.Name, "framework", s.Framework, "format", s.ReportFormat)

	var runID uuid.UUID
	if err := d.pool.QueryRow(ctx, `
INSERT INTO compliance_runs (org_id, cluster_id, schedule_id, framework, status, triggered_by)
VALUES ($1,$2,$3,$4,'running','schedule')
RETURNING id`, s.OrgID, s.ClusterID, s.ID, s.Framework).Scan(&runID); err != nil {
		return fmt.Errorf("insert run row: %w", err)
	}

	finalize := func(status, artifactURI, sig string, size int64, summary map[string]int, runErr error) {
		errMsg := ""
		if runErr != nil {
			errMsg = runErr.Error()
		}
		summaryRaw, _ := json.Marshal(summary)
		_, _ = d.pool.Exec(ctx, `
UPDATE compliance_runs
   SET completed_at = NOW(), status = $1, summary = $2::jsonb,
       artifact_uri = NULLIF($3,''), artifact_signature = NULLIF($4,''),
       artifact_size_bytes = $5, error_message = NULLIF($6,'')
 WHERE id = $7`, status, summaryRaw, artifactURI, sig, size, errMsg, runID)
		// Mirror onto the schedule's last_* columns.
		_, _ = d.pool.Exec(ctx, `
UPDATE compliance_schedules
   SET last_run_at = NOW(), last_status = $1, last_artifact_uri = NULLIF($2,''),
       last_error = NULLIF($3,''), updated_at = NOW()
 WHERE id = $4`, status, artifactURI, errMsg, s.ID)
		d.logger.Info("run finished", "schedule", s.Name, "status", status, "artifact", artifactURI, "signature_bytes", len(sig))
	}

	checks, summary, err := d.loadChecks(ctx, s)
	if err != nil {
		finalize("failed", "", "", 0, summary, err)
		return err
	}

	orgName, clusterName := d.resolveNames(ctx, s.OrgID, s.ClusterID)
	frameworkName := s.Framework
	for _, fw := range compliance.AllFrameworks() {
		if fw.ID == s.Framework {
			frameworkName = fw.Name
			break
		}
	}

	artifact, ext, err := renderArtifact(s.ReportFormat, report.ComplianceData{
		OrgName:       orgName,
		GeneratedAt:   time.Now().UTC(),
		Framework:     s.Framework,
		FrameworkName: fmt.Sprintf("%s (cluster: %s)", frameworkName, clusterName),
		Summary: report.FrameworkSummary{
			Total: summary["total"], Pass: summary["pass"], Fail: summary["fail"], Manual: summary["manual"],
		},
		Checks: checks,
	})
	if err != nil {
		finalize("failed", "", "", 0, summary, err)
		return err
	}

	stamp := time.Now().UTC().Format("20060102T150405Z")
	filename := fmt.Sprintf("%s-%s-%s.%s", safeName(s.Name), s.Framework, stamp, ext)
	localPath := filepath.Join(d.outDir, filename)
	if err := os.WriteFile(localPath, artifact, 0o644); err != nil {
		finalize("failed", "", "", 0, summary, err)
		return err
	}
	size := int64(len(artifact))

	// Sign the artifact bytes (best-effort).
	sig := ""
	if d.signer != nil {
		raw, err := d.signer.Sign(ctx, localPath)
		if err != nil {
			d.logger.Warn("cosign sign", "err", err.Error())
		} else {
			sig = raw
			// Persist the signature next to the artifact so cosign verify-blob works.
			_ = os.WriteFile(localPath+".sig", []byte(sig), 0o644)
		}
	} else {
		// Fallback: sha256 the artifact so the UI can show *something* in
		// X-Constellation-Cosign-Signature when cosign isn't installed.
		h := sha256.Sum256(artifact)
		sig = "sha256:" + hex.EncodeToString(h[:])
	}

	// Deliver to each target. Email/webhook/file/S3. Errors don't fail the run.
	primaryURI := "file://" + localPath
	for _, t := range s.Delivery {
		if err := d.deliver(ctx, t, s, localPath, artifact, sig, ext); err != nil {
			d.logger.Warn("delivery failed", "kind", t.Kind, "err", err.Error())
			continue
		}
		// Prefer the externally-addressable URI when available.
		switch t.Kind {
		case "s3":
			primaryURI = fmt.Sprintf("s3://%s/%s/%s", t.Bucket, strings.TrimSuffix(t.Prefix, "/"), filename)
		case "file":
			if t.Target != "" {
				primaryURI = strings.TrimRight(t.Target, "/") + "/" + filename
			}
		}
	}

	finalize("succeeded", primaryURI, sig, size, summary, nil)
	return nil
}

// loadChecks pulls the first-class compliance evidence rows for the
// (org, cluster, framework) tuple and aggregates effective summary counters.
// The collector includes persisted Kubernetes rows plus host, workload, and
// cloud evidence synthesized from the latest inventory/posture tables.
func (d *daemon) loadChecks(ctx context.Context, s dueSchedule) ([]report.ComplianceCheck, map[string]int, error) {
	summary := map[string]int{"pass": 0, "fail": 0, "manual": 0, "total": 0}
	result, err := evidence.Collector{Pool: d.pool}.Collect(ctx, evidence.Query{
		OrgID:     s.OrgID,
		ClusterID: s.ClusterID,
		Framework: s.Framework,
		Limit:     5000,
	})
	if err != nil {
		return nil, summary, fmt.Errorf("load evidence checks: %w", err)
	}
	out := make([]report.ComplianceCheck, 0, len(result.Items))
	for _, item := range result.Items {
		status := item.EffectiveStatus
		if status == "" {
			status = item.Status
		}
		out = append(out, report.ComplianceCheck{
			ControlID: item.ControlID,
			Title:     fmt.Sprintf("%s [%s: %s]", item.Title, item.Scope, item.Target),
			Status:    status,
			Severity:  item.Severity,
			Evidence:  item.ReportEvidence(),
		})
		summary["total"]++
		switch strings.ToLower(status) {
		case "pass", "exempted":
			summary["pass"]++
		case "fail":
			summary["fail"]++
		case "manual":
			summary["manual"]++
		}
	}
	return out, summary, nil
}

func (d *daemon) resolveNames(ctx context.Context, orgID uuid.UUID, clusterID *uuid.UUID) (string, string) {
	orgName := "unknown-org"
	_ = d.pool.QueryRow(ctx, `SELECT name FROM orgs WHERE id=$1`, orgID).Scan(&orgName)
	clusterName := "all-clusters"
	if clusterID != nil {
		_ = d.pool.QueryRow(ctx, `SELECT name FROM clusters WHERE id=$1`, *clusterID).Scan(&clusterName)
	}
	return orgName, clusterName
}

// renderArtifact picks the right pkg/report path for the configured format. For
// pdf it tries wkhtmltopdf; if that's missing it returns the rendered HTML so
// the artifact is at least viewable in a browser. ext is the file extension to
// stamp into the local filename (and the X-Content-Type hint).
func renderArtifact(format string, data report.ComplianceData) ([]byte, string, error) {
	switch strings.ToLower(format) {
	case "", "pdf":
		html, err := report.ComplianceHTML(data)
		if err != nil {
			return nil, "", err
		}
		pdf, err := report.HTMLToPDF(html)
		if err == nil {
			return pdf, "pdf", nil
		}
		if errors.Is(err, report.ErrPDFToolMissing) {
			return html, "html", nil
		}
		return nil, "", err
	case "html":
		html, err := report.ComplianceHTML(data)
		return html, "html", err
	case "json":
		raw, err := json.MarshalIndent(map[string]any{
			"org": data.OrgName, "framework": data.Framework, "summary": data.Summary,
			"checks": data.Checks, "generated_at": data.GeneratedAt,
		}, "", "  ")
		return raw, "json", err
	case "csv":
		var buf bytes.Buffer
		buf.WriteString("control_id,title,status,severity,evidence\n")
		for _, c := range data.Checks {
			buf.WriteString(fmt.Sprintf("%q,%q,%q,%q,%q\n", c.ControlID, c.Title, c.Status, c.Severity, c.Evidence))
		}
		return buf.Bytes(), "csv", nil
	case "sarif":
		// Minimal SARIF 2.1 envelope so consumers like GitHub code-scanning can
		// ingest the artifact directly. We map each fail/manual to a result.
		results := []map[string]any{}
		for _, c := range data.Checks {
			switch strings.ToLower(c.Status) {
			case "pass", "exempted", "not_applicable":
				continue
			}
			results = append(results, map[string]any{
				"ruleId":  c.ControlID,
				"message": map[string]string{"text": c.Title},
				"level":   sarifLevel(c.Severity),
				"properties": map[string]string{
					"status": c.Status, "evidence": c.Evidence,
				},
			})
		}
		envelope := map[string]any{
			"version": "2.1.0",
			"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
			"runs": []map[string]any{{
				"tool":    map[string]any{"driver": map[string]any{"name": "constellation-compliance", "rules": []any{}}},
				"results": results,
			}},
		}
		raw, err := json.MarshalIndent(envelope, "", "  ")
		return raw, "sarif", err
	default:
		return nil, "", fmt.Errorf("unsupported report format %q", format)
	}
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// deliver dispatches the rendered artifact to one target.
func (d *daemon) deliver(ctx context.Context, t compliancehandler.DeliveryTarget, s dueSchedule, localPath string, body []byte, sig, ext string) error {
	switch t.Kind {
	case "file":
		if t.Target == "" {
			return errors.New("file delivery: target required")
		}
		dir := strings.TrimPrefix(t.Target, "file://")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		dest := filepath.Join(dir, filepath.Base(localPath))
		if err := os.WriteFile(dest, body, 0o644); err != nil {
			return err
		}
		if sig != "" {
			_ = os.WriteFile(dest+".sig", []byte(sig), 0o644)
		}
		d.logger.Info("delivered: file", "path", dest)
		return nil
	case "email":
		return d.deliverEmail(t, s, body, sig, filepath.Base(localPath))
	case "s3":
		return d.deliverS3(ctx, t, body, sig, filepath.Base(localPath))
	case "webhook":
		return d.deliverWebhook(ctx, t, s, sig, filepath.Base(localPath))
	default:
		return fmt.Errorf("unknown delivery kind %q", t.Kind)
	}
}

func (d *daemon) deliverEmail(t compliancehandler.DeliveryTarget, s dueSchedule, body []byte, sig, filename string) error {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		d.logger.Warn("email delivery skipped: SMTP_HOST not set")
		return nil
	}
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")
	if from == "" {
		from = user
	}
	if t.Target == "" {
		return errors.New("email delivery: target email required")
	}
	// RFC 822 message with a base64-encoded attachment + cosign signature header.
	boundary := "constellation-boundary-" + uuid.NewString()
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", t.Target)
	fmt.Fprintf(&buf, "Subject: Compliance report — %s (%s)\r\n", s.Name, s.Framework)
	fmt.Fprintf(&buf, "X-Constellation-Cosign-Signature: %s\r\n", sig)
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	fmt.Fprintf(&buf, "Content-Type: text/plain; charset=utf-8\r\n\r\n")
	fmt.Fprintf(&buf, "Attached: %s\nFramework: %s\nGenerated by Constellation.\n\r\n", filename, s.Framework)
	fmt.Fprintf(&buf, "--%s\r\n", boundary)
	fmt.Fprintf(&buf, "Content-Type: application/octet-stream; name=%q\r\n", filename)
	fmt.Fprintf(&buf, "Content-Transfer-Encoding: base64\r\n")
	fmt.Fprintf(&buf, "Content-Disposition: attachment; filename=%q\r\n\r\n", filename)
	buf.WriteString(base64.StdEncoding.EncodeToString(body))
	fmt.Fprintf(&buf, "\r\n--%s--\r\n", boundary)

	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":587"
	}
	auth := smtp.PlainAuth("", user, pass, strings.Split(host, ":")[0])
	if user == "" {
		auth = nil
	}
	if err := smtp.SendMail(addr, auth, from, []string{t.Target}, buf.Bytes()); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	d.logger.Info("delivered: email", "to", t.Target)
	return nil
}

func (d *daemon) deliverS3(ctx context.Context, t compliancehandler.DeliveryTarget, body []byte, sig, filename string) error {
	if t.Bucket == "" {
		return errors.New("s3 delivery: bucket required")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}
	var client *s3.Client
	if t.Endpoint != "" {
		client = s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.BaseEndpoint = awssdk.String(t.Endpoint)
			o.UsePathStyle = true
		})
	} else {
		client = s3.NewFromConfig(cfg)
	}
	key := strings.TrimSuffix(t.Prefix, "/") + "/" + filename
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      awssdk.String(t.Bucket),
		Key:         awssdk.String(key),
		Body:        bytes.NewReader(body),
		ContentType: awssdk.String("application/octet-stream"),
		Metadata:    map[string]string{"cosign-signature": sig},
	}); err != nil {
		return fmt.Errorf("s3 put: %w", err)
	}
	if sig != "" {
		_, _ = client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: awssdk.String(t.Bucket),
			Key:    awssdk.String(key + ".sig"),
			Body:   strings.NewReader(sig),
		})
	}
	d.logger.Info("delivered: s3", "bucket", t.Bucket, "key", key)
	return nil
}

func (d *daemon) deliverWebhook(ctx context.Context, t compliancehandler.DeliveryTarget, s dueSchedule, sig, filename string) error {
	url := t.URL
	if url == "" {
		return errors.New("webhook delivery: url required")
	}
	payload, _ := json.Marshal(map[string]any{
		"kind":         "compliance.report",
		"schedule_id":  s.ID,
		"name":         s.Name,
		"framework":    s.Framework,
		"format":       s.ReportFormat,
		"filename":     filename,
		"signature":    sig,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Constellation-Cosign-Signature", sig)
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook %s: %d %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	d.logger.Info("delivered: webhook", "url", url, "status", resp.StatusCode)
	return nil
}

// ---------------------- cosign helpers ----------------------

type cosignSigner struct {
	bin      string
	keyPath  string
	password string
}

// ensureCosignKey returns a signer using $COSIGN_KEY when set; otherwise it
// generates an ephemeral key under outDir/.cosign and reuses it across runs.
func ensureCosignKey(outDir string, logger *slog.Logger) (*cosignSigner, error) {
	bin := os.Getenv("COSIGN_BIN")
	if bin == "" {
		bin = "cosign"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("cosign binary not found in PATH (set COSIGN_BIN)")
	}
	key := os.Getenv("COSIGN_KEY")
	pw := os.Getenv("COSIGN_PASSWORD")
	if key != "" {
		return &cosignSigner{bin: bin, keyPath: key, password: pw}, nil
	}
	// Generate an ephemeral key if absent.
	keyDir := filepath.Join(outDir, ".cosign")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(keyDir, "cosign.key")
	pubPath := filepath.Join(keyDir, "cosign.pub")
	if _, err := os.Stat(keyPath); err == nil {
		return &cosignSigner{bin: bin, keyPath: keyPath, password: pw}, nil
	}
	cmd := exec.Command(bin, "generate-key-pair", "--output-key-prefix", filepath.Join(keyDir, "cosign"))
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+pw)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cosign generate-key-pair: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	logger.Info("generated cosign key", "key", keyPath, "pub", pubPath)
	return &cosignSigner{bin: bin, keyPath: keyPath, password: pw}, nil
}

// Sign produces a base64 cosign signature over the artifact at path. Returns the
// signature only (matches `cosign sign-blob --yes <path>` output).
func (s *cosignSigner) Sign(ctx context.Context, path string) (string, error) {
	cmd := exec.CommandContext(ctx, s.bin, "sign-blob", "--yes", "--key", s.keyPath, path)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+s.password)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cosign sign-blob: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ---------------------- helpers ----------------------

func env(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func safeName(in string) string {
	// Replace anything outside [A-Za-z0-9._-] with `_`. Used to build filenames.
	var b strings.Builder
	for _, r := range in {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// Belt-and-suspenders: keep pgx import used (avoids removal by goimports if all
// callsites are factored away in a refactor).
var _ = pgx.ErrNoRows
