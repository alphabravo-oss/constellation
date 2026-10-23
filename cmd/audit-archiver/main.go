// audit-archiver publishes signed audit chain segments and verifies downloaded
// archives without database access. See docs/audit-archive.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auditarchive"
	"github.com/alphabravocompany/constellation/internal/telemetry"
	"github.com/alphabravocompany/constellation/pkg/backup"
	"github.com/alphabravocompany/constellation/pkg/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var c auditarchive.Config
	flag.StringVar(&c.Bucket, "bucket", env("AUDIT_BUCKET", ""), "S3 bucket")
	flag.StringVar(&c.Prefix, "prefix", env("AUDIT_PREFIX", "audit"), "Object key prefix")
	flag.StringVar(&c.Endpoint, "endpoint", env("AWS_ENDPOINT_URL_S3", env("AWS_ENDPOINT_URL", "")), "S3-compatible endpoint (also scopes archive progress)")
	flag.IntVar(&c.BatchSize, "batch-size", 1000, "Maximum rows per run (1-10000)")
	flag.BoolVar(&c.DryRun, "dry-run", false, "Write local artifacts without changing durable progress")
	flag.StringVar(&c.OutDir, "out-dir", env("AUDIT_OUT_DIR", filepath.Join(os.TempDir(), "constellation-audit")), "Local dry-run output directory")
	mode := flag.String("sign-mode", env("AUDIT_SIGN_MODE", "none"), "static-key or keyless; none permitted only for dry-run")
	flag.StringVar(&c.Signer.KeyPath, "sign-key", env("AUDIT_SIGN_KEY", ""), "Ed25519 private key path")
	flag.StringVar(&c.Verifier.KeyPath, "verify-key", env("AUDIT_VERIFY_KEY", ""), "Trusted Ed25519 public key path")
	flag.StringVar(&c.Verifier.Identity, "verify-identity", env("AUDIT_VERIFY_IDENTITY", ""), "Expected keyless certificate identity")
	flag.StringVar(&c.Signer.CosignBin, "cosign-bin", env("COSIGN_BIN", "cosign"), "cosign executable")
	manifestPath := flag.String("verify-manifest", "", "Verify downloaded manifest without connecting to a database")
	archivePath := flag.String("verify-archive", "", "Downloaded .jsonl.gz path")
	signaturePath := flag.String("signature", "", "Downloaded signature path")
	certificatePath := flag.String("certificate", "", "Downloaded certificate path for keyless signing")
	timeout := flag.Duration("timeout", 15*time.Minute, "Maximum run time, including object upload/read-back")
	flag.Parse()
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c.Signer.Mode = backup.SignMode(*mode)
	c.Verifier.Mode = c.Signer.Mode
	c.Verifier.CosignBin = c.Signer.CosignBin
	if *manifestPath != "" {
		raw, err := readMetadata(*manifestPath)
		if err != nil {
			return err
		}
		sig, err := readMetadata(*signaturePath)
		if err != nil {
			return err
		}
		var cert []byte
		if *certificatePath != "" {
			cert, err = readMetadata(*certificatePath)
			if err != nil {
				return err
			}
		}
		m, err := auditarchive.Verify(ctx, *archivePath, raw, sig, cert, c.Verifier)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(m)
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if err := backup.ValidateS3Endpoint(c.Endpoint); err != nil {
		return err
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL required")
	}
	tel, err := telemetry.Init(ctx, telemetry.ConfigFromEnv("audit-archiver"))
	if err != nil {
		return err
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(shutdown)
	}()
	version.LogStartup(tel.Logger, "audit-archiver")
	state := &auditArchiveHeartbeatState{Bucket: c.Bucket, Prefix: c.Prefix, DryRun: c.DryRun, SignMode: *mode, Stage: "starting"}
	hb := version.HeartbeatConfigFromEnv("audit-archiver", version.HeartbeatEnvOptions{
		TokenEnv:     []string{"CONSTELLATION_AUDIT_ARCHIVER_TOKEN", "RUNTIME_AGENT_TOKEN", "SCANNER_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_AUDIT_ARCHIVER_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE", "SCANNER_TOKEN_FILE"},
		Logger:       tel.Logger, LastErrorFn: state.lastError, MetadataFn: state.snapshot})
	defer func() {
		if version.HeartbeatConfigured(hb) {
			hctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := version.SendOnceExternal(hctx, hb); err != nil {
				tel.Logger.Warn("heartbeat failed", slog.String("err", err.Error()))
			}
		}
	}()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		state.Stage = "db connect"
		state.LastErrorText = err.Error()
		return err
	}
	defer pool.Close()
	var objects auditarchive.ObjectStore
	if !c.DryRun {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			state.Stage = "aws config"
			state.LastErrorText = err.Error()
			return err
		}
		objects = s3.NewFromConfig(cfg, func(o *s3.Options) {
			if c.Endpoint != "" {
				o.BaseEndpoint = aws.String(c.Endpoint)
			}
		})
	}
	m, err := auditarchive.Run(ctx, pool, objects, c)
	if err != nil {
		state.Stage = "archive failed"
		state.LastErrorText = err.Error()
		return err
	}
	state.Success = true
	state.Stage = "verified"
	if c.DryRun {
		state.Stage = "dry-run"
	}
	state.RecordCount = m.RecordCount
	state.ArchiveKey = m.ArchiveKey
	state.ManifestKey = m.ManifestKey
	tel.Logger.Info("archive completed", slog.String("stage", state.Stage), slog.Int64("count", m.RecordCount), slog.Int64("last_id", m.LastID))
	return json.NewEncoder(os.Stdout).Encode(m)
}
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
