// audit-archiver is a cron-style job that freezes a rolling window of audit rows to S3 and
// produces a signed manifest.
//
// Schedule: run from a Kubernetes CronJob (deploy/charts/constellation/templates/audit-archiver-cronjob.yaml).
//
// Window:        configurable via FREEZE_WINDOW env var (default 24h)
// Output:        s3://<bucket>/<prefix>/<window-start>--<window-end>.jsonl.gz
// Manifest:      adjacent .manifest.json with sha256 + chain head/tail + count
// Signature:     adjacent .manifest.json.sig and optional .manifest.json.cert
package main

import (
	"bytes"
	"compress/gzip"
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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
	"github.com/alphabravocompany/constellation/pkg/observability"
	"github.com/alphabravocompany/constellation/pkg/version"
)

const archiveManifestVersion = 1

type archiveKeys struct {
	Archive   string
	Manifest  string
	Signature string
	Cert      string
}

type archiveManifest struct {
	FormatVersion  int               `json:"format_version"`
	WindowStart    string            `json:"window_start"`
	WindowEnd      string            `json:"window_end"`
	RecordCount    int64             `json:"record_count"`
	ArchiveSHA256  string            `json:"archive_sha256"`
	JSONLSHA256    string            `json:"jsonl_sha256"`
	SHA256         string            `json:"sha256"`
	FirstChain     string            `json:"first_chain"`
	LastChain      string            `json:"last_chain"`
	ArchiveKey     string            `json:"archive_key"`
	ManifestKey    string            `json:"manifest_key"`
	SignatureKey   string            `json:"signature_key,omitempty"`
	CertificateKey string            `json:"certificate_key,omitempty"`
	SignMode       backup.SignMode   `json:"sign_mode"`
	SignerIdentity string            `json:"signer_identity,omitempty"`
	CreatedAt      string            `json:"created_at"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type auditArchiveHeartbeatState struct {
	Bucket        string
	Prefix        string
	Window        time.Duration
	DryRun        bool
	SignMode      string
	Stage         string
	RecordCount   int64
	ArchiveKey    string
	ManifestKey   string
	Success       bool
	LastErrorText string
}

func (s *auditArchiveHeartbeatState) snapshot() any {
	return map[string]any{
		"bucket_configured": strings.TrimSpace(s.Bucket) != "",
		"prefix":            s.Prefix,
		"window_seconds":    s.Window.Seconds(),
		"dry_run":           s.DryRun,
		"sign_mode":         s.SignMode,
		"stage":             s.Stage,
		"record_count":      s.RecordCount,
		"archive_key":       s.ArchiveKey,
		"manifest_key":      s.ManifestKey,
		"success":           s.Success,
	}
}

func (s *auditArchiveHeartbeatState) lastError() string {
	return s.LastErrorText
}

func main() {
	bucket := flag.String("bucket", env("AUDIT_BUCKET", ""), "S3 bucket (or s3-compatible) for archive")
	prefix := flag.String("prefix", env("AUDIT_PREFIX", "audit"), "Object key prefix")
	window := flag.Duration("window", envDuration("FREEZE_WINDOW", 24*time.Hour), "Window size to freeze")
	dryRun := flag.Bool("dry-run", false, "Write to local files instead of S3")
	outDir := flag.String("out-dir", env("AUDIT_OUT_DIR", os.TempDir()), "Local output directory for --dry-run")
	signMode := flag.String("sign-mode", env("AUDIT_SIGN_MODE", string(backup.SignModeNone)), "Manifest signing mode: none, static-key, keyless")
	signKey := flag.String("sign-key", env("AUDIT_SIGN_KEY", ""), "PEM ed25519 private key path for --sign-mode=static-key")
	cosignBin := flag.String("cosign-bin", env("COSIGN_BIN", "cosign"), "cosign binary path for --sign-mode=keyless")
	flag.Parse()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL required")
		os.Exit(2)
	}
	if *bucket == "" && !*dryRun {
		fmt.Fprintln(os.Stderr, "--bucket required unless --dry-run")
		os.Exit(2)
	}

	ctx := context.Background()

	tel, err := observability.Init(ctx, "audit-archiver")
	if err != nil {
		fmt.Fprintln(os.Stderr, "observability init:", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = tel.Shutdown(shutdownCtx)
	}()
	logger := tel.Logger
	version.LogStartup(logger, "audit-archiver")
	hbState := &auditArchiveHeartbeatState{
		Bucket:   *bucket,
		Prefix:   *prefix,
		Window:   *window,
		DryRun:   *dryRun,
		SignMode: *signMode,
		Stage:    "starting",
	}
	hbCfg := version.HeartbeatConfigFromEnv("audit-archiver", version.HeartbeatEnvOptions{
		TokenEnv:     []string{"CONSTELLATION_AUDIT_ARCHIVER_TOKEN", "RUNTIME_AGENT_TOKEN", "SCANNER_TOKEN"},
		TokenFileEnv: []string{"CONSTELLATION_AUDIT_ARCHIVER_TOKEN_FILE", "RUNTIME_AGENT_TOKEN_FILE", "SCANNER_TOKEN_FILE"},
		Logger:       logger,
		LastErrorFn:  hbState.lastError,
		MetadataFn:   hbState.snapshot,
	})
	sendHeartbeat := func(success bool, stage string, err error) {
		hbState.Success = success
		hbState.Stage = stage
		hbState.LastErrorText = ""
		if err != nil {
			hbState.LastErrorText = err.Error()
		}
		if version.HeartbeatConfigured(hbCfg) {
			hctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := version.SendOnceExternal(hctx, hbCfg); err != nil {
				logger.Warn("heartbeat failed", slog.String("err", err.Error()))
			}
		}
	}
	fatal := func(code int, stage string, err error, attrs ...any) {
		args := append([]any{}, attrs...)
		if err != nil {
			args = append(args, slog.String("err", err.Error()))
		}
		logger.Error(stage, args...)
		sendHeartbeat(false, stage, err)
		os.Exit(code)
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		fatal(1, "db connect", err)
	}
	defer pool.Close()

	// First, verify the chain to catch tampering before we archive.
	if cb, err := audit.VerifyChain(ctx, pool); err != nil {
		fatal(1, "verify chain", err)
	} else if cb != nil {
		fatal(1, "chain broken; refusing to archive", errors.New(cb.Reason), slog.Int64("at_id", cb.ID))
	}

	end := time.Now().UTC()
	start := end.Add(-*window)
	rows, err := pool.Query(ctx, `
SELECT id, org_id, actor_id, actor_ip::text, action, target_kind, target_id, before, after,
       prev_hash, chain_hash, request_id, at
  FROM audit_events
 WHERE at >= $1 AND at < $2
 ORDER BY id ASC`, start, end)
	if err != nil {
		fatal(1, "query window", err)
	}
	defer rows.Close()

	keys := makeArchiveKeys(*prefix, start, end)

	// Write to a temp file (gzip), checksum, then upload or move locally.
	tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("audit-%s.jsonl.gz", start.Format("20060102T150405Z")))
	f, err := os.Create(tmpPath)
	if err != nil {
		fatal(1, "temp file", err)
	}
	defer os.Remove(tmpPath)
	gz := gzip.NewWriter(f)
	enc := json.NewEncoder(gz)

	jsonlHasher := sha256.New()
	var firstHash, lastHash string
	var count int64

	for rows.Next() {
		var row map[string]any = make(map[string]any)
		var id int64
		var orgID, actorID *string
		var actorIP, action, targetKind, targetID, prevHash, chainHash, requestID *string
		var before, after []byte
		var at time.Time
		if err := rows.Scan(&id, &orgID, &actorID, &actorIP, &action, &targetKind, &targetID,
			&before, &after, &prevHash, &chainHash, &requestID, &at); err != nil {
			fatal(1, "scan", err)
		}
		row["id"] = id
		row["org_id"] = orgID
		row["actor_id"] = actorID
		row["actor_ip"] = actorIP
		row["action"] = strDeref(action)
		row["target_kind"] = strDeref(targetKind)
		row["target_id"] = strDeref(targetID)
		row["before"] = json.RawMessage(before)
		row["after"] = json.RawMessage(after)
		row["prev_hash"] = strDeref(prevHash)
		row["chain_hash"] = strDeref(chainHash)
		row["request_id"] = strDeref(requestID)
		row["at"] = at

		// Stream into the gzip writer and the hash simultaneously.
		buf, err := json.Marshal(row)
		if err != nil {
			fatal(1, "marshal", err)
		}
		_, _ = jsonlHasher.Write(buf)
		_, _ = jsonlHasher.Write([]byte("\n"))
		if err := enc.Encode(row); err != nil {
			fatal(1, "encode", err)
		}
		if firstHash == "" {
			firstHash = strDeref(chainHash)
		}
		lastHash = strDeref(chainHash)
		count++
	}
	if err := rows.Err(); err != nil {
		fatal(1, "rows", err)
	}
	if err := gz.Close(); err != nil {
		fatal(1, "gzip close", err)
	}
	if err := f.Close(); err != nil {
		fatal(1, "file close", err)
	}

	archiveSHA, err := fileSHA256(tmpPath)
	if err != nil {
		fatal(1, "archive sha256", err)
	}

	manifest := archiveManifest{
		FormatVersion: archiveManifestVersion,
		WindowStart:   start.Format(time.RFC3339),
		WindowEnd:     end.Format(time.RFC3339),
		RecordCount:   count,
		ArchiveSHA256: archiveSHA,
		JSONLSHA256:   hex.EncodeToString(jsonlHasher.Sum(nil)),
		SHA256:        archiveSHA,
		FirstChain:    firstHash,
		LastChain:     lastHash,
		ArchiveKey:    keys.Archive,
		ManifestKey:   keys.Manifest,
		SignMode:      backup.SignMode(*signMode),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]string{
			"generator": "constellation-audit-archiver",
		},
	}
	if manifest.SignMode != backup.SignModeNone {
		manifest.SignatureKey = keys.Signature
	}
	if manifest.SignMode == backup.SignModeKeyless {
		manifest.CertificateKey = keys.Cert
	}

	manifestBytes, sigBytes, certBytes, err := signArchiveManifest(manifest, backup.SignerOptions{
		Mode:      backup.SignMode(*signMode),
		KeyPath:   *signKey,
		CosignBin: *cosignBin,
	})
	if err != nil {
		fatal(1, "sign manifest", err)
	}

	hbState.RecordCount = count
	hbState.ArchiveKey = keys.Archive
	hbState.ManifestKey = keys.Manifest
	if *dryRun {
		if err := writeLocalArtifacts(*outDir, keys, tmpPath, manifestBytes, sigBytes, certBytes); err != nil {
			fatal(1, "dry-run write", err)
		}
		logger.Info("dry-run", slog.String("dir", *outDir), slog.Int64("count", count))
		_, _ = io.Copy(os.Stdout, strings.NewReader(string(manifestBytes)))
		sendHeartbeat(true, "dry-run", nil)
		return
	}

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		fatal(1, "aws config", err)
	}
	client := s3.NewFromConfig(awsCfg)
	if err := uploadArchive(ctx, client, *bucket, keys, tmpPath, manifestBytes, sigBytes, certBytes, manifest); err != nil {
		fatal(1, "upload", err)
	}
	logger.Info("uploaded",
		slog.String("bucket", *bucket),
		slog.String("archive_key", keys.Archive),
		slog.String("manifest_key", keys.Manifest),
		slog.Int64("count", count),
	)
	sendHeartbeat(true, "uploaded", nil)
}

func strDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
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

func makeArchiveKeys(prefix string, start, end time.Time) archiveKeys {
	base := fmt.Sprintf("%s--%s", start.UTC().Format("20060102T150405Z"), end.UTC().Format("20060102T150405Z"))
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix != "" {
		base = prefix + "/" + base
	}
	archive := base + ".jsonl.gz"
	manifest := base + ".manifest.json"
	return archiveKeys{
		Archive:   archive,
		Manifest:  manifest,
		Signature: manifest + ".sig",
		Cert:      manifest + ".cert",
	}
}

func signArchiveManifest(manifest archiveManifest, opts backup.SignerOptions) ([]byte, []byte, []byte, error) {
	if opts.Mode == "" {
		opts.Mode = backup.SignModeNone
	}
	if opts.Mode == backup.SignModeNone {
		manifest.SignMode = backup.SignModeNone
		manifest.SignatureKey = ""
		manifest.CertificateKey = ""
		manifest.SignerIdentity = ""
		b, err := json.MarshalIndent(manifest, "", "  ")
		return b, nil, nil, err
	}

	manifest.SignMode = opts.Mode
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, nil, nil, err
	}
	sig, cert, identity, err := backup.Sign(manifestBytes, opts)
	if err != nil {
		return nil, nil, nil, err
	}
	if identity != "" {
		manifest.SignerIdentity = identity
		manifestBytes, err = json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return nil, nil, nil, err
		}
		sig, cert, _, err = backup.Sign(manifestBytes, opts)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return manifestBytes, sig, cert, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeLocalArtifacts(outDir string, keys archiveKeys, archivePath string, manifest, sig, cert []byte) error {
	if outDir == "" {
		outDir = os.TempDir()
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(outDir, filepath.Base(keys.Archive)), archivePath, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, filepath.Base(keys.Manifest)), manifest, 0o644); err != nil {
		return err
	}
	if len(sig) > 0 {
		if err := os.WriteFile(filepath.Join(outDir, filepath.Base(keys.Signature)), sig, 0o644); err != nil {
			return err
		}
	}
	if len(cert) > 0 {
		if err := os.WriteFile(filepath.Join(outDir, filepath.Base(keys.Cert)), cert, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(dst, src string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

type objectUploader interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func uploadArchive(ctx context.Context, client objectUploader, bucket string, keys archiveKeys, archivePath string, manifest, sig, cert []byte, m archiveManifest) error {
	if strings.TrimSpace(bucket) == "" {
		return errors.New("bucket required")
	}
	commonMeta := map[string]string{
		"window-start":   m.WindowStart,
		"window-end":     m.WindowEnd,
		"record-count":   fmt.Sprintf("%d", m.RecordCount),
		"archive-sha256": m.ArchiveSHA256,
	}
	if err := putFile(ctx, client, bucket, keys.Archive, archivePath, "application/x-ndjson", "gzip", commonMeta); err != nil {
		return err
	}
	if err := putBytes(ctx, client, bucket, keys.Manifest, manifest, "application/json", "", commonMeta); err != nil {
		return err
	}
	if len(sig) > 0 {
		if err := putBytes(ctx, client, bucket, keys.Signature, sig, "text/plain", "", commonMeta); err != nil {
			return err
		}
	}
	if len(cert) > 0 {
		if err := putBytes(ctx, client, bucket, keys.Cert, cert, "application/x-pem-file", "", commonMeta); err != nil {
			return err
		}
	}
	return nil
}

func putFile(ctx context.Context, client objectUploader, bucket, key, path, contentType, contentEncoding string, metadata map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return putObject(ctx, client, bucket, key, f, contentType, contentEncoding, metadata)
}

func putBytes(ctx context.Context, client objectUploader, bucket, key string, body []byte, contentType, contentEncoding string, metadata map[string]string) error {
	return putObject(ctx, client, bucket, key, bytes.NewReader(body), contentType, contentEncoding, metadata)
}

func putObject(ctx context.Context, client objectUploader, bucket, key string, body io.Reader, contentType, contentEncoding string, metadata map[string]string) error {
	input := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        body,
		ContentType: aws.String(contentType),
		Metadata:    metadata,
	}
	if contentEncoding != "" {
		input.ContentEncoding = aws.String(contentEncoding)
	}
	sum, err := payloadSHA256(body)
	if err != nil {
		return fmt.Errorf("checksum %s: %w", key, err)
	}
	if sum != "" {
		input.ChecksumSHA256 = aws.String(sum)
	}
	_, err = client.PutObject(ctx, input)
	if err != nil {
		return fmt.Errorf("put s3://%s/%s: %w", bucket, key, err)
	}
	return nil
}

func payloadSHA256(r io.Reader) (string, error) {
	seeker, ok := r.(io.ReadSeeker)
	if !ok {
		return "", nil
	}
	pos, err := seeker.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, seeker); err != nil {
		return "", err
	}
	if _, err := seeker.Seek(pos, io.SeekStart); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
