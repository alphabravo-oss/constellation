// Package auditarchive exports bounded, signed audit chain segments. It never
// deletes source evidence and does not make claims about bucket retention policy.
package auditarchive

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

const MaxBatch = 10000
const MaxArchiveBytes int64 = 256 << 20

// ObjectStore supports server-validated writes and independent read-back.
type ObjectStore interface {
	objectUploader
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type Config struct {
	Bucket, Prefix, Endpoint string
	BatchSize                int
	DryRun                   bool
	OutDir                   string
	Signer                   backup.SignerOptions
	Verifier                 backup.VerifierOptions
}

func (c Config) Validate() error {
	if c.BatchSize < 1 || c.BatchSize > MaxBatch {
		return fmt.Errorf("batch-size must be between 1 and %d", MaxBatch)
	}
	if !c.DryRun && strings.TrimSpace(c.Bucket) == "" {
		return errors.New("bucket required")
	}
	mode, err := backup.ResolveSignMode(string(c.Signer.Mode), backup.SignModeNone)
	if err != nil {
		return err
	}
	if mode == backup.SignModeNone {
		if c.DryRun {
			return nil
		}
		return errors.New("durable audit archive requires static-key or keyless signing")
	}
	if c.Verifier.Mode != mode {
		return errors.New("signing and verification modes must match")
	}
	if mode == backup.SignModeStaticKey && (c.Signer.KeyPath == "" || c.Verifier.KeyPath == "") {
		return errors.New("static-key archive requires sign-key and verify-key")
	}
	if mode == backup.SignModeKeyless && c.Verifier.Identity == "" {
		return errors.New("keyless archive requires an expected verify-identity")
	}
	return nil
}

func (c Config) stream() string {
	// Include the endpoint so a destination change starts an independent catch-up.
	b, _ := json.Marshal([]string{c.Endpoint, c.Bucket, strings.Trim(strings.TrimSpace(c.Prefix), "/")})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type checkpoint struct {
	ID             int64
	Hash, Manifest string
}

// Run publishes at most one batch. Row locking serializes replicas per stream,
// including network verification; cancellation rolls back progress. Dry runs
// read the same checkpoint but never create or update it.
func Run(ctx context.Context, pool *pgxpool.Pool, objects ObjectStore, c Config) (Manifest, error) {
	if err := c.Validate(); err != nil {
		return Manifest{}, err
	}
	if !c.DryRun && objects == nil {
		return Manifest{}, errors.New("object store required")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Manifest{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	cp, err := loadCheckpoint(ctx, tx, c)
	if err != nil {
		return Manifest{}, err
	}
	bundle, err := export(ctx, tx, c, cp)
	if err != nil {
		return Manifest{}, err
	}
	if bundle == nil {
		return Manifest{}, nil
	}
	defer func() { _ = os.Remove(bundle.path) }()
	m := bundle.manifest
	if c.DryRun {
		err = writeLocalArtifacts(c.OutDir, bundle.keys, bundle.path, bundle.raw, bundle.sig, bundle.cert)
		return m, err
	}
	if err = uploadArchive(ctx, objects, c.Bucket, bundle.keys, bundle.path, bundle.raw, bundle.sig, bundle.cert, m); err != nil {
		return Manifest{}, err
	}
	if err = verifyRemote(ctx, objects, c, bundle); err != nil {
		return Manifest{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE audit_archive_progress SET last_id=$2,last_hash=$3,last_manifest=$4,updated_at=now() WHERE stream=$1`, c.stream(), m.LastID, m.LastChain, m.ManifestKey)
	if err != nil {
		return Manifest{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

type archiveBundle struct {
	path           string
	keys           archiveKeys
	manifest       Manifest
	raw, sig, cert []byte
}

func export(ctx context.Context, tx pgx.Tx, c Config, cp checkpoint) (*archiveBundle, error) {
	rows, err := tx.Query(ctx, `SELECT id,org_id,actor_id,host(actor_ip),action,COALESCE(target_kind,''),COALESCE(target_id,''),before,after,prev_hash,chain_hash,COALESCE(request_id,''),at
 FROM audit_events WHERE id>$1 ORDER BY id LIMIT $2`, cp.ID, c.BatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	f, err := os.CreateTemp("", "constellation-audit-*.jsonl.gz")
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(f.Name())
		}
	}()
	compressed := &limitedWriter{w: f, left: MaxArchiveBytes}
	gz := gzip.NewWriter(compressed)
	h := sha256.New()
	plain := &limitedWriter{w: io.MultiWriter(gz, h), left: MaxArchiveBytes}
	enc := json.NewEncoder(plain)
	m := Manifest{FormatVersion: archiveManifestVersion, Stream: c.stream(), FirstPrevHash: cp.Hash, PreviousManifest: cp.Manifest,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), SignMode: c.Signer.Mode}
	if err = writeRows(rows, enc, &m, cp); err != nil {
		return nil, err
	}
	if err = gz.Close(); err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	if m.RecordCount == 0 {
		return nil, nil
	}
	m.JSONLSHA256 = hex.EncodeToString(h.Sum(nil))
	m.ArchiveSHA256, err = fileSHA256(f.Name())
	if err != nil {
		return nil, err
	}
	m.SHA256 = m.ArchiveSHA256
	keys := makeArchiveKeys(c.Prefix, m.FirstID, m.LastID, uuid.NewString())
	m.ArchiveKey = keys.Archive
	m.ManifestKey = keys.Manifest
	if c.Signer.Mode != backup.SignModeNone && c.Signer.Mode != "" {
		m.SignatureKey = keys.Signature
	}
	if c.Signer.Mode == backup.SignModeKeyless {
		m.CertificateKey = keys.Cert
	}
	raw, sig, cert, err := signArchiveManifest(ctx, m, c.Signer)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.SignMode != backup.SignModeNone {
		if _, err = Verify(ctx, f.Name(), raw, sig, cert, c.Verifier); err != nil {
			return nil, fmt.Errorf("local archive verification: %w", err)
		}
	}
	keep = true
	return &archiveBundle{path: f.Name(), keys: keys, manifest: m, raw: raw, sig: sig, cert: cert}, nil
}

type limitedWriter struct {
	w    io.Writer
	left int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.left {
		return 0, errors.New("audit archive exceeds byte limit; reduce batch-size")
	}
	n, err := w.w.Write(p)
	w.left -= int64(n)
	return n, err
}

func writeRows(rows pgx.Rows, enc *json.Encoder, m *Manifest, cp checkpoint) error {
	prev, lastID := cp.Hash, cp.ID
	var earliest, latest time.Time
	for rows.Next() {
		var r audit.Record
		if err := rows.Scan(&r.ID, &r.OrgID, &r.ActorID, &r.ActorIP, &r.Action, &r.TargetKind, &r.TargetID, &r.Before, &r.After, &r.PrevHash, &r.ChainHash, &r.RequestID, &r.At); err != nil {
			return err
		}
		if r.ID <= lastID {
			return errors.New("audit IDs are not increasing")
		}
		if err := audit.VerifyRecord(r, prev); err != nil {
			return err
		}
		if err := enc.Encode(r); err != nil {
			return err
		}
		if m.RecordCount == 0 {
			m.FirstID = r.ID
			m.FirstChain = r.ChainHash
			earliest = r.At
			latest = r.At
		}
		if r.At.Before(earliest) {
			earliest = r.At
		}
		if r.At.After(latest) {
			latest = r.At
		}
		m.RecordCount++
		prev = r.ChainHash
		lastID = r.ID
	}
	if err := rows.Err(); err != nil {
		return err
	}
	m.LastID = lastID
	m.LastChain = prev
	m.WindowStart = earliest.UTC().Format(time.RFC3339Nano)
	m.WindowEnd = latest.UTC().Format(time.RFC3339Nano)
	return nil
}
