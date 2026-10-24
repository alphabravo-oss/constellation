// Package inventoryarchive preserves signed package-inventory evidence without
// deleting source records or weakening their existing reference protections.
package inventoryarchive

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/archiveio"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

const (
	formatVersion    = "constellation-inventory-evidence/v1"
	MaxRecordBytes   = 32 << 20
	MaxArtifactBytes = 48 << 20
)

type targetIdentity struct {
	Type       string  `json:"type"`
	Ref        string  `json:"ref"`
	SourceType string  `json:"source_type"`
	SourceRef  *string `json:"source_ref"`
}

type record struct {
	ID            uuid.UUID       `json:"id"`
	OrgID         uuid.UUID       `json:"org_id"`
	TargetID      uuid.UUID       `json:"scan_target_id"`
	ClusterID     *uuid.UUID      `json:"cluster_id"`
	TargetType    string          `json:"target_type"`
	TargetRef     string          `json:"target_ref"`
	SourceType    string          `json:"source_type"`
	SourceRef     *string         `json:"source_ref"`
	EvidenceType  string          `json:"evidence_type"`
	InventoryHash string          `json:"inventory_hash"`
	PackageCount  int             `json:"package_count"`
	Payload       json.RawMessage `json:"payload"`
	ObservedAt    time.Time       `json:"observed_at"`
	ExpiresAt     *time.Time      `json:"expires_at"`
	CreatedAt     time.Time       `json:"created_at"`
}

type manifest struct {
	Format           string         `json:"format"`
	OrgID            uuid.UUID      `json:"org_id"`
	TargetID         uuid.UUID      `json:"target_id"`
	EvidenceID       uuid.UUID      `json:"evidence_id"`
	Target           targetIdentity `json:"target"`
	RecordSHA256     string         `json:"record_sha256"`
	CompressedSHA256 string         `json:"compressed_sha256"`
	RecordBytes      int            `json:"record_bytes"`
	SignerIdentity   string         `json:"signer_identity"`
	CreatedAt        time.Time      `json:"created_at"`
}

type envelope struct {
	Manifest  json.RawMessage `json:"manifest"`
	Signature []byte          `json:"signature"`
	Data      []byte          `json:"data"`
}

// Report contains verified identities and digests, never the inventory payload.
type Report struct {
	OrgID          uuid.UUID `json:"source_org_id"`
	TargetID       uuid.UUID `json:"source_target_id"`
	EvidenceID     uuid.UUID `json:"evidence_id"`
	ArchiveSHA256  string    `json:"archive_sha256"`
	RecordSHA256   string    `json:"record_sha256"`
	SignerIdentity string    `json:"signer_identity"`
	PackageCount   int       `json:"package_count"`
}

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func strictJSON(raw []byte, value any) error { return archiveio.Decode(raw, value) }

func encode(ctx context.Context, row record, target targetIdentity, privateKey, publicKey string) ([]byte, Report, error) {
	var report Report
	raw, err := json.Marshal(row)
	if err != nil {
		return nil, report, err
	}
	if len(raw) > MaxRecordBytes {
		return nil, report, errors.New("inventory record exceeds byte limit")
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err = gz.Write(raw); err != nil {
		return nil, report, err
	}
	if err = gz.Close(); err != nil {
		return nil, report, err
	}
	m := manifest{Format: formatVersion, OrgID: row.OrgID, TargetID: row.TargetID, EvidenceID: row.ID, Target: target,
		RecordSHA256: checksum(raw), CompressedSHA256: checksum(compressed.Bytes()), RecordBytes: len(raw), CreatedAt: time.Now().UTC()}
	// The identity is derived from the actual signing key and included in the
	// final signed bytes; a manifest-supplied identity is never sufficient trust.
	_, _, identity, err := backup.Sign(ctx, nil, backup.SignerOptions{Mode: backup.SignModeStaticKey, KeyPath: privateKey})
	if err != nil {
		return nil, report, err
	}
	m.SignerIdentity = identity
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		return nil, report, err
	}
	sig, _, _, err := backup.Sign(ctx, manifestBytes, backup.SignerOptions{Mode: backup.SignModeStaticKey, KeyPath: privateKey})
	if err != nil {
		return nil, report, err
	}
	artifact, err := json.Marshal(envelope{Manifest: manifestBytes, Signature: sig, Data: compressed.Bytes()})
	if err != nil {
		return nil, report, err
	}
	_, _, report, err = verify(ctx, bytes.NewReader(artifact), publicKey)
	return artifact, report, err
}

// Verify works offline with an independently supplied Ed25519 public key.
func Verify(ctx context.Context, input io.Reader, publicKey string) (Report, error) {
	_, _, report, err := verify(ctx, input, publicKey)
	return report, err
}

func verify(ctx context.Context, input io.Reader, publicKey string) (record, manifest, Report, error) {
	var row record
	var m manifest
	var report Report
	if err := ctx.Err(); err != nil {
		return row, m, report, err
	}
	raw, err := io.ReadAll(io.LimitReader(archiveio.Reader{Context: ctx, Input: input}, MaxArtifactBytes+1))
	if err != nil {
		return row, m, report, err
	}
	if len(raw) > MaxArtifactBytes {
		return row, m, report, errors.New("inventory artifact exceeds byte limit")
	}
	var e envelope
	if err = strictJSON(raw, &e); err != nil {
		return row, m, report, err
	}
	if len(e.Manifest) > 1<<20 || len(e.Signature) > 1<<20 {
		return row, m, report, errors.New("inventory metadata exceeds byte limit")
	}
	identity, err := backup.Verify(ctx, e.Manifest, e.Signature, nil, backup.VerifierOptions{Mode: backup.SignModeStaticKey, KeyPath: publicKey})
	if err != nil {
		return row, m, report, err
	}
	if err = strictJSON(e.Manifest, &m); err != nil {
		return row, m, report, err
	}
	if m.Format != formatVersion || m.SignerIdentity != identity || m.RecordBytes < 1 || m.RecordBytes > MaxRecordBytes || checksum(e.Data) != m.CompressedSHA256 {
		return row, m, report, errors.New("invalid signed inventory manifest or compressed checksum")
	}
	row, err = decompressRecord(e.Data, m)
	if err != nil {
		return row, m, report, err
	}
	if err = ctx.Err(); err != nil {
		return row, m, report, err
	}
	report = Report{OrgID: m.OrgID, TargetID: m.TargetID, EvidenceID: m.EvidenceID, ArchiveSHA256: checksum(raw), RecordSHA256: m.RecordSHA256, SignerIdentity: identity, PackageCount: row.PackageCount}
	return row, m, report, nil
}

func decompressRecord(data []byte, m manifest) (record, error) {
	var row record
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return row, err
	}
	defer func() { _ = gz.Close() }()
	raw, err := io.ReadAll(io.LimitReader(gz, MaxRecordBytes+1))
	if err != nil {
		return row, err
	}
	if len(raw) != m.RecordBytes || checksum(raw) != m.RecordSHA256 {
		return row, errors.New("inventory record checksum or byte count mismatch")
	}
	if err = strictJSON(raw, &row); err != nil {
		return row, err
	}
	if row.ID == uuid.Nil || row.OrgID == uuid.Nil || row.TargetID == uuid.Nil || row.ID != m.EvidenceID || row.OrgID != m.OrgID || row.TargetID != m.TargetID ||
		row.TargetType != m.Target.Type || row.TargetRef != m.Target.Ref || row.EvidenceType != "package-inventory" || row.InventoryHash == "" || row.PackageCount < 0 || row.ObservedAt.IsZero() || row.CreatedAt.IsZero() || !json.Valid(row.Payload) {
		return row, errors.New("invalid inventory record identity or metadata")
	}
	return row, nil
}
