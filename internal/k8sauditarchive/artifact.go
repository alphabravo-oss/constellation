// Package k8sauditarchive preserves Kubernetes audit evidence in signed pages.
// Export and restoration never authorize source expiry.
package k8sauditarchive

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
	formatVersion    = "constellation-kubernetes-audit/v1"
	MaxRows          = 1000
	MaxRecordBytes   = 4 << 20
	MaxBatchBytes    = 32 << 20
	MaxArtifactBytes = 48 << 20
)

type Record struct {
	ID          uuid.UUID       `json:"id"`
	OrgID       uuid.UUID       `json:"org_id"`
	ClusterID   uuid.UUID       `json:"cluster_id"`
	Verb        string          `json:"verb"`
	Resource    *string         `json:"resource"`
	Subresource *string         `json:"subresource"`
	APIGroup    *string         `json:"api_group"`
	Namespace   *string         `json:"namespace"`
	Name        *string         `json:"name"`
	User        *string         `json:"user"`
	SourceIP    *string         `json:"source_ip"`
	Decision    *string         `json:"decision"`
	Signal      *string         `json:"signal"`
	Severity    *string         `json:"severity"`
	AuditID     *string         `json:"audit_id"`
	Raw         json.RawMessage `json:"raw"`
	ReportedAt  *time.Time      `json:"reported_at"`
	At          time.Time       `json:"at"`
}

// Cursor is an exclusive (receipt time, UUID) key, never a reported timestamp.
type Cursor struct {
	At time.Time `json:"at"`
	ID uuid.UUID `json:"id"`
}

type Window struct {
	OrgID     uuid.UUID `json:"org_id"`
	ClusterID uuid.UUID `json:"cluster_id"`
	From      time.Time `json:"from"`
	Through   time.Time `json:"through"`
	After     Cursor    `json:"after"`
}

type Manifest struct {
	Format           string    `json:"format"`
	Window           Window    `json:"window"`
	First            Cursor    `json:"first"`
	Last             Cursor    `json:"last"`
	Count            int       `json:"count"`
	More             bool      `json:"more"`
	RecordBytes      int       `json:"record_bytes"`
	RecordsSHA256    string    `json:"records_sha256"`
	CompressedSHA256 string    `json:"compressed_sha256"`
	SignerIdentity   string    `json:"signer_identity"`
	CreatedAt        time.Time `json:"created_at"`
}

type Report struct {
	Manifest      Manifest `json:"manifest"`
	ArchiveSHA256 string   `json:"archive_sha256"`
}

type envelope struct {
	Manifest  json.RawMessage `json:"manifest"`
	Signature []byte          `json:"signature"`
	Data      []byte          `json:"data"`
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func (w Window) validate() error {
	if w.OrgID == uuid.Nil || w.ClusterID == uuid.Nil || w.From.IsZero() || !w.Through.After(w.From) || w.From.Nanosecond()%1000 != 0 || w.Through.Nanosecond()%1000 != 0 {
		return errors.New("explicit scope and increasing microsecond-precision time window required")
	}
	if w.After.ID == uuid.Nil && w.After.At.IsZero() {
		return nil
	}
	if w.After.ID == uuid.Nil || w.After.At.Before(w.From) || !w.After.At.Before(w.Through) || w.After.At.Nanosecond()%1000 != 0 {
		return errors.New("invalid archive continuation cursor")
	}
	return nil
}

func encode(ctx context.Context, w Window, records []Record, more bool, private, public string) ([]byte, Report, error) {
	var report Report
	raw, err := json.Marshal(records)
	if err != nil {
		return nil, report, err
	}
	if len(raw) > MaxBatchBytes || len(records) < 1 || len(records) > MaxRows {
		return nil, report, errors.New("archive page outside limits")
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err = io.Copy(gz, archiveio.Reader{Context: ctx, Input: bytes.NewReader(raw)}); err != nil {
		_ = gz.Close()
		return nil, report, err
	}
	if err = gz.Close(); err != nil {
		return nil, report, err
	}
	_, _, identity, err := backup.Sign(ctx, nil, backup.SignerOptions{Mode: backup.SignModeStaticKey, KeyPath: private})
	if err != nil {
		return nil, report, err
	}
	m := Manifest{Format: formatVersion, Window: w, First: Cursor{records[0].At, records[0].ID}, Last: Cursor{records[len(records)-1].At, records[len(records)-1].ID}, Count: len(records), More: more, RecordBytes: len(raw), RecordsSHA256: digest(raw), CompressedSHA256: digest(compressed.Bytes()), SignerIdentity: identity, CreatedAt: time.Now().UTC()}
	metadata, err := json.Marshal(m)
	if err != nil {
		return nil, report, err
	}
	signature, _, _, err := backup.Sign(ctx, metadata, backup.SignerOptions{Mode: backup.SignModeStaticKey, KeyPath: private})
	if err != nil {
		return nil, report, err
	}
	data, err := json.Marshal(envelope{metadata, signature, compressed.Bytes()})
	if err != nil {
		return nil, report, err
	}
	report, err = Verify(ctx, bytes.NewReader(data), public)
	return data, report, err
}

// Verify needs only an artifact and independently trusted public key. Reports
// contain boundaries and hashes, never raw event bodies or user/source fields.
func Verify(ctx context.Context, input io.Reader, public string) (Report, error) {
	_, report, err := verify(ctx, input, public)
	return report, err
}

func verify(ctx context.Context, input io.Reader, public string) ([]Record, Report, error) {
	var report Report
	raw, err := io.ReadAll(io.LimitReader(archiveio.Reader{Context: ctx, Input: input}, MaxArtifactBytes+1))
	if err != nil {
		return nil, report, err
	}
	if len(raw) > MaxArtifactBytes {
		return nil, report, errors.New("archive exceeds byte limit")
	}
	var e envelope
	if err = archiveio.Decode(raw, &e); err != nil {
		return nil, report, err
	}
	if len(e.Manifest) > 1<<20 || len(e.Signature) > 1<<20 {
		return nil, report, errors.New("archive metadata exceeds limit")
	}
	identity, err := backup.Verify(ctx, e.Manifest, e.Signature, nil, backup.VerifierOptions{Mode: backup.SignModeStaticKey, KeyPath: public})
	if err != nil {
		return nil, report, err
	}
	var m Manifest
	if err = archiveio.Decode(e.Manifest, &m); err != nil {
		return nil, report, err
	}
	if err = m.Window.validate(); err != nil {
		return nil, report, err
	}
	if m.Format != formatVersion || m.Count < 1 || m.Count > MaxRows || m.RecordBytes < 1 || m.RecordBytes > MaxBatchBytes || m.CreatedAt.IsZero() || m.SignerIdentity != identity || digest(e.Data) != m.CompressedSHA256 {
		return nil, report, errors.New("invalid signed archive manifest")
	}
	records, err := decodeRecords(ctx, e.Data, m)
	if err != nil {
		return nil, report, err
	}
	return records, Report{m, digest(raw)}, ctx.Err()
}

func decodeRecords(ctx context.Context, data []byte, m Manifest) ([]Record, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	raw, err := io.ReadAll(io.LimitReader(archiveio.Reader{Context: ctx, Input: gz}, MaxBatchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) != m.RecordBytes || digest(raw) != m.RecordsSHA256 {
		return nil, errors.New("archive payload checksum or size mismatch")
	}
	var records []Record
	if err = archiveio.Decode(raw, &records); err != nil {
		return nil, err
	}
	if len(records) != m.Count {
		return nil, errors.New("archive row count mismatch")
	}
	previous := m.Window.After
	for i, row := range records {
		cursor := Cursor{row.At, row.ID}
		if row.At.Nanosecond()%1000 != 0 || row.ReportedAt != nil && row.ReportedAt.Nanosecond()%1000 != 0 || row.ID == uuid.Nil || row.OrgID != m.Window.OrgID || row.ClusterID != m.Window.ClusterID || row.Verb == "" || row.At.Before(m.Window.From) || !row.At.Before(m.Window.Through) || !cursorAfter(cursor, previous) {
			return nil, errors.New("invalid archive row scope, order or time")
		}
		encoded, err := json.Marshal(row)
		if err != nil || len(encoded) > MaxRecordBytes {
			return nil, errors.New("archive row exceeds limit")
		}
		if i == 0 && !cursorEqual(cursor, m.First) {
			return nil, errors.New("archive first boundary mismatch")
		}
		previous = cursor
	}
	if !cursorEqual(previous, m.Last) {
		return nil, errors.New("archive last boundary mismatch")
	}
	return records, nil
}

func cursorAfter(a, b Cursor) bool {
	return a.At.After(b.At) || a.At.Equal(b.At) && bytes.Compare(a.ID[:], b.ID[:]) > 0
}

func cursorEqual(a, b Cursor) bool { return a.ID == b.ID && a.At.Equal(b.At) }
