// Package k8sauditarchive preserves Kubernetes audit evidence without authorizing source expiry.
package k8sauditarchive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/evidencepage"
)

const (
	formatVersion    = "constellation-kubernetes-audit/v1"
	MaxRows          = evidencepage.MaxRows
	MaxRecordBytes   = evidencepage.MaxRecordBytes
	MaxBatchBytes    = evidencepage.MaxBatchBytes
	MaxArtifactBytes = evidencepage.MaxArtifactBytes
)

type Window = evidencepage.Window
type Cursor = evidencepage.Cursor
type Manifest = evidencepage.Manifest
type Report = evidencepage.Report
type envelope = evidencepage.Envelope
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

var codec = evidencepage.Codec[Record]{Format: formatVersion, Cursor: recordCursor}

func recordCursor(row Record, w Window) (Cursor, error) {
	if row.OrgID != w.OrgID || row.ClusterID != w.ClusterID || row.Verb == "" || row.ReportedAt != nil && row.ReportedAt.Nanosecond()%1000 != 0 {
		return Cursor{}, errors.New("invalid audit row scope or content")
	}
	return Cursor{At: row.At, ID: row.ID}, nil
}
func encode(ctx context.Context, w Window, rows []Record, more bool, private, public string) ([]byte, Report, error) {
	return codec.Encode(ctx, w, rows, more, private, public)
}
func Verify(ctx context.Context, input io.Reader, public string) (Report, error) {
	return codec.Verify(ctx, input, public)
}
func verify(ctx context.Context, input io.Reader, public string) ([]Record, Report, error) {
	return codec.Read(ctx, input, public)
}
func decodeRecords(ctx context.Context, data []byte, m Manifest) ([]Record, error) {
	return codec.DecodeRecords(ctx, data, m)
}
