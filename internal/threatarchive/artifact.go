// Package threatarchive preserves runtime threats, including packet evidence.
// Archives never authorize pruning or replay response actions.
package threatarchive

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/evidencepage"
)

const (
	formatVersion    = "constellation-runtime-threat/v1"
	MaxRows          = evidencepage.MaxRows
	MaxRecordBytes   = evidencepage.MaxRecordBytes
	MaxBatchBytes    = evidencepage.MaxBatchBytes
	MaxArtifactBytes = evidencepage.MaxArtifactBytes
)

type Window = evidencepage.Window
type Cursor = evidencepage.Cursor
type Manifest = evidencepage.Manifest
type Report = evidencepage.Report

// Record mirrors persisted evidence, not the live ingest DTO. Nullable fields,
// historical metadata, and packet length claims must survive without coercion.
// Packet uses PostgreSQL hex bytea notation; nil and an empty packet are distinct.
type Record struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	ClusterID   uuid.UUID `json:"cluster_id"`
	Node        *string   `json:"node"`
	EPMAC       *string   `json:"ep_mac"`
	ThreatID    uint32    `json:"threat_id"`
	Severity    int16     `json:"severity"`
	Action      int16     `json:"action"`
	Application *int32    `json:"application"`
	Msg         *string   `json:"msg"`
	DLPNameHash *int64    `json:"dlp_name_hash"`
	IPProto     *int16    `json:"ip_proto"`
	EtherType   *int32    `json:"ether_type"`
	SrcIP       *string   `json:"src_ip"`
	SrcPort     *int32    `json:"src_port"`
	DstIP       *string   `json:"dst_ip"`
	DstPort     *int32    `json:"dst_port"`
	ICMPCode    *int16    `json:"icmp_code"`
	ICMPType    *int16    `json:"icmp_type"`
	Packet      *string   `json:"packet"`
	PktLen      *int32    `json:"pkt_len"`
	CapLen      *int32    `json:"cap_len"`
	PktIngress  bool      `json:"pkt_ingress"`
	SessIngress bool      `json:"sess_ingress"`
	TapMode     bool      `json:"tap_mode"`
	ReportedAt  time.Time `json:"reported_at"`
	At          time.Time `json:"at"`
	WorkloadID  *string   `json:"workload_id"`
	Namespace   *string   `json:"namespace"`
	PodName     *string   `json:"pod_name"`
}

var codec = evidencepage.Codec[Record]{Format: formatVersion, Cursor: recordCursor}

func recordCursor(row Record, w Window) (Cursor, error) {
	if row.OrgID != w.OrgID || row.ClusterID != w.ClusterID || row.ReportedAt.IsZero() || row.ReportedAt.Nanosecond()%1000 != 0 {
		return Cursor{}, errors.New("invalid threat scope or timestamp")
	}
	if row.Packet != nil {
		if !strings.HasPrefix(*row.Packet, `\x`) {
			return Cursor{}, errors.New("invalid packet encoding")
		}
		if _, err := hex.DecodeString((*row.Packet)[2:]); err != nil {
			return Cursor{}, errors.New("invalid packet encoding")
		}
	}
	return Cursor{At: row.At, ID: row.ID}, nil
}
func encode(ctx context.Context, w Window, rows []Record, more bool, private, public string) ([]byte, Report, error) {
	return codec.Encode(ctx, w, rows, more, private, public)
}

// Verify uses only the artifact and an independently trusted public key.
func Verify(ctx context.Context, input io.Reader, public string) (Report, error) {
	return codec.Verify(ctx, input, public)
}
func verify(ctx context.Context, input io.Reader, public string) ([]Record, Report, error) {
	return codec.Read(ctx, input, public)
}
