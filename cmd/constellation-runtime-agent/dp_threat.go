// Wave 5: dp threat events → /api/v1/runtime-threats:bulk.
//
// dp emits one DPMsgThreatLog per signature hit: HTTP smuggling, DNS tunneling,
// SQL injection, SSL Heartbleed, mid-stream TCP with bad flags, etc. The
// supervisor decodes these into dp.EventThreat; this file's job is to fan
// them out to the control plane.
//
// We mirror the flow upload-loop shape exactly (batch buffer + flush trigger
// = N rows OR T elapsed, exponential-backoff retries) so operators only have
// one mental model for "the runtime-agent's outbound batching".
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// threatIngestRow is the wire shape sent to /api/v1/runtime-threats:bulk.
// Mirrors handler.ThreatIngestRow — keep field tags in lockstep.
type threatIngestRow struct {
	At          time.Time `json:"at"`
	Node        string    `json:"node,omitempty"`
	EPMAC       string    `json:"ep_mac,omitempty"`
	ThreatID    uint32    `json:"threat_id"`
	Severity    uint8     `json:"severity"`
	Action      uint8     `json:"action"`
	Application uint32    `json:"application,omitempty"`
	Msg         string    `json:"msg,omitempty"`
	DlpNameHash uint32    `json:"dlp_name_hash,omitempty"`

	IPProto   uint8  `json:"ip_proto,omitempty"`
	EtherType uint16 `json:"ether_type,omitempty"`
	SrcIP     string `json:"src_ip,omitempty"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	ICMPCode  uint8  `json:"icmp_code,omitempty"`
	ICMPType  uint8  `json:"icmp_type,omitempty"`

	Packet []byte `json:"packet,omitempty"`
	PktLen int    `json:"pkt_len,omitempty"`
	CapLen int    `json:"cap_len,omitempty"`

	PktIngress  bool `json:"pkt_ingress,omitempty"`
	SessIngress bool `json:"sess_ingress,omitempty"`
	TapMode     bool `json:"tap,omitempty"`

	ReportedAt time.Time `json:"reported_at,omitempty"`
}

// dpThreatToIngest builds a threatIngestRow from one dp.EventThreat.
// ev.At is the agent-side decode timestamp; ev.Threat.ReportedAt is the
// host-clock epoch second dp recorded — we promote that to reported_at.
func dpThreatToIngest(ev dp.Event, node string) threatIngestRow {
	t := ev.Threat
	row := threatIngestRow{
		At:          ev.At,
		Node:        node,
		ThreatID:    t.ThreatID,
		Severity:    t.Severity,
		Action:      t.Action,
		Application: uint32(t.Application),
		Msg:         t.Msg,
		DlpNameHash: t.DlpNameHash,
		IPProto:     t.IPProto,
		EtherType:   t.EtherType,
		SrcPort:     int(t.SrcPort),
		DstPort:     int(t.DstPort),
		ICMPCode:    t.ICMPCode,
		ICMPType:    t.ICMPType,
		Packet:      t.Packet,
		PktLen:      int(t.PktLen),
		CapLen:      int(t.CapLen),
		PktIngress:  t.PktIngress,
		SessIngress: t.SessIngress,
		TapMode:     t.Tap,
		ReportedAt:  time.Unix(int64(t.ReportedAt), 0).UTC(),
	}
	if t.EPMAC != nil {
		row.EPMAC = strings.ToLower(t.EPMAC.String())
	}
	if t.SrcIP != nil {
		row.SrcIP = t.SrcIP.String()
	}
	if t.DstIP != nil {
		row.DstIP = t.DstIP.String()
	}
	return row
}

// threatUploadLoop drains threatOut into batches and POSTs each batch.
// Same flush triggers as flowUploadLoop (batch full OR ticker fires).
// On failure: 3 retries with exponential backoff; final failure drops the
// batch and bumps `dropped` by len(batch).
func threatUploadLoop(
	ctx context.Context,
	logger *slog.Logger,
	url, token string,
	size int,
	interval time.Duration,
	in <-chan threatIngestRow,
	uploaded, dropped *atomic.Uint64,
) {
	client := sharedUploadClient
	sem := make(chan struct{}, maxInFlightUploads)
	buf := make([]threatIngestRow, 0, size)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		batch := buf
		buf = make([]threatIngestRow, 0, size)
		// Bound in-flight POSTs: block briefly for a slot so a wedged API
		// can't leak an unbounded number of upload goroutines + batches.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		go func() {
			defer func() { <-sem }()
			if err := postThreatBatch(ctx, client, url, token, batch); err != nil {
				logger.Warn("threat upload failed; dropping",
					slog.Int("batch", len(batch)),
					slog.String("err", err.Error()))
				dropped.Add(uint64(len(batch)))
				return
			}
			uploaded.Add(uint64(len(batch)))
		}()
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case row, ok := <-in:
			if !ok {
				flush()
				return
			}
			buf = append(buf, row)
			if len(buf) >= size {
				flush()
				ticker.Reset(interval)
			}
		case <-ticker.C:
			flush()
		}
	}
}

func postThreatBatch(ctx context.Context, client *http.Client, url, token string, batch []threatIngestRow) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	delays := []time.Duration{0, 100 * time.Millisecond, 400 * time.Millisecond, 1600 * time.Millisecond}
	var lastErr error
	for _, delay := range delays {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("new request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
		lastErr = fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if lastErr == nil {
		lastErr = errors.New("unknown threat upload failure")
	}
	return lastErr
}
