// Live-session upload lane (NV RESTSession parity).
//
// dp maintains a ctrl_list_session table (the SessionCache, refreshed by the
// session poller). Unlike threats/flows — which are event STREAMS — the session
// table is a SNAPSHOT of current connections. So this lane doesn't drain a
// channel; it ticks, snapshots dpSup.Sessions().List(), and uploads the whole
// table. The ingest replaces the node's rows, so evicted sessions disappear.
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

// sessionUploadRow is the wire shape POSTed to /network-sessions:bulk. Field
// tags mirror handler/network.sessionIngestRow — keep them in lockstep.
type sessionUploadRow struct {
	ID           int64  `json:"id"`
	Node         string `json:"node,omitempty"`
	EPMAC        string `json:"ep_mac,omitempty"`
	EtherType    int    `json:"ether_type,omitempty"`
	IPProto      int    `json:"ip_proto,omitempty"`
	Application  int    `json:"application,omitempty"`
	ClientMAC    string `json:"client_mac,omitempty"`
	ServerMAC    string `json:"server_mac,omitempty"`
	ClientIP     string `json:"client_ip,omitempty"`
	ServerIP     string `json:"server_ip,omitempty"`
	ClientPort   int    `json:"client_port,omitempty"`
	ServerPort   int    `json:"server_port,omitempty"`
	ICMPCode     int    `json:"icmp_code,omitempty"`
	ICMPType     int    `json:"icmp_type,omitempty"`
	ClientPkts   int64  `json:"client_pkts,omitempty"`
	ServerPkts   int64  `json:"server_pkts,omitempty"`
	ClientBytes  int64  `json:"client_bytes,omitempty"`
	ServerBytes  int64  `json:"server_bytes,omitempty"`
	ClientAsmPkts  int64 `json:"client_asm_pkts,omitempty"`
	ServerAsmPkts  int64 `json:"server_asm_pkts,omitempty"`
	ClientAsmBytes int64 `json:"client_asm_bytes,omitempty"`
	ServerAsmBytes int64 `json:"server_asm_bytes,omitempty"`
	ClientState  int    `json:"client_state,omitempty"`
	ServerState  int    `json:"server_state,omitempty"`
	Idle         int    `json:"idle,omitempty"`
	Age          int    `json:"age,omitempty"`
	Life         int    `json:"life,omitempty"`
	ThreatID     int64  `json:"threat_id,omitempty"`
	PolicyID     int64  `json:"policy_id,omitempty"`
	PolicyAction int    `json:"policy_action,omitempty"`
	Severity     int    `json:"severity,omitempty"`
	Ingress      bool   `json:"ingress,omitempty"`
	Tap          bool   `json:"tap,omitempty"`
	MidStream    bool   `json:"mid_stream,omitempty"`
	XffIP        string `json:"xff_ip,omitempty"`
	XffApp       int    `json:"xff_app,omitempty"`
	XffPort      int    `json:"xff_port,omitempty"`
}

// dp session Flags bits (NV defs.h DPSESS_FLAG_*).
const (
	dpSessIngress      = 0x0001 // DPSESS_FLAG_INGRESS
	dpSessTap          = 0x0002 // DPSESS_FLAG_TAP
	dpSessFlagMidStream = 0x0004 // DPSESS_FLAG_MID
)

func dpSessionToRow(s *dp.Session, node string) sessionUploadRow {
	row := sessionUploadRow{
		ID:           int64(s.ID),
		Node:         node,
		EtherType:    int(s.EtherType),
		IPProto:      int(s.IPProto),
		Application:  int(s.Application),
		ClientPort:   int(s.ClientPort),
		ServerPort:   int(s.ServerPort),
		ICMPCode:     int(s.ICMPCode),
		ICMPType:     int(s.ICMPType),
		ClientPkts:   int64(s.ClientPkts),
		ServerPkts:   int64(s.ServerPkts),
		ClientBytes:  int64(s.ClientBytes),
		ServerBytes:  int64(s.ServerBytes),
		ClientAsmPkts:  int64(s.ClientAsmPkts),
		ServerAsmPkts:  int64(s.ServerAsmPkts),
		ClientAsmBytes: int64(s.ClientAsmBytes),
		ServerAsmBytes: int64(s.ServerAsmBytes),
		ClientState:  int(s.ClientState),
		ServerState:  int(s.ServerState),
		Idle:         int(s.Idle),
		Age:          int(s.Age),
		Life:         int(s.Life),
		ThreatID:     int64(s.ThreatID),
		PolicyID:     int64(s.PolicyID),
		PolicyAction: int(s.PolicyAction),
		Severity:     int(s.Severity),
		Ingress:      s.Flags&dpSessIngress != 0,
		Tap:          s.Flags&dpSessTap != 0,
		MidStream:    s.Flags&dpSessFlagMidStream != 0,
		XffApp:       int(s.XffApp),
		XffPort:      int(s.XffPort),
	}
	if s.EPMAC != nil {
		row.EPMAC = strings.ToLower(s.EPMAC.String())
	}
	if s.ClientMAC != nil {
		row.ClientMAC = strings.ToLower(s.ClientMAC.String())
	}
	if s.ServerMAC != nil {
		row.ServerMAC = strings.ToLower(s.ServerMAC.String())
	}
	if s.ClientIP != nil {
		row.ClientIP = s.ClientIP.String()
	}
	if s.ServerIP != nil {
		row.ServerIP = s.ServerIP.String()
	}
	if s.XffIP != nil {
		row.XffIP = s.XffIP.String()
	}
	return row
}

// sessionUploadLoop ticks every `interval`, snapshots the session cache, and
// uploads the full table. An empty snapshot is still uploaded (as an empty
// batch is skipped) — but a node with zero sessions simply lets its rows go
// stale and GC out on the server, so we skip empty uploads to save a round-trip.
func sessionUploadLoop(
	ctx context.Context,
	logger *slog.Logger,
	url, token, node string,
	interval time.Duration,
	sup *dp.Supervisor,
	uploaded, dropped *atomic.Uint64,
) {
	if sup == nil || sup.Sessions() == nil {
		return
	}
	client := sharedUploadClient
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var weakTLSApplied *bool // last value pushed to dp; nil until first apply
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sessions := sup.Sessions().List()
			if len(sessions) == 0 {
				continue
			}
			batch := make([]sessionUploadRow, 0, len(sessions))
			for _, s := range sessions {
				batch = append(batch, dpSessionToRow(s, node))
			}
			resp, err := postSessionBatch(ctx, client, url, token, batch)
			if err != nil {
				logger.Warn("session upload failed; dropping snapshot",
					slog.Int("sessions", len(batch)), slog.String("err", err.Error()))
				dropped.Add(uint64(len(batch)))
				continue
			}
			uploaded.Add(uint64(len(batch)))
			// NV session-kill: the control plane returns any session ids an operator
			// asked to terminate; issue dp ctrl_clear_session for each.
			for _, id := range resp.Kill {
				if err := sup.ClearSession(id); err != nil {
					logger.Warn("session kill failed", slog.Uint64("id", uint64(id)), slog.String("err", err.Error()))
				} else {
					logger.Info("session killed via dp ctrl_clear_session", slog.Uint64("id", uint64(id)))
				}
			}
			// Apply the cluster's weak-TLS detection toggle live (only when it changes).
			if weakTLSApplied == nil || *weakTLSApplied != resp.WeakTLS {
				if err := sup.SetWeakTLSDetection(resp.WeakTLS); err != nil {
					logger.Warn("set weak-TLS detection failed", slog.Bool("enable", resp.WeakTLS), slog.String("err", err.Error()))
				} else {
					v := resp.WeakTLS
					weakTLSApplied = &v
					logger.Info("weak-TLS detection applied", slog.Bool("enabled", resp.WeakTLS))
				}
			}
		}
	}
}

type sessionUploadResp struct {
	Accepted int      `json:"accepted"`
	Kill     []uint32 `json:"kill"`
	WeakTLS  bool     `json:"weak_tls"`
}

// postSessionBatch uploads the snapshot and returns the server's response (kill ids +
// the weak-TLS toggle).
func postSessionBatch(ctx context.Context, client *http.Client, url, token string, batch []sessionUploadRow) (*sessionUploadResp, error) {
	body, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	delays := []time.Duration{0, 200 * time.Millisecond, 800 * time.Millisecond}
	var lastErr error
	for _, delay := range delays {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("new request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var parsed sessionUploadResp
			_ = json.Unmarshal(respBody, &parsed)
			return &parsed, nil
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return nil, fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
		lastErr = fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if lastErr == nil {
		lastErr = errors.New("unknown session upload failure")
	}
	return nil, lastErr
}
