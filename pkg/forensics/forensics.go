// Package forensics captures pod-level forensic snapshots when a workload is quarantined
// or hits a critical alert. v1 is **kernel-free** — we use the K8s API for events + log
// tails + pod spec, and the runtime agent's NetworkFlow stream for recent flows. This
// gives 80% of the IR value without needing eBPF/pcap.
//
// Snapshot envelope (gzipped JSON, stored in forensics_snapshots.payload_gzip):
//
//	{
//	  "kind": "ConstellationForensicSnapshot/v1",
//	  "captured_at": "2026-05-12T18:00:00Z",
//	  "pod": { ...K8s PodSpec... },
//	  "events": [ {time, reason, message, source}, ... ],
//	  "logs":   { "container-a": ["...last 1000 lines..."] },
//	  "flows":  [ {peer, port, proto, count}, ... ]
//	}
package forensics

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Envelope is the v1 snapshot shape.
type Envelope struct {
	Kind        string                  `json:"kind"`
	CapturedAt  time.Time               `json:"captured_at"`
	Trigger     string                  `json:"trigger"`
	Pod         json.RawMessage         `json:"pod,omitempty"`
	Events      []Event                 `json:"events,omitempty"`
	Logs        map[string][]string     `json:"logs,omitempty"` // container → lines
	Flows       []Flow                  `json:"flows,omitempty"`
	Annotations map[string]string       `json:"annotations,omitempty"`
}

// Event is a K8s Event projection.
type Event struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`    // Normal | Warning
	Reason  string    `json:"reason"`
	Message string    `json:"message"`
	Source  string    `json:"source"`
}

// Flow is a NetworkFlow projection.
type Flow struct {
	Peer     string `json:"peer"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Count    int    `json:"count"`
}

// Capture builds an Envelope from the caller-supplied inputs + gzips it. Returns
// (gzipped bytes, sha256 hex, error).
func Capture(env Envelope) ([]byte, string, error) {
	env.Kind = "ConstellationForensicSnapshot/v1"
	if env.CapturedAt.IsZero() {
		env.CapturedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, "", err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		return nil, "", err
	}
	if err := gz.Close(); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

// Restore decompresses + parses an envelope. Useful when serving snapshots from the API.
func Restore(gz []byte) (*Envelope, error) {
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		return nil, err
	}
	return &env, nil
}
