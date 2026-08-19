package forensics

import (
	"encoding/json"
	"time"
)

// RuntimeArtifacts is the v2 forensic-snapshot extension that carries the artifacts
// the runtime agent's quarantine collector produces (pcap, procfs, manifest hash).
// It rides inside the existing Envelope.Annotations as JSON so older readers can
// still parse the snapshot.
type RuntimeArtifacts struct {
	ManifestSHA256 string            `json:"manifest_sha256"`
	TarballPath    string            `json:"tarball_path,omitempty"`
	TarballBytes   int64             `json:"tarball_bytes,omitempty"`
	Components     []string          `json:"components,omitempty"` // pcap, proc, logs, netpolicy
	Trigger        RuntimeTrigger    `json:"trigger,omitempty"`
	Target         RuntimeTarget     `json:"target,omitempty"`
	CapturedAt     time.Time         `json:"captured_at,omitempty"`
}

// RuntimeTrigger mirrors quarantine.Trigger (kept here so pkg/forensics has no
// dependency on internal/runtime).
type RuntimeTrigger struct {
	Source   string `json:"source"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
}

// RuntimeTarget mirrors quarantine.Target.
type RuntimeTarget struct {
	Namespace   string `json:"namespace"`
	Pod         string `json:"pod"`
	WorkloadID  string `json:"workload_id"`
	ContainerID string `json:"container_id"`
	PID         int    `json:"pid"`
}

// EncodeRuntimeArtifacts marshals `a` into a JSON string suitable for
// Envelope.Annotations["runtime"]. The caller adds it to the envelope before Capture.
func EncodeRuntimeArtifacts(a RuntimeArtifacts) string {
	b, err := json.Marshal(a)
	if err != nil {
		return ""
	}
	return string(b)
}

// DecodeRuntimeArtifacts pulls the runtime-artifacts subdocument out of an
// envelope's Annotations map. Returns (nil, false) when absent.
func DecodeRuntimeArtifacts(env *Envelope) (*RuntimeArtifacts, bool) {
	if env == nil || env.Annotations == nil {
		return nil, false
	}
	raw, ok := env.Annotations["runtime"]
	if !ok || raw == "" {
		return nil, false
	}
	var a RuntimeArtifacts
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return nil, false
	}
	return &a, true
}
