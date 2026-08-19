// Wave 9b: Prometheus /metrics endpoint for the runtime-agent.
//
// We render the text exposition format (https://prometheus.io/docs/instrumenting/
// exposition_formats/) directly so we don't pull in the prometheus client lib.
// All counters come from the same atomic.Uint64 values that already drive the
// 5-second heartbeat JSON; this endpoint just packages them so Prometheus
// can scrape every node on a fixed cadence.
//
// The endpoint mounts at /metrics on the same HTTP server health.go owns.
// Operators point a ServiceMonitor / PodMonitor at port 9404 and target the
// runtime-agent DaemonSet.
package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// metricsSource bundles every atomic counter we expose. Built in main() and
// handed to the metrics handler via closure — keeping main()'s vars private.
type metricsSource struct {
	Node string

	// BPF event-stream counters
	NExec      *atomic.Uint64
	NFile      *atomic.Uint64
	NTotal     *atomic.Uint64
	NUploaded  *atomic.Uint64
	NDropped   *atomic.Uint64
	BPFDropped func() uint64

	// dp-event lane counters
	NDPConn        *atomic.Uint64
	NDPThreat      *atomic.Uint64
	NDPKeepAlive   *atomic.Uint64
	NDPOther       *atomic.Uint64
	NFlowsUploaded *atomic.Uint64
	NFlowsDropped  *atomic.Uint64
	// NFlowsDroppedFull counts flows dropped because the shared flowOut
	// channel was full at enqueue time (backpressure from a slow upload
	// lane), distinct from NFlowsDropped which counts upload-failure drops.
	NFlowsDroppedFull *atomic.Uint64
	NThreatsUploaded  *atomic.Uint64
	NThreatsDropped   *atomic.Uint64

	// DNSSnoopUp is 1 while the AF_PACKET DNS snoop loop is running, 0 once
	// it exits (fatal recv error or shutdown). Exposed so operators can alarm
	// on the FQDN resolver feeder going dark.
	DNSSnoopUp *atomic.Uint64

	// dp supervisor stats — pulled live via Stats()
	DPSup *dp.Supervisor
}

// metricsHandler renders the text exposition format. Cheap — every counter
// is an atomic Load. We write directly to the ResponseWriter; no buffering.
func metricsHandler(m *metricsSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var sb strings.Builder

		nodeLabel := fmt.Sprintf("node=%q", m.Node)

		emitCounter(&sb, "constellation_runtime_agent_bpf_events_total",
			"BPF events observed by the agent since start.", nodeLabel,
			map[string]uint64{
				"exec": m.NExec.Load(),
				"file": m.NFile.Load(),
			})
		emitGauge(&sb, "constellation_runtime_agent_events_total",
			"Total events emitted to /events:bulk.", nodeLabel, m.NTotal.Load())
		emitCounter(&sb, "constellation_runtime_agent_events_uploaded_total",
			"Events successfully uploaded to the control plane.", nodeLabel,
			map[string]uint64{"path": m.NUploaded.Load()})
		emitCounter(&sb, "constellation_runtime_agent_events_dropped_total",
			"Events dropped due to upload failure or full buffer.", nodeLabel,
			map[string]uint64{"path": m.NDropped.Load()})
		emitGauge(&sb, "constellation_runtime_agent_bpf_ringbuf_dropped_total",
			"Records the kernel BPF ringbuf dropped because userspace was slow.",
			nodeLabel, m.BPFDropped())

		// dp lane
		emitCounter(&sb, "constellation_runtime_agent_dp_events_total",
			"dp events decoded by the supervisor, by kind.", nodeLabel,
			map[string]uint64{
				"connection": m.NDPConn.Load(),
				"threat":     m.NDPThreat.Load(),
				"keepalive":  m.NDPKeepAlive.Load(),
				"other":      m.NDPOther.Load(),
			})
		emitCounter(&sb, "constellation_runtime_agent_flows_uploaded_total",
			"Flow rows successfully POSTed to /network-flows:bulk.", nodeLabel,
			map[string]uint64{"path": m.NFlowsUploaded.Load()})
		emitCounter(&sb, "constellation_runtime_agent_flows_dropped_total",
			"Flow rows dropped due to upload failure or full buffer.", nodeLabel,
			map[string]uint64{
				"path":        m.NFlowsDropped.Load(),
				"buffer_full": m.NFlowsDroppedFull.Load(),
			})
		emitCounter(&sb, "constellation_runtime_agent_threats_uploaded_total",
			"Threat rows successfully POSTed to /runtime-threats:bulk.", nodeLabel,
			map[string]uint64{"path": m.NThreatsUploaded.Load()})
		emitCounter(&sb, "constellation_runtime_agent_threats_dropped_total",
			"Threat rows dropped due to upload failure or full buffer.", nodeLabel,
			map[string]uint64{"path": m.NThreatsDropped.Load()})

		if m.DNSSnoopUp != nil {
			emitGauge(&sb, "constellation_runtime_agent_dns_snoop_up",
				"1 while the AF_PACKET DNS snoop (FQDN resolver feeder) is running, else 0.",
				nodeLabel, m.DNSSnoopUp.Load())
		}

		// dp supervisor health (only when dp is enabled)
		if m.DPSup != nil {
			life, ipcStats, ka, taps := m.DPSup.Stats()
			emitCounter(&sb, "constellation_runtime_agent_dp_lifecycle_total",
				"dp subprocess lifecycle counters.", nodeLabel,
				map[string]uint64{
					"starts":  life.StartCount,
					"exits":   life.ExitCount,
					"crashes": life.CrashCount,
				})
			emitCounter(&sb, "constellation_runtime_agent_dp_ipc_total",
				"dp IPC datagram counters.", nodeLabel,
				map[string]uint64{
					"rx":          ipcStats.RxTotal,
					"rx_dropped":  ipcStats.RxDrop,
					"bad_header":  ipcStats.RxBadHdr,
					"bad_payload": ipcStats.RxBadPL,
				})
			emitCounter(&sb, "constellation_runtime_agent_dp_keepalive_total",
				"dp keepalive request/reply counters.", nodeLabel,
				map[string]uint64{
					"sent":    ka.Sent,
					"replied": ka.Replied,
					"timeout": ka.Timeout,
					"errors":  ka.Errors,
				})
			emitGauge(&sb, "constellation_runtime_agent_dp_taps_current",
				"Active dp AF_PACKET taps on this node.", nodeLabel,
				uint64(taps.CurrentTaps))
			emitCounter(&sb, "constellation_runtime_agent_dp_taps_total",
				"Lifetime dp tap add / remove / error counters.", nodeLabel,
				map[string]uint64{
					"added":   taps.Added,
					"removed": taps.Removed,
					"errors":  taps.Errors,
				})
		}

		_, _ = w.Write([]byte(sb.String()))
	}
}

// emitCounter writes one HELP/TYPE pair followed by one line per (variant, value).
// variants is a {label_value: number} map; the metric gets a "result" label so
// scrapes can break down dropped vs uploaded vs other shapes.
func emitCounter(sb *strings.Builder, name, help, nodeLabel string, variants map[string]uint64) {
	fmt.Fprintf(sb, "# HELP %s %s\n", name, help)
	fmt.Fprintf(sb, "# TYPE %s counter\n", name)
	for k, v := range variants {
		fmt.Fprintf(sb, "%s{%s,result=%q} %d\n", name, nodeLabel, k, v)
	}
}

// emitGauge writes a single-value gauge (current state, not cumulative).
func emitGauge(sb *strings.Builder, name, help, nodeLabel string, value uint64) {
	fmt.Fprintf(sb, "# HELP %s %s\n", name, help)
	fmt.Fprintf(sb, "# TYPE %s gauge\n", name)
	fmt.Fprintf(sb, "%s{%s} %d\n", name, nodeLabel, value)
}
