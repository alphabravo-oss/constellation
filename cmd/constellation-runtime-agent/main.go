// constellation-runtime-agent is the kernel data-plane DaemonSet binary that runs on
// every node and observes exec / network / file events via the eBPF agent in
// internal/runtime/ebpf.
//
// Events flow:
//
//	BPF ringbuf  -> ebpf.Agent -> per-event batch buffer -> POST /api/v1/events:bulk
//	                                       \-> stdout heartbeat (kubectl logs friendly)
//
// The batch buffer flushes whenever it reaches BATCH_SIZE events or BATCH_INTERVAL
// elapses (whichever happens first), then POSTs the array as JSON to the control-plane
// at $CONSTELLATION_API_URL/api/v1/events:bulk with Bearer $RUNTIME_AGENT_TOKEN.
//
// The POST is retried with exponential backoff up to 3 times (100ms, 400ms, 1.6s). After
// the final failure the batch is dropped and the agent's `dropped` counter is bumped, so
// operators can alarm on `constellation_runtime_agent_dropped_total > 0`.
//
// Configuration env vars (* required for upload):
//
//	CONSTELLATION_BPF_OBJ        path to runtime.bpf.o (default /opt/constellation/runtime.bpf.o)
//	CONSTELLATION_API_URL    *   control-plane base URL (e.g. http://constellation-api:8080)
//	RUNTIME_AGENT_TOKEN      *   Bearer token issued by handler.IssueRuntimeAgentToken
//	CONSTELLATION_BATCH_SIZE     events per batch (default 200; cap 1000 -- handler limit)
//	CONSTELLATION_BATCH_INTERVAL flush even if batch under-full (default 2s)
//	CONSTELLATION_NODE_NAME      node label attached to every emitted record (default $HOSTNAME)
//	CONSTELLATION_LOG_EVERY      emit a one-line summary every N events (default 50)
//	CONSTELLATION_HUBBLE_RELAY_ADDR  Hubble relay address (host:port) for the NET-3
//	                             Cilium flow lane; only used when the detected CNI is cilium
//
// When CONSTELLATION_API_URL or RUNTIME_AGENT_TOKEN are unset the agent runs in
// "stdout-only" mode (the H2 behavior): events are encoded as JSON to stdout, no HTTP.
//
// Exit codes:
//   - 0 on graceful shutdown (SIGINT/SIGTERM)
//   - 2 if the eBPF agent fails to come up (kernel/BTF missing, no permissions, …)
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
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/internal/runtime/ebpf"
	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
	"github.com/alphabravocompany/constellation/pkg/version"
)

// maxInFlightUploads bounds the number of concurrent POST goroutines a single
// upload loop may spawn. A slow control-plane used to leak one goroutine (and
// its batch) per flush; the loops now block briefly for a slot instead, applying
// backpressure rather than growing unbounded.
const maxInFlightUploads = 4

// sharedUploadClient is the single keep-alive HTTP client reused by every upload
// loop (events, flows, threats). One tuned Transport with a pooled connection
// set beats one fresh client per loop: idle connections to the control plane are
// reused instead of reopened per batch.
var sharedUploadClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: obslog.Level()}))
	slog.SetDefault(logger)

	node := getenv("CONSTELLATION_NODE_NAME", os.Getenv("HOSTNAME"))
	if node == "" {
		node = "unknown"
	}
	logEvery, _ := strconv.Atoi(getenv("CONSTELLATION_LOG_EVERY", "50"))
	if logEvery <= 0 {
		logEvery = 50
	}
	batchSize, _ := strconv.Atoi(getenv("CONSTELLATION_BATCH_SIZE", "200"))
	if batchSize <= 0 || batchSize > 1000 {
		batchSize = 200
	}
	batchIntervalMs, _ := strconv.Atoi(getenv("CONSTELLATION_BATCH_INTERVAL_MS", "2000"))
	if batchIntervalMs <= 0 {
		batchIntervalMs = 2000
	}
	apiURL := strings.TrimRight(os.Getenv("CONSTELLATION_API_URL"), "/")
	apiToken := os.Getenv("RUNTIME_AGENT_TOKEN")
	clusterID := strings.TrimSpace(os.Getenv("CONSTELLATION_CLUSTER_ID"))
	clusterName := strings.TrimSpace(os.Getenv("CONSTELLATION_CLUSTER_NAME"))
	workloads := newWorkloadResolver()
	// Non-overridable enforcement guard: the agent's own namespace, the kube-system
	// family, and the host can never be blocked/killed by any enforcer, no matter
	// what rule an operator writes. Operators may only ADD namespaces via
	// CONSTELLATION_ENFORCEMENT_PROTECTED_NAMESPACES.
	protectedNS := newProtectedSetFromEnv(os.Getenv("CONSTELLATION_POD_NAMESPACE"))

	// API URL set but token is empty == we're inside the bootstrap race
	// window. bootstrap-job creates the runtime-agent-token Secret as a
	// Helm post-install hook, which only runs AFTER the DaemonSet pod
	// is Ready. So at first-boot the secret might not exist yet — but
	// the chart also mounts the same Secret as a file (the kubelet
	// auto-updates file-mounted secrets when they change), so we wait
	// on the file path. Env-var-from-secret can't be re-read once the
	// process is running; file mount can. Without this the agent would
	// silently drop events/flows/threats/host-facts forever.
	if apiURL != "" && apiToken == "" {
		const (
			tokenFile   = "/var/run/secrets/constellation/runtime-agent-token"
			pollEvery   = 2 * time.Second
			pollTimeout = 5 * time.Minute
		)
		logger.Info("runtime-agent: waiting for token at mounted secret file",
			slog.String("file", tokenFile),
			slog.Duration("timeout", pollTimeout),
		)
		apiToken = waitForToken(tokenFile, pollEvery, pollTimeout, logger)
	}
	uploadEnabled := apiURL != "" && apiToken != ""

	logger.Info("runtime-agent: starting",
		slog.String("node", node),
		slog.String("bpf_obj", os.Getenv("CONSTELLATION_BPF_OBJ")),
		slog.Int("log_every", logEvery),
		slog.Int("batch_size", batchSize),
		slog.Int("batch_interval_ms", batchIntervalMs),
		slog.Bool("upload_enabled", uploadEnabled),
		slog.String("api_url", apiURL),
	)
	version.LogStartup(logger, "runtime-agent")

	// Wave 7: BPF observes exec + file only. The NeuVector dp data-plane
	// owns the network path end-to-end (Wave 4 wired DPMsgConnect into
	// /api/v1/network-flows:bulk, retiring the synthetic byte-estimator that
	// used to ride tcp_connect / inet_csk_accept kprobes).
	a, err := ebpf.New(ebpf.Options{
		Logger:             logger,
		AttachExec:         true,
		AttachFile:         true,
		EventChannelBuffer: 4096,
	})
	if err != nil {
		logger.Error("ebpf agent New failed", slog.String("err", err.Error()))
		os.Exit(2)
	}
	defer a.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- a.Run(ctx) }()

	// Wave 2: the vendored NeuVector C data-plane. Enabled when
	// CONSTELLATION_DP_ENABLED=true. Provides real bytes / packets / sessions
	// per (EPMAC, 5-tuple, policy_id) plus L7 from DPI parsers and threat
	// signatures — replacing the connect-event byte estimator in flowAggregator.
	// Wave 2 stops at "log the decoded events"; Wave 4 promotes them into
	// flowIngestRow / threat rows for the API.
	var (
		dpSup          *dp.Supervisor
		dpEvents       <-chan dp.Event
		nDPConn        atomic.Uint64
		nDPThreat      atomic.Uint64
		nDPKeepAlive   atomic.Uint64
		nDPOther       atomic.Uint64
		cniName        string
		cniNFQueueSafe bool
	)
	if strings.EqualFold(os.Getenv("CONSTELLATION_DP_ENABLED"), "true") {
		threads, _ := strconv.Atoi(os.Getenv("CONSTELLATION_DP_THREADS"))
		// Wave D1 / A4: detect CNI at startup so we can refuse to set up
		// NFQUEUE-based enforcement on Cilium clusters (where the eBPF
		// data plane bypasses iptables and our rules would silently
		// no-op). Auto-discovery walks every well-known CNI config path
		// (kubeadm, k3s, RKE2, OpenShift OVN, microk8s — see
		// pkg/runtime/dp/cnidetect.CandidateCNIDirs) when the env var is
		// unset. Set CONSTELLATION_CNI_DIR to pin the lookup to a single
		// directory (fixture-based dev or a non-standard install).
		cniDir := os.Getenv("CONSTELLATION_CNI_DIR") // empty == auto-discovery
		cni := dp.DetectCNI(cniDir)
		cniName = cni.Name
		cniNFQueueSafe = cni.SafeForNFQUEUE()
		logger.Info("dp: CNI detected",
			slog.String("name", cni.Name),
			slog.String("source", cni.Source),
			slog.Bool("nfqueue_safe", cni.SafeForNFQUEUE()))
		// CONSTELLATION_DP_ENFORCE_ON_CILIUM=true overrides the safety
		// gate for operators who know what they're doing (eg. they've
		// set up Cilium iptables-only mode).
		enforceOnCilium := strings.EqualFold(os.Getenv("CONSTELLATION_DP_ENFORCE_ON_CILIUM"), "true")
		// Inline (NFQUEUE) enforcement activates ONLY when explicitly gated AND the
		// CNI is NFQUEUE-safe (or the operator overrode it on Cilium). Default OFF:
		// the whole verdict-capable datapath stays dormant and every workload is on
		// the TAP mirror path, so nothing is intercepted inline by accident.
		enforceActive := envTruthy(os.Getenv("CONSTELLATION_DP_ENFORCE")) && (cniNFQueueSafe || enforceOnCilium)
		tapProvider := selectTapProvider(logger, enforceActive)
		enforceProvider := selectEnforceProvider(tapProvider, enforceActive, logger)
		if enforceProvider != nil {
			logger.Info("dp: inline enforcement ENABLED (per-workload, label-scoped)",
				slog.Bool("nfqueue_safe", cniNFQueueSafe), slog.Bool("cilium_override", enforceOnCilium))
		}

		dpSup = dp.New(dp.Options{
			Logger:          logger,
			Binary:          getenv("CONSTELLATION_DP_BIN", dp.DefaultBinary),
			Threads:         threads, // 0 → defaults to 1 inside dp.New
			TapInterface:    os.Getenv("CONSTELLATION_DP_TAP_IFACE"),
			NoTC:            strings.EqualFold(os.Getenv("CONSTELLATION_DP_NOTC"), "true"),
			TapProvider:     tapProvider,
			EnforceProvider: enforceProvider, // nil unless enforceActive → inline path dormant by default
		})
		dpEvents = dpSup.Events()
		go func() {
			if err := dpSup.Start(ctx); err != nil {
				logger.Error("dp supervisor: stopped with error", slog.String("err", err.Error()))
			}
		}()
	}

	// Counters feed stdout summaries, /metrics, and component heartbeat
	// diagnostics. Keep them in one source so the API and local probes agree.
	var (
		nExec     atomic.Uint64
		nFile     atomic.Uint64
		nTotal    atomic.Uint64
		nUploaded atomic.Uint64
		nDropped  atomic.Uint64

		nFlowsUploaded    atomic.Uint64
		nFlowsDropped     atomic.Uint64
		nFlowsDroppedFull atomic.Uint64

		nThreatsUploaded atomic.Uint64
		nThreatsDropped  atomic.Uint64

		nSessionsUploaded atomic.Uint64
		nSessionsDropped  atomic.Uint64

		nDNSSnoopUp atomic.Uint64
	)
	metrics := &metricsSource{
		Node:              node,
		NExec:             &nExec,
		NFile:             &nFile,
		NTotal:            &nTotal,
		NUploaded:         &nUploaded,
		NDropped:          &nDropped,
		BPFDropped:        a.Dropped,
		NDPConn:           &nDPConn,
		NDPThreat:         &nDPThreat,
		NDPKeepAlive:      &nDPKeepAlive,
		NDPOther:          &nDPOther,
		NFlowsUploaded:    &nFlowsUploaded,
		NFlowsDropped:     &nFlowsDropped,
		NFlowsDroppedFull: &nFlowsDroppedFull,
		NThreatsUploaded:  &nThreatsUploaded,
		NThreatsDropped:   &nThreatsDropped,
		DNSSnoopUp:        &nDNSSnoopUp,
		DPSup:             dpSup,
	}

	// Wave N6: heartbeat goroutine — reuses the runtime-agent-token so the
	// API can attribute heartbeats to this org without a separate credential.
	if uploadEnabled {
		go version.HeartbeatLoop(ctx, version.HeartbeatConfig{
			APIBaseURL:  apiURL,
			Token:       apiToken,
			Component:   "runtime-agent",
			ClusterID:   clusterID,
			ClusterName: clusterName,
			Logger:      logger,
			MetadataFn: func() any {
				return runtimeAgentHeartbeatMetadata(metrics, runtimeAgentHeartbeatOptions{
					UploadEnabled:   uploadEnabled,
					BatchSize:       batchSize,
					BatchIntervalMS: batchIntervalMs,
					ClusterID:       clusterID,
					ClusterName:     clusterName,
					CNIName:         cniName,
					NFQueueSafe:     cniNFQueueSafe,
				})
			},
		})

		// Host-facts reporter: snapshots OS / kernel / modules / CNI / CRI
		// every CONSTELLATION_HOSTSCAN_INTERVAL (default 5m) and POSTs to
		// /api/v1/host-facts:report. See cmd/.../hostscan_loop.go.
		go hostScanLoop(ctx, hostScanConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			NodeName:   node,
			CNIDir:     os.Getenv("CONSTELLATION_CNI_DIR"),
			Interval:   hostScanIntervalFromEnv(os.Getenv("CONSTELLATION_HOSTSCAN_INTERVAL"), 5*time.Minute),
			HostRoot:   hostScanHostRootFromEnv(),
			Logger:     logger,
		})

		// Host process snapshot (Slice B). Snapshots /proc every
		// CONSTELLATION_HOSTSCAN_PROC_INTERVAL (default 1m) and POSTs
		// to /api/v1/host-processes:report. Independent goroutine from
		// hostScanLoop because the cadence is different (processes
		// change quickly; OS facts don't).
		go hostProcessesLoop(ctx, hostProcessesConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			NodeName:   node,
			Interval:   hostScanIntervalFromEnv(os.Getenv("CONSTELLATION_HOSTSCAN_PROC_INTERVAL"), time.Minute),
			HostRoot:   hostScanHostRootFromEnv(),
			MaxItems:   hostProcMaxItemsFromEnv(),
			Logger:     logger,
		})

		// Host container inventory (Slice C). Shells out to crictl on
		// the host's CRI socket every CONSTELLATION_HOSTSCAN_CONT_INTERVAL
		// (default 1m). The crictl binary ships in the agent image.
		go hostContainersLoop(ctx, hostContainersConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			NodeName:   node,
			Interval:   hostScanIntervalFromEnv(os.Getenv("CONSTELLATION_HOSTSCAN_CONT_INTERVAL"), time.Minute),
			HostRoot:   hostScanHostRootFromEnv(),
			Logger:     logger,
			OnSnapshot: workloads.Update,
		})

		// Running workload package evidence. Reads package databases through
		// each running container's /proc/<pid>/root and posts workload-scoped
		// scan evidence for scanner workers to match with VulnDB.
		go workloadPackagesLoop(ctx, workloadPackagesConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			NodeName:   node,
			ClusterID:  clusterID,
			Interval:   hostScanIntervalFromEnv(os.Getenv("CONSTELLATION_HOSTSCAN_CONTAINER_PKG_INTERVAL"), 15*time.Minute),
			HostRoot:   hostScanHostRootFromEnv(),
			Logger:     logger,
		})

		// Host package inventory (Slice D.1). Reads dpkg/rpm/apk natively
		// every CONSTELLATION_HOSTSCAN_PKG_INTERVAL (default 1h).
		go hostPackagesLoop(ctx, hostPackagesConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			NodeName:   node,
			Interval:   hostScanIntervalFromEnv(os.Getenv("CONSTELLATION_HOSTSCAN_PKG_INTERVAL"), time.Hour),
			HostRoot:   hostScanHostRootFromEnv(),
			Logger:     logger,
		})

		// Host CIS benchmark (Slice E). In-tree native check set,
		// no shell-out. Runs every CONSTELLATION_HOSTSCAN_CIS_INTERVAL
		// (default 6h — host hardening drifts slowly).
		go hostCISLoop(ctx, hostCISConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			NodeName:   node,
			Interval:   hostScanIntervalFromEnv(os.Getenv("CONSTELLATION_HOSTSCAN_CIS_INTERVAL"), 6*time.Hour),
			HostRoot:   hostScanHostRootFromEnv(),
			Logger:     logger,
		})
	}

	// Upload goroutine — single writer; events are pushed onto `toUpload` channel.
	var toUpload chan ingestEvent
	if uploadEnabled {
		toUpload = make(chan ingestEvent, batchSize*4)
		go uploadLoop(ctx, logger, withClusterID(apiURL+"/api/v1/events:bulk", clusterID), apiToken, batchSize,
			time.Duration(batchIntervalMs)*time.Millisecond, toUpload, &nUploaded, &nDropped)
	}

	// Network-flows lane: every dp.EventConnection becomes one row on this
	// channel; flowUploadLoop POSTs batches to /api/v1/network-flows:bulk.
	// The synthetic BPF aggregator that used to feed this is gone — dp's
	// on-wire DPI metrics are the only source now (Wave 7).
	var flowOut chan flowIngestRow
	// Wave 5: separate upload channel for DPI threats from dp. Threats are
	// much lower volume than flows but each row carries up to ~2KB of
	// captured packet bytes, so the buffer is smaller and the batch cap on
	// the wire is lower.
	var threatOut chan threatIngestRow

	if uploadEnabled {
		flowOut = make(chan flowIngestRow, 8192)

		go flowUploadLoop(ctx, logger, apiURL+"/api/v1/network-flows:bulk", apiToken,
			200, 5*time.Second, flowOut, &nFlowsUploaded, &nFlowsDropped)

		// Wave 5: threat upload. Only starts when dp is enabled — the BPF
		// path doesn't produce DPI threat detections.
		if dpSup != nil {
			threatOut = make(chan threatIngestRow, 256)
			go threatUploadLoop(ctx, logger, apiURL+"/api/v1/runtime-threats:bulk", apiToken,
				50, 5*time.Second, threatOut, &nThreatsUploaded, &nThreatsDropped)

			// Live-session lane (NV RESTSession): periodically snapshot dp's
			// ctrl_list_session cache and upload the whole table so the console
			// shows current connections. Snapshot, not stream — dp already keeps
			// the authoritative cache.
			go sessionUploadLoop(ctx, logger, apiURL+"/api/v1/network-sessions:bulk", apiToken,
				node, 15*time.Second, dpSup.Sessions(), &nSessionsUploaded, &nSessionsDropped)
		}

		// NET-3: Hubble lane. On Cilium clusters the dp/iptables datapath is
		// structurally blind (cnidetect.SafeForNFQUEUE()==false), so when a
		// Hubble relay address is configured we stream flows from the relay's
		// observer API through hubbleStreamLoop -> the same flowOut channel.
		// The gate ("Cilium detected AND relay addr set") is live here; the
		// concrete observer client (cilium gRPC dep) is the remaining piece —
		// see the DEPENDENCY CEILING note on hubbleObserver in hubble_flow.go.
		if hub := hubbleEnabled(cniName, os.Getenv("CONSTELLATION_HUBBLE_RELAY_ADDR")); hub.Enabled {
			logger.Info("hubble: lane enabled (Cilium + relay configured)",
				slog.String("relay_addr", hub.RelayAddr))
			// The concrete observer client (hubble_client.go) dials the
			// relay over gRPC and streams flows; hubbleStreamLoop drains
			// them through the converter onto the shared flowOut channel,
			// mirroring the dp lane's start above.
			obs := newHubbleRelayClient(hub.RelayAddr, logger)
			go hubbleStreamLoop(ctx, logger, obs, node, flowOut, &nFlowsUploaded, &nFlowsDropped)
		}
	}

	// File-profile rule sync is independent of the NeuVector DP process.
	// Rule sync feeds watched-file inventory and the fanotify permission
	// enforcer used for enforce-mode block_access rules.
	// procEnforcer is consulted inline in the exec event loop below; nil-safe so
	// it no-ops when upload is disabled or the enforcer isn't constructed.
	var procEnforcer *processEnforcer
	if uploadEnabled {
		fileEnforcementStatus := newFileProfileEnforcementStatusStore()
		fileRulesWorker := NewFileProfileRuleSyncWorker(FileProfileRuleSyncConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			ClusterID:  clusterID,
			Node:       node,
			Logger:     logger,
			DPSup:      dpSup,
		})
		go fileRulesWorker.Run(ctx)
		go fileProfileFilesLoop(ctx, fileProfileFilesConfig{
			APIBaseURL:        apiURL,
			Token:             apiToken,
			NodeName:          node,
			ClusterID:         clusterID,
			Interval:          hostScanIntervalFromEnv(os.Getenv("CONSTELLATION_FILE_PROFILE_SCAN_INTERVAL"), time.Minute),
			HostRoot:          hostScanHostRootFromEnv(),
			Logger:            logger,
			RuleSync:          fileRulesWorker,
			EnforcementStatus: fileEnforcementStatus,
		})
		// Process-baseline sync — created here (before the exec enforcer) so it can
		// serve as the exec enforcer's learn-first gate as well as the process
		// enforcer's kill decision. Shared by both.
		procBaselineWorker := NewProcessBaselineSyncWorker(ProcessBaselineSyncConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			ClusterID:  clusterID,
			Node:       node,
			Logger:     logger,
			DPSup:      dpSup,
		})
		go procBaselineWorker.Run(ctx)

		go fileProfileEnforcerLoop(ctx, fileProfileEnforcerConfig{
			Disabled:  !fileProfileEnforcerEnabledFromEnv(os.Getenv("CONSTELLATION_FILE_PROFILE_ENFORCER")),
			NodeName:  node,
			Interval:  hostScanIntervalFromEnv(os.Getenv("CONSTELLATION_FILE_PROFILE_ENFORCER_INTERVAL"), time.Minute),
			HostRoot:  hostScanHostRootFromEnv(),
			Logger:    logger,
			RuleSync:  fileRulesWorker,
			Workloads: workloads,
			Status:    fileEnforcementStatus,
			Protected: protectedNS,
			Sync:      procBaselineWorker,
			OnDeny: func(event fanotifyDecisionEvent, ruleID string) {
				if toUpload == nil {
					return
				}
				ie := ingestEvent{
					At:                time.Now().UTC(),
					Kind:              "file_open",
					Node:              node,
					WorkloadID:        event.WorkloadID,
					ContainerID:       event.ContainerID,
					PID:               uint32(event.Pid),
					Comm:              event.Comm,
					Path:              event.Path,
					Blocked:           true,
					FileProfileRuleID: ruleID,
				}
				ident := workloads.Resolve(event.ContainerID)
				ie.Namespace = ident.Namespace
				ie.Pod = ident.Pod
				select {
				case toUpload <- ie:
				default:
					nDropped.Add(1)
				}
			},
			// P0-3: pre-exec zero-drift decision (FAN_OPEN_EXEC_PERM). Surfaces the
			// drift to the server; Blocked reflects whether it was actually denied
			// (enforce) vs merely observed (monitor). Mirrors OnDeny above.
			OnExecDeny: func(event fanotifyDecisionEvent, reason string, denied bool) {
				if toUpload == nil {
					return
				}
				ie := ingestEvent{
					At:              time.Now().UTC(),
					Kind:            "process_exec",
					Node:            node,
					WorkloadID:      event.WorkloadID,
					ContainerID:     event.ContainerID,
					PID:             uint32(event.Pid),
					Comm:            event.Comm,
					Filename:        event.Path,
					Blocked:         denied,
					ZeroDriftReason: "zero-drift:" + reason,
				}
				ident := workloads.Resolve(event.ContainerID)
				ie.Namespace = ident.Namespace
				ie.Pod = ident.Pod
				select {
				case toUpload <- ie:
				default:
					nDropped.Add(1)
				}
			},
		})

		// B3: host-path File Integrity Monitor. Opt-in (CONSTELLATION_HOST_FIM),
		// monitor-only (FAN_CLASS_NOTIF — physically cannot block). Watches the
		// node's own sensitive paths (/etc, /boot, kubelet PKI) and reports real
		// content modifications (sha256-confirmed) into the same event pipeline.
		go hostFIMLoop(ctx, hostFIMConfig{
			Disabled:     !hostFIMEnabledFromEnv(os.Getenv("CONSTELLATION_HOST_FIM")),
			NodeName:     node,
			HostRoot:     hostScanHostRootFromEnv(),
			Paths:        hostFIMPathsFromEnv(os.Getenv("CONSTELLATION_HOST_FIM_PATHS")),
			Interval:     hostScanIntervalFromEnv(os.Getenv("CONSTELLATION_HOST_FIM_INTERVAL"), time.Minute),
			HashMaxBytes: fileProfileHashMaxBytes(),
			Logger:       logger,
			OnChange: func(ev hostFIMEvent) {
				if toUpload == nil {
					return
				}
				ie := ingestEvent{
					At:     time.Now().UTC(),
					Kind:   "host_file_change",
					Node:   node,
					PID:    uint32(ev.Pid),
					Comm:   ev.Comm,
					Path:   ev.Path,
					Sha256: ev.Sha256,
				}
				select {
				case toUpload <- ie:
				default:
					nDropped.Add(1)
				}
			},
		})

		// Process enforcer (kill-on-exec). DB-backed baseline bundle synced from
		// the api (procBaselineWorker, created above); consulted inline in the exec
		// loop below. Default OFF.
		procEnforcer = newProcessEnforcer(processEnforcerConfig{
			Disabled:  !processEnforcerEnabledFromEnv(os.Getenv("CONSTELLATION_PROCESS_ENFORCER")),
			Sync:      procBaselineWorker,
			Status:    newProcessEnforcementStatusStore(),
			Logger:    logger,
			Protected: protectedNS,
			// P0-4: wiring Workloads activates the already-coded zero-drift path
			// (driftViolation needs the container start time to judge provenance).
			// Without it CONSTELLATION_PROCESS_ZERO_DRIFT is a no-op.
			Workloads: workloads,
			OnKill: func(pid int, workloadID, containerID, comm, filename, reason string) {
				if toUpload == nil {
					return
				}
				ie := ingestEvent{
					At:          time.Now().UTC(),
					Kind:        "process_exec",
					Node:        node,
					WorkloadID:  workloadID,
					ContainerID: containerID,
					PID:         uint32(pid),
					Comm:        comm,
					Filename:    filename,
					Blocked:     true,
				}
				// Preserve the zero-drift reason on an enforce-mode kill (mirrors OnAlert);
				// baseline kills carry reason="baseline" which is not a zero-drift tag.
				if strings.HasPrefix(reason, "zero-drift:") {
					ie.ZeroDriftReason = reason
				}
				ident := workloads.Resolve(containerID)
				ie.Namespace = ident.Namespace
				ie.Pod = ident.Pod
				select {
				case toUpload <- ie:
				default:
					nDropped.Add(1)
				}
			},
			// OnAlert surfaces a monitor-mode zero-drift observation (not killed) to
			// the server, carrying the drift reason. Mirrors OnKill but Blocked=false.
			OnAlert: func(pid int, workloadID, containerID, comm, filename, reason string) {
				if toUpload == nil {
					return
				}
				ie := ingestEvent{
					At:              time.Now().UTC(),
					Kind:            "process_exec",
					Node:            node,
					WorkloadID:      workloadID,
					ContainerID:     containerID,
					PID:             uint32(pid),
					Comm:            comm,
					Filename:        filename,
					ZeroDriftReason: reason,
				}
				ident := workloads.Resolve(containerID)
				ie.Namespace = ident.Namespace
				ie.Pod = ident.Pod
				select {
				case toUpload <- ie:
				default:
					nDropped.Add(1)
				}
			},
		})
	}

	// B4: kill-process / kill-session response actions. Both DEFAULT OFF and
	// independently gated. The pull-poller only runs when at least one is
	// enabled; the server endpoint that emits pending actions is a separate
	// subsystem (see TODO(matrix) in response_actions.go).
	killProcEnabled := responseKillProcessEnabledFromEnv(os.Getenv("CONSTELLATION_RESPONSE_KILL_PROCESS"))
	killSessEnabled := responseKillSessionEnabledFromEnv(os.Getenv("CONSTELLATION_RESPONSE_KILL_SESSION"))
	if uploadEnabled && (killProcEnabled || killSessEnabled) {
		resp := newResponder(responderConfig{
			Node:               node,
			HostRoot:           hostScanHostRootFromEnv(),
			KillProcessEnabled: killProcEnabled,
			KillSessionEnabled: killSessEnabled,
			Workloads:          workloads,
			Logger:             logger,
		})
		respWorker := &responseActionWorker{
			APIBaseURL: apiURL,
			Token:      apiToken,
			ClusterID:  clusterID,
			Node:       node,
			Responder:  resp,
			Logger:     logger,
		}
		logger.Info("responder: enabled",
			slog.Bool("kill_process", killProcEnabled),
			slog.Bool("kill_session", killSessEnabled))
		go respWorker.Run(ctx)
	}

	// Wave C3.5 + C4.5: DP pull-pollers. These depend on dp being up
	// (so we get TapMACs) AND on an API URL + token. Launched as
	// goroutines that run for the supervisor lifetime; failure paths
	// inside the pollers are non-fatal and self-retry on the next tick.
	if dpSup != nil && uploadEnabled {
		dlpWorker := NewDLPSyncWorker(DLPSyncConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			ClusterID:  clusterID,
			Logger:     logger,
			DPSup:      dpSup,
		})
		go dlpWorker.Run(ctx)

		// H6: program dp's per-workload policy engine. Without this poller
		// PushPolicy has no caller and dp enforces against an empty rule table.
		policyWorker := NewRuntimePolicySyncWorker(RuntimePolicySyncConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			ClusterID:  clusterID,
			Logger:     logger,
			DPSup:      dpSup,
		})
		go policyWorker.Run(ctx)

		// FQDN egress: feed snooped DNS responses into the resolver so dp's
		// FQDN→IP table tracks what allowed names actually resolve to. The
		// allow-set itself is supplied by policyWorker.SetAllowedFqdns above.
		go runDNSSnoop(ctx, dpSup, logger, &nDNSSnoopUp)

		pcapWorker := NewPcapWorker(PcapWorkerConfig{
			APIBaseURL: apiURL,
			Token:      apiToken,
			ClusterID:  clusterID,
			Node:       node,
			Logger:     logger,
		})
		go pcapWorker.Run(ctx)
	}

	// Wave 9: liveness + readiness + /metrics HTTP endpoints. /healthz is
	// "process is up"; /readyz is "dp answered a keepalive AND the tap
	// reconciler ran"; /metrics is Prometheus text exposition over all dp +
	// ingest + ebpf counters. All three live on one HTTP server.
	if addr := strings.TrimSpace(os.Getenv("CONSTELLATION_HEALTH_ADDR")); addr != "" {
		go runHealthServer(ctx, logger, addr, dpSup, metrics)
	}

	// stdout JSON encoder — one line per event (kubectl logs friendly).
	enc := json.NewEncoder(os.Stdout)

	// Wave 4: drain decoded dp events and route the connection ones into
	// the network-flows ingest channel. Threats stream to stdout for now
	// (Wave 5 promotes them to a runtime_threats ingest). EventOther and
	// EventKeepAlive remain log-only as before.
	if dpEvents != nil {
		go func() {
			// Push the env-driven flood-meter thresholds (SYN/ICMP/session)
			// to dp the first time each dp instance proves it's up and the
			// ctrl socket is live (first keepalive). Keyed on the supervisor's
			// lifecycle generation rather than a sync.Once: after dp segfaults
			// and the supervisor restarts it, Generation() bumps and the fresh
			// (config-less) instance gets the meter config re-pushed on its
			// first keepalive. Ready() gates the very first push past dp's
			// init race. lastMeterGen is only ever touched by this single
			// dpEvents goroutine, so no synchronisation is needed.
			var lastMeterGen uint64
			pushMeterConfig := func() {
				if !dpSup.Ready() {
					return
				}
				gen := dpSup.Generation()
				if gen == lastMeterGen {
					return
				}
				if err := dpSup.PushMeterConfig(); err != nil {
					logger.Warn("dp meter: push flood-meter config", slog.String("err", err.Error()))
					return
				}
				lastMeterGen = gen
			}
			for ev := range dpEvents {
				switch ev.Kind {
				case dp.EventConnection:
					nDPConn.Add(1)
					if ev.Conn != nil {
						// Push the row to the ingest channel. Non-blocking
						// — if flowOut is full, drop and count, matching the
						// kernel-pump-never-stalls policy elsewhere.
						if flowOut != nil {
							// Wave C1: the supervisor's session cache may
							// have a matching DPMsgSession with the
							// per-direction byte split we want.
							var sess *dp.Session
							if dpSup != nil {
								sess, _ = dpSup.Sessions().Lookup(dp.SessionKey{
									ClientIP:   ev.Conn.ClientIP.String(),
									ServerIP:   ev.Conn.ServerIP.String(),
									ClientPort: ev.Conn.ClientPort,
									ServerPort: ev.Conn.ServerPort,
									IPProto:    ev.Conn.IPProto,
								})
							}
							row := dpConnToFlowIngest(ev, node, sess)
							select {
							case flowOut <- row:
							default:
								nFlowsDroppedFull.Add(1)
							}
						}
						_ = enc.Encode(map[string]any{
							"ts":            ev.At.Format(time.RFC3339Nano),
							"kind":          "dp.connection",
							"node":          node,
							"ep_mac":        ev.Conn.EPMAC.String(),
							"client_ip":     ev.Conn.ClientIP.String(),
							"server_ip":     ev.Conn.ServerIP.String(),
							"client_port":   ev.Conn.ClientPort,
							"server_port":   ev.Conn.ServerPort,
							"ip_proto":      ev.Conn.IPProto,
							"application":   ev.Conn.Application,
							"bytes":         ev.Conn.Bytes,
							"sessions":      ev.Conn.Sessions,
							"policy_action": dp.PolicyActionString(ev.Conn.PolicyAction),
							"policy_id":     ev.Conn.PolicyID,
							"threat_id":     ev.Conn.ThreatID,
							"severity":      ev.Conn.Severity,
							"ingress":       ev.Conn.Ingress,
							"external":      ev.Conn.ExternalPeer,
						})
					}
				case dp.EventThreat:
					nDPThreat.Add(1)
					if ev.Threat != nil {
						// Wave 5: also push to the threat ingest channel.
						// Non-blocking; if the buffer is full we drop and
						// count so the IPC reader never stalls.
						if threatOut != nil {
							row := dpThreatToIngest(ev, node)
							select {
							case threatOut <- row:
							default:
								nThreatsDropped.Add(1)
							}
						}
						_ = enc.Encode(map[string]any{
							"ts":          ev.At.Format(time.RFC3339Nano),
							"kind":        "dp.threat",
							"node":        node,
							"threat_id":   ev.Threat.ThreatID,
							"severity":    ev.Threat.Severity,
							"application": ev.Threat.Application,
							"src_ip":      ev.Threat.SrcIP.String(),
							"dst_ip":      ev.Threat.DstIP.String(),
							"src_port":    ev.Threat.SrcPort,
							"dst_port":    ev.Threat.DstPort,
							"ip_proto":    ev.Threat.IPProto,
							"msg":         ev.Threat.Msg,
							"pkt_len":     ev.Threat.PktLen,
							"cap_len":     ev.Threat.CapLen,
						})
					}
				case dp.EventKeepAlive:
					nDPKeepAlive.Add(1)
					pushMeterConfig()
				case dp.EventSession:
					// #6: a ctrl_list_session response is a full dump that dp
					// splits across N datagrams, terminated by DPMsgHdr.More==false.
					// The dp package assembles those datagrams (More-aware) and
					// hands us one complete snapshot; we Replace() the cache with it
					// so sessions dp has since evicted disappear from our cache too.
					// Apply()-per-datagram only ever accreted, so stale sessions
					// leaked forever.
					if dpSup != nil && len(ev.Sessions) > 0 {
						dpSup.Sessions().Replace(ev.Sessions)
					}
				case dp.EventOther:
					nDPOther.Add(1)
				}
			}
		}()
	}

	// Periodic ticker: every 5s emit a heartbeat with running totals + dropped.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				rec := map[string]any{
					"ts":             now.UTC().Format(time.RFC3339Nano),
					"kind":           "heartbeat",
					"node":           node,
					"exec":           nExec.Load(),
					"file":           nFile.Load(),
					"total":          nTotal.Load(),
					"uploaded":       nUploaded.Load(),
					"dropped":        nDropped.Load(),
					"bpf_dropped":    a.Dropped(),
					"flows_uploaded": nFlowsUploaded.Load(),
					"flows_dropped":  nFlowsDropped.Load(),
				}
				if dpSup != nil {
					life, ipcStats, ka, taps := dpSup.Stats()
					rec["dp_starts"] = life.StartCount
					rec["dp_exits"] = life.ExitCount
					rec["dp_crashes"] = life.CrashCount
					rec["dp_rx_total"] = ipcStats.RxTotal
					rec["dp_rx_dropped"] = ipcStats.RxDrop
					rec["dp_rx_bad_hdr"] = ipcStats.RxBadHdr
					rec["dp_rx_bad_pl"] = ipcStats.RxBadPL
					rec["dp_ka_sent"] = ka.Sent
					rec["dp_ka_replied"] = ka.Replied
					rec["dp_ka_timeout"] = ka.Timeout
					rec["dp_ka_errors"] = ka.Errors
					rec["dp_conn_events"] = nDPConn.Load()
					rec["dp_threat_events"] = nDPThreat.Load()
					rec["dp_keepalive_events"] = nDPKeepAlive.Load()
					rec["dp_other_events"] = nDPOther.Load()
					rec["dp_taps_added"] = taps.Added
					rec["dp_taps_removed"] = taps.Removed
					rec["dp_taps_errors"] = taps.Errors
					rec["dp_taps_current"] = taps.CurrentTaps
					rec["dp_threats_uploaded"] = nThreatsUploaded.Load()
					rec["dp_threats_dropped"] = nThreatsDropped.Load()
				}
				_ = enc.Encode(rec)
			}
		}
	}()

	// Consume events.
	for ev := range a.Events() {
		nTotal.Add(1)
		out := map[string]any{
			"ts":   ev.At.UTC().Format(time.RFC3339Nano),
			"node": node,
		}
		// Build the typed ingest record in parallel with the stdout record.
		ie := ingestEvent{At: ev.At.UTC(), Node: node}
		switch ev.Kind {
		case ebpf.EventKindProcess:
			nExec.Add(1)
			if ev.Process != nil {
				out["kind"] = "exec"
				out["pid"] = ev.Process.PID
				out["ppid"] = ev.Process.PPID
				out["uid"] = ev.Process.UID
				out["comm"] = ev.Process.Comm
				out["filename"] = ev.Process.Filename
				if ev.Process.ContainerID != "" {
					out["container_id"] = ev.Process.ContainerID
				}
				ie.Kind = "process_exec"
				ie.PID = ev.Process.PID
				ie.PPID = ev.Process.PPID
				ie.UID = ev.Process.UID
				ie.Comm = ev.Process.Comm
				ie.Filename = ev.Process.Filename
				ie.Args = ev.Process.Args
				ie.ContainerID = ev.Process.ContainerID
				// RT-4: enrich from /proc — real uid + stdio-socket (reverse shell).
				// Best-effort and cheap (one readdir + one small read); a missing
				// /proc entry (exec already exited) leaves the fields at zero.
				enr := enrichProcExec(ev.Process.PID)
				ie.StdioSocket = enr.StdioSocket
				if enr.RuidOK {
					ie.Ruid = enr.Ruid
					ie.RuidKnown = true
				}
				ident := workloads.Resolve(ev.Process.ContainerID)
				ie.WorkloadID = ident.WorkloadID
				ie.Namespace = ident.Namespace
				ie.Pod = ident.Pod
				// Kill-on-exec enforcement (nil-safe no-op unless enabled).
				procEnforcer.onExec(int(ev.Process.PID), ev.Process.ContainerID,
					ev.Process.Comm, ev.Process.Filename, ident.WorkloadID)
				if ident.WorkloadID != "" {
					out["workload_id"] = ident.WorkloadID
				}
				if ident.Namespace != "" {
					out["namespace"] = ident.Namespace
				}
				if ident.Pod != "" {
					out["pod"] = ident.Pod
				}
			}
		case ebpf.EventKindFile:
			nFile.Add(1)
			if ev.File != nil {
				out["kind"] = "file"
				out["pid"] = ev.File.PID
				out["comm"] = ev.File.Comm
				out["path"] = ev.File.Path
				ie.Kind = "file_open"
				ie.PID = ev.File.PID
				ie.Comm = ev.File.Comm
				ie.Path = ev.File.Path
				ie.Flags = ev.File.Flags
				ie.Mode = ev.File.Mode
				ie.ContainerID = ev.File.ContainerID
				ident := workloads.Resolve(ev.File.ContainerID)
				ie.WorkloadID = ident.WorkloadID
				ie.Namespace = ident.Namespace
				ie.Pod = ident.Pod
				if ident.WorkloadID != "" {
					out["workload_id"] = ident.WorkloadID
				}
				if ident.Namespace != "" {
					out["namespace"] = ident.Namespace
				}
				if ident.Pod != "" {
					out["pod"] = ident.Pod
				}
			}
		default:
			out["kind"] = "unknown"
		}

		// Forward to uploader (non-blocking; drop and count if buffer is full so the
		// kernel pump never stalls).
		if uploadEnabled && ie.Kind != "" {
			select {
			case toUpload <- ie:
			default:
				nDropped.Add(1)
			}
		}

		// Throttle stdout: every Nth event prints, but interesting events
		// (exec + network) always print. File events are noisy so we only
		// print every Nth.
		total := nTotal.Load()
		if ev.Kind == ebpf.EventKindProcess || ev.Kind == ebpf.EventKindNetwork || total%uint64(logEvery) == 0 {
			_ = enc.Encode(out)
		}
	}

	if err := <-runErrCh; err != nil {
		logger.Error("runtime-agent: Run returned", slog.String("err", err.Error()))
	}

	// Drain the upload channel so the last partial batch flushes before exit.
	if toUpload != nil {
		close(toUpload)
	}
	if flowOut != nil {
		// Aggregator's Run() exits on ctx cancel; closing flowOut here would
		// race with that goroutine, so we just leave it for the GC.
		_ = flowOut
	}
	// Give the upload loops a brief window to drain.
	if uploadEnabled {
		time.Sleep(time.Duration(batchIntervalMs)*time.Millisecond + 500*time.Millisecond)
	}

	fmt.Fprintf(os.Stderr, "== runtime-agent shutdown ==\nexec=%d file=%d total=%d uploaded=%d dropped=%d bpf_dropped=%d flows_uploaded=%d flows_dropped=%d\n",
		nExec.Load(), nFile.Load(), nTotal.Load(),
		nUploaded.Load(), nDropped.Load(), a.Dropped(),
		nFlowsUploaded.Load(), nFlowsDropped.Load())
}

// flowUploadLoop drains bucketed flows into batches and POSTs them to
// /api/v1/network-flows:bulk. Mirrors uploadLoop above but for flowIngestRow.
func flowUploadLoop(
	ctx context.Context,
	logger *slog.Logger,
	url, token string,
	size int,
	interval time.Duration,
	in <-chan flowIngestRow,
	uploaded, dropped *atomic.Uint64,
) {
	client := sharedUploadClient
	sem := make(chan struct{}, maxInFlightUploads)
	buf := make([]flowIngestRow, 0, size)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		batch := buf
		buf = make([]flowIngestRow, 0, size)
		// Bound in-flight POSTs: block briefly for a slot so a wedged API
		// can't leak an unbounded number of upload goroutines + batches.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		go func() {
			defer func() { <-sem }()
			if err := postFlowBatch(ctx, client, url, token, batch); err != nil {
				logger.Warn("flow upload failed; dropping",
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

// postFlowBatch posts a batch of flow rows with the same retry semantics as
// postBatch.
func postFlowBatch(ctx context.Context, client *http.Client, url, token string, batch []flowIngestRow) error {
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
		lastErr = errors.New("unknown flow upload failure")
	}
	return lastErr
}

// ingestEvent is the wire shape sent to POST /api/v1/events:bulk. Kept here as a private
// copy of handler.IngestEvent so this binary does not pull in the entire HTTP handler
// dependency graph. Field tags MUST match handler.IngestEvent exactly.
type ingestEvent struct {
	At          time.Time `json:"at"`
	Kind        string    `json:"kind"`
	Node        string    `json:"node,omitempty"`
	WorkloadID  string    `json:"workload_id,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Pod         string    `json:"pod,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`

	PID      uint32   `json:"pid,omitempty"`
	PPID     uint32   `json:"ppid,omitempty"`
	UID      uint32   `json:"uid,omitempty"`
	Comm     string   `json:"comm,omitempty"`
	Filename string   `json:"filename,omitempty"`
	Args     []string `json:"args,omitempty"`

	// RT-4 /proc enrichment (optional; absent => current behavior). UID above is the
	// effective uid from the kernel record; Ruid is the real uid read from
	// /proc/<pid>/status. StdioSocket is true when any of fd 0/1/2 is a socket (a classic
	// reverse-shell tell). RuidKnown distinguishes "ruid is 0" (root) from "ruid unread".
	Ruid        uint32 `json:"ruid,omitempty"`
	RuidKnown   bool   `json:"ruid_known,omitempty"`
	StdioSocket bool   `json:"stdio_socket,omitempty"`

	Direction string `json:"direction,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Src       string `json:"src,omitempty"`
	Dst       string `json:"dst,omitempty"`

	Path  string `json:"path,omitempty"`
	Flags uint32 `json:"flags,omitempty"`
	Mode  uint32 `json:"mode,omitempty"`

	// Sha256 is the content hash of Path when this event confirms a real file
	// modification (B3 host-path FIM). Empty for non-file events or when hashing
	// was skipped (oversized/unreadable). Additive; the server may ignore it.
	Sha256 string `json:"sha256,omitempty"`

	Blocked           bool   `json:"blocked,omitempty"`
	FileProfileRuleID string `json:"file_profile_rule_id,omitempty"`

	// ZeroDriftReason is the agent's P0-4 zero-drift tag ("zero-drift:image-drift" |
	// "zero-drift:unanchored") for a process_exec the agent flagged via its /proc
	// provenance proxy. Empty for non-drift events. The server can't reproduce this
	// /proc-derived signal, so it classifies the exec from this tag.
	ZeroDriftReason string `json:"zero_drift_reason,omitempty"`
}

// uploadLoop is the single writer that drains `in` into batches and POSTs each batch.
// Flush triggers: batch reaches `size`, or `interval` elapses since the last flush.
//
// Failures retry up to 3 times with exponential backoff (100ms, 400ms, 1.6s). After the
// final failure the batch is dropped and `dropped` is bumped by len(batch).
func uploadLoop(
	ctx context.Context,
	logger *slog.Logger,
	url, token string,
	size int,
	interval time.Duration,
	in <-chan ingestEvent,
	uploaded, dropped *atomic.Uint64,
) {
	client := sharedUploadClient
	sem := make(chan struct{}, maxInFlightUploads)
	buf := make([]ingestEvent, 0, size)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		// Try POST + retries. Avoid blocking the loop forever on a wedged API: the total
		// retry budget is ~2.1s.
		batch := buf
		buf = make([]ingestEvent, 0, size)
		// Bound in-flight POSTs: block briefly for a slot so a wedged API
		// can't leak an unbounded number of upload goroutines + batches.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		go func() {
			defer func() { <-sem }()
			if err := postBatch(ctx, client, url, token, batch); err != nil {
				logger.Warn("upload batch failed; dropping",
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
		case ev, ok := <-in:
			if !ok {
				flush()
				return
			}
			buf = append(buf, ev)
			if len(buf) >= size {
				flush()
				ticker.Reset(interval)
			}
		case <-ticker.C:
			flush()
		}
	}
}

// postBatch marshals + POSTs the batch, with up to 3 retries on transient failures.
// A non-2xx response is treated as terminal — there's no point retrying a 400. A network
// error or 5xx is retried.
func postBatch(ctx context.Context, client *http.Client, url, token string, batch []ingestEvent) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	delays := []time.Duration{0, 100 * time.Millisecond, 400 * time.Millisecond, 1600 * time.Millisecond}
	var lastErr error
	for attempt, delay := range delays {
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
			continue // retry
		}
		// Drain the body so the connection can be reused.
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		// 4xx -> terminal, no point retrying with the same body.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
		lastErr = fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		_ = attempt
	}
	if lastErr == nil {
		lastErr = errors.New("unknown upload failure")
	}
	return lastErr
}

// selectTapProvider picks how the dp supervisor will discover interfaces to
// inspect. See main()'s Options literal for priority.
//
// "none" disables the reconciler entirely (dp idles, useful for testing only
// the IPC plumbing). "env" forces the bootstrap env-var provider regardless
// of whether CONSTELLATION_DP_TAP_PORTS is set. "podveth" forces sysfs
// auto-discovery regardless. The defaulted fall-through prefers env-var
// when explicit ports are configured, else auto-discovery.
func selectTapProvider(logger *slog.Logger, enforceActive bool) dp.TapProvider {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CONSTELLATION_DP_TAP_PROVIDER"))) {
	case "none":
		return nil
	case "env":
		return dp.NewEnvTapProvider()
	case "podveth":
		// Legacy: taps the host-side veth with the host-side MAC. Kept for
		// debugging/regression only — dp drops these packets because EPMAC is
		// matched against the on-wire (pod-side) MACs. See container_tap.go.
		return dp.NewPodVethProvider(logger)
	case "container":
		return dp.NewContainerTapProvider(logger, crictlContainerLister(enforceActive))
	}
	// Explicit env-var ports still win (dev/test bootstrap).
	if env := dp.NewEnvTapProvider(); env != nil {
		return env
	}
	// Default: per-container netns tapping (NeuVector's proven model). This
	// replaces PodVethProvider as the active auto-discovery provider so the
	// network map sees real traffic.
	return dp.NewContainerTapProvider(logger, crictlContainerLister(enforceActive))
}

// selectEnforceProvider returns the inline (NFQUEUE) enforce provider, or nil
// (the default — inline path dormant). It activates only when enforceActive is
// set AND the tap provider is the container provider (the only one that reads
// pod labels for the per-workload enforce opt-in). Scoped per-workload: only
// pods labelled dpi.constellation.alphabravo.io/enforce go inline.
func selectEnforceProvider(tp dp.TapProvider, enforceActive bool, logger *slog.Logger) dp.EnforceProvider {
	if !enforceActive {
		return nil
	}
	cp, ok := tp.(*dp.ContainerTapProvider)
	if !ok {
		logger.Warn("dp: enforce gate on but tap provider is not the container provider; inline enforcement stays off")
		return nil
	}
	return dp.NewContainerEnforceProvider(cp)
}

// crictlContainerLister adapts hostscan.ListRunningContainers (crictl over the
// host CRI socket) into dp.ContainerLister. Kept here so the dp package needn't
// import hostscan (hostscan already imports dp).
func crictlContainerLister(enforceActive bool) dp.ContainerLister {
	hostRoot := hostScanHostRootFromEnv()
	return func(ctx context.Context) ([]dp.RunningContainer, error) {
		raw, err := hostscan.ListRunningContainers(ctx, hostscan.ListRunningContainersOptions{
			HostRoot: hostRoot,
			Timeout:  10 * time.Second,
		})
		if err != nil {
			return nil, err
		}
		out := make([]dp.RunningContainer, 0, len(raw))
		for _, c := range raw {
			waf, dlp, enforce := dpiOptIn(c.PodLabels)
			out = append(out, dp.RunningContainer{
				ID: c.ID, PodName: c.PodName, PID: c.PID,
				WAF: waf, DLP: dlp,
				// Inline enforcement activates ONLY under the agent gate
				// (enforceActive = CONSTELLATION_DP_ENFORCE + NFQUEUE-safe CNI);
				// the pod's enforce label alone is inert. This keeps the Enforce
				// flag and the ContainerEnforceProvider consistent, so a labeled
				// pod is never skipped-from-tap without an enforce reconciler to
				// pick it up.
				Enforce: enforceActive && enforce,
			})
		}
		return out, nil
	}
}

// DPI opt-in pod labels (per-workload, NeuVector-group-style scoping). A
// workload is bound into WAF/DLP only when it carries the matching label with a
// truthy value; DPI is OFF by default so it never fleet-wide false-positives.
//
//	dpi.constellation.alphabravo.io/waf: "true"   → bind the CRS WAF pack
//	dpi.constellation.alphabravo.io/dlp: "true"   → bind the DLP catalog
//	dpi.constellation.alphabravo.io/inspect: "waf,dlp" | "all" → both
const (
	labelDPIWaf     = "dpi.constellation.alphabravo.io/waf"
	labelDPIDlp     = "dpi.constellation.alphabravo.io/dlp"
	labelDPIInspect = "dpi.constellation.alphabravo.io/inspect"
	// labelDPIEnforce opts a workload into INLINE (NFQUEUE) mode so DLP/WAF/policy
	// verdicts (drop/reset) can actually take effect. Inert unless the agent gate
	// CONSTELLATION_DP_ENFORCE is on AND the CNI is NFQUEUE-safe (see main).
	labelDPIEnforce = "dpi.constellation.alphabravo.io/enforce"
)

func dpiOptIn(labels map[string]string) (waf, dlp, enforce bool) {
	if len(labels) == 0 {
		return false, false, false
	}
	if envTruthy(labels[labelDPIWaf]) {
		waf = true
	}
	if envTruthy(labels[labelDPIDlp]) {
		dlp = true
	}
	if envTruthy(labels[labelDPIEnforce]) {
		enforce = true
	}
	switch strings.ToLower(strings.TrimSpace(labels[labelDPIInspect])) {
	case "all", "waf,dlp", "dlp,waf":
		waf, dlp = true, true
	case "waf":
		waf = true
	case "dlp":
		dlp = true
	}
	return waf, dlp, enforce
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func withClusterID(rawURL, clusterID string) string {
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return rawURL
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + "cluster_id=" + url.QueryEscape(clusterID)
}

// formatAddrPort renders a netip.AddrPort safely. The zero value formats as "invalid
// AddrPort"; we want the empty string in that case so the server doesn't try to parse it.
func formatAddrPort(a netip.AddrPort) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
