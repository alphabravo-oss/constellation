package main

type runtimeAgentHeartbeatOptions struct {
	UploadEnabled   bool
	BatchSize       int
	BatchIntervalMS int
	ClusterID       string
	ClusterName     string
	CNIName         string
	NFQueueSafe     bool
}

func runtimeAgentHeartbeatMetadata(m *metricsSource, opts runtimeAgentHeartbeatOptions) map[string]any {
	out := map[string]any{
		"node":              m.Node,
		"upload_enabled":    opts.UploadEnabled,
		"batch_size":        opts.BatchSize,
		"batch_interval_ms": opts.BatchIntervalMS,
		"processed_events":  m.NTotal.Load(),
		"exec_events":       m.NExec.Load(),
		"file_events":       m.NFile.Load(),
		"uploaded_events":   m.NUploaded.Load(),
		"dropped_events":    m.NDropped.Load(),
		"bpf_dropped":       m.BPFDropped(),
		"flows_uploaded":    m.NFlowsUploaded.Load(),
		"flows_dropped":     m.NFlowsDropped.Load(),
		"threats_uploaded":  m.NThreatsUploaded.Load(),
		"threats_dropped":   m.NThreatsDropped.Load(),
	}
	if opts.ClusterID != "" {
		out["cluster_id"] = opts.ClusterID
	}
	if opts.ClusterName != "" {
		out["cluster_name"] = opts.ClusterName
	}
	if opts.CNIName != "" {
		out["cni"] = map[string]any{
			"name":         opts.CNIName,
			"nfqueue_safe": opts.NFQueueSafe,
		}
	}

	dpStatus := "disabled"
	probeStatus := "ready"
	policyMode := "monitor"
	dpMeta := map[string]any{"enabled": false, "status": dpStatus}
	if m.DPSup != nil {
		life, ipcStats, ka, taps, enforce := m.DPSup.StatsAll()
		sessions := m.DPSup.SessionStats()
		dpStatus = runtimeAgentDPStatus(life.StartCount, life.CrashCount, ipcStats.RxDrop, ka.Replied, ka.Timeout, ka.Errors, taps.Errors)
		probeStatus = dpStatus
		if enforce.Current > 0 {
			policyMode = "enforce"
		}
		dpMeta = map[string]any{
			"enabled":            true,
			"status":             dpStatus,
			"starts":             life.StartCount,
			"exits":              life.ExitCount,
			"crashes":            life.CrashCount,
			"rx_total":           ipcStats.RxTotal,
			"rx_dropped":         ipcStats.RxDrop,
			"rx_bad_header":      ipcStats.RxBadHdr,
			"rx_bad_payload":     ipcStats.RxBadPL,
			"keepalive_sent":     ka.Sent,
			"keepalive_replied":  ka.Replied,
			"keepalive_timeout":  ka.Timeout,
			"keepalive_errors":   ka.Errors,
			"taps_added":         taps.Added,
			"taps_removed":       taps.Removed,
			"taps_errors":        taps.Errors,
			"taps_current":       taps.CurrentTaps,
			"enforce_added":      enforce.Added,
			"enforce_removed":    enforce.Removed,
			"enforce_errors":     enforce.Errors,
			"enforce_current":    enforce.Current,
			"enforce_queues":     enforce.QueuesInUse,
			"connection_events":  m.NDPConn.Load(),
			"threat_events":      m.NDPThreat.Load(),
			"keepalive_events":   m.NDPKeepAlive.Load(),
			"other_events":       m.NDPOther.Load(),
			"threats_uploaded":   m.NThreatsUploaded.Load(),
			"threats_dropped":    m.NThreatsDropped.Load(),
			"sessions_size":      sessions.Size,
			"sessions_updates":   sessions.Updates,
			"sessions_observed":  sessions.Sessions,
			"session_lookups":    sessions.Lookups,
			"session_lookup_hit": sessions.LookupHits,
		}
	}
	out["dp"] = dpMeta
	out["enforcer"] = map[string]any{
		"node":             m.Node,
		"dp_status":        dpStatus,
		"ebpf_status":      runtimeAgentEBPFStatus(m.BPFDropped()),
		"probe_status":     probeStatus,
		"policy_mode":      policyMode,
		"processed_events": runtimeAgentProcessedEvents(m),
		"dropped_events":   runtimeAgentDroppedEvents(m),
	}
	return out
}

func runtimeAgentProcessedEvents(m *metricsSource) uint64 {
	return m.NTotal.Load() + m.NDPConn.Load() + m.NDPThreat.Load() + m.NDPKeepAlive.Load() + m.NDPOther.Load()
}

func runtimeAgentDroppedEvents(m *metricsSource) uint64 {
	return m.NDropped.Load() + m.NFlowsDropped.Load() + m.NThreatsDropped.Load()
}

func runtimeAgentDPStatus(starts, crashes, rxDropped, keepaliveReplies, keepaliveTimeouts, keepaliveErrors, tapErrors uint64) string {
	switch {
	case starts == 0:
		return "starting"
	case keepaliveReplies == 0:
		return "starting"
	case crashes > 0 || rxDropped > 0 || keepaliveTimeouts > 0 || keepaliveErrors > 0 || tapErrors > 0:
		return "degraded"
	default:
		return "ready"
	}
}

func runtimeAgentEBPFStatus(dropped uint64) string {
	if dropped > 0 {
		return "degraded"
	}
	return "ready"
}
