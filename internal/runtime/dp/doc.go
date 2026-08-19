// Package dp drives the vendored NeuVector C data-plane (third_party/neuvector/dp).
//
// The constellation runtime-agent runs as a single Go process per node. When
// CONSTELLATION_DP_ENABLED is set, the agent forks /usr/local/bin/dp as a
// child process and communicates with it over two SOCK_DGRAM unix sockets:
//
//	/tmp/dp_client.<agent_pid>   request socket  (agent → dp)
//	/tmp/ctrl_listen.sock        notification socket  (dp → agent)
//
// dp sends asynchronous notifications — connection reports, threat logs,
// L7 app detections, FQDN updates — as length-prefixed messages framed by
// DPMsgHdr (proto.go). Wave 2 decodes the two message kinds that carry the
// metrics we care about:
//
//	DP_KIND_CONNECTION  → ConnectionEvent  (real bytes / packets / sessions
//	                                        with L7 app, policy verdict, threat ID
//	                                        per (src,dst,port,proto) tuple)
//	DP_KIND_THREAT_LOG  → ThreatEvent      (per-incident threat detection
//	                                        with src/dst, captured packet, msg)
//
// All other DP_KIND_* messages are decoded loosely (header validated) and
// counted as EventOther with their raw kind preserved. That keeps parser/app
// metadata observable until a feature promotes a specific payload to a typed
// event.
//
// The request path (agent → dp) covers policy push, DLP build/config messages,
// tap-port registration, and session-list polling. CNI-specific enforcement
// wiring still decides which veths and packet paths dp should inspect.
//
// Runtime-agent consumers bridge decoded events into network flow, runtime
// threat, session-cache, heartbeat, and metrics paths.
package dp
