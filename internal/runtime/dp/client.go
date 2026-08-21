package dp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// DPServerSocket is dp's request socket. Hardcoded in third_party/neuvector/dp/ctrl.c:45
// (`#define DP_SERVER_SOCK "/tmp/dp_listen.sock"`); cannot be changed without
// forking the C source.
const DPServerSocket = "/tmp/dp_listen.sock"

// dpClientAddr is the agent's local bind point for its DialUnix to dp. The
// %d is the agent's PID so multiple agents on the same node (eg. during
// rolling restart) can coexist briefly.
func dpClientAddr() string {
	return fmt.Sprintf("/tmp/dp_client.%d", os.Getpid())
}

// keepAliveRequest is the JSON we send dp every 2s. Mirrors NeuVector's
// agent/dp/dp_apis.go DPKeepAliveReq.
type keepAliveRequest struct {
	Alive keepAlivePayload `json:"ctrl_keep_alive"`
}

type keepAlivePayload struct {
	SeqNum uint32 `json:"seq_num"`
}

// tapPort is the JSON wire shape shared by ctrl_add_tap_port and
// ctrl_del_tap_port. Mirrors neuvector/agent/dp/dp_apis.go DPTapPort.
//
// netns is a path that dp passes to setns(), e.g. "/proc/1/ns/net" for the
// host or "/proc/<pid>/ns/net" for a container. Empty means current netns.
//
// iface is the interface name as visible inside that netns (eg. "eth0",
// "veth9a4b…", "cali_xxx").
//
// epmac is the workload's MAC; dp tags DPMsgConnect.EPMAC with it so the
// agent can map traffic → workload downstream. For host-side veth taps this
// should be the *pod-side* MAC; the host-side MAC won't match any inbound
// destination MAC and breaks attribution.
type tapPort struct {
	NetNS string `json:"netns"`
	Iface string `json:"iface"`
	EPMAC string `json:"epmac,omitempty"`
}

type addTapPortReq struct{ Add *tapPort `json:"ctrl_add_tap_port"` }
type delTapPortReq struct{ Del *tapPort `json:"ctrl_del_tap_port"` }

// clearSessionReq maps to dp's ctrl_clear_session (ctrl.c:1250). filter_id is the
// dp session id to terminate; 0 would clear ALL sessions, so callers must pass a
// specific id. Fire-and-forget like the other oneway ctrl commands.
type clearSessionReq struct {
	Clear clearSessionPayload `json:"ctrl_clear_session"`
}
type clearSessionPayload struct {
	FilterID uint32 `json:"filter_id"`
}

// DPI_THRT_* enum indices (dpi/dpi_log.h) for the weak-TLS version signatures that
// dp lets us toggle at runtime. These index the global threat_config[] table.
const (
	ThreatSSLv3   uint32 = 16 // DPI_THRT_SSL_VER_2OR3
	ThreatTLS10   uint32 = 17 // DPI_THRT_SSL_TLS_1DOT0
	ThreatTLS11   uint32 = 29 // DPI_THRT_SSL_TLS_1DOT1
)

// setThreatReq maps to dp's ctrl_set_threat (ctrl.c): toggle a built-in DPI signature
// live. `threat` is the DPI_THRT_* enum index; `enable` turns it on/off.
type setThreatReq struct {
	Set setThreatPayload `json:"ctrl_set_threat"`
}
type setThreatPayload struct {
	Threat uint32 `json:"threat"`
	Enable bool   `json:"enable"`
}

// SetThreatStatus enables/disables a built-in dp threat signature at runtime.
func (c *dpClient) SetThreatStatus(idx uint32, enable bool) error {
	return c.sendOneway(&setThreatReq{Set: setThreatPayload{Threat: idx, Enable: enable}})
}

// ClearSession asks dp to terminate the session with the given id (NV session-kill).
func (c *dpClient) ClearSession(id uint32) error {
	if id == 0 {
		return fmt.Errorf("dp: refusing clear-session with id 0 (would clear all)")
	}
	return c.sendOneway(&clearSessionReq{Clear: clearSessionPayload{FilterID: id}})
}

// setDebugPayload — mirrors NeuVector dp_apis.DPSetDebug. Categories are the
// short names dp recognises (see third_party/neuvector/dp/debug.c): "ctrl",
// "packet", "session", "timer", "tcp", "parser", "log", "ddos", "policy", "dlp"
// (or "all" / "none").
type setDebugPayload struct {
	Categories []string `json:"categories"`
}

type setDebugReq struct{ Set *setDebugPayload `json:"ctrl_set_debug"` }

// nfqPort is the JSON wire shape for ctrl_add_nfq_port / ctrl_del_nfq_port.
// Mirrors neuvector/agent/dp/dp_apis.go DPNfqPort. NFQUEUE mode is the
// inline-enforcement variant of TAP: dp doesn't just observe packets, it
// owns the verdict (ACCEPT or DROP) the kernel applies to each one.
//
// Scaffold note: the agent does NOT today install the iptables rules that
// redirect traffic to the queue number — that's the CNI-compat piece of
// Wave 3c (1–2 weeks of operationally-sensitive work). These RPCs exist
// so the rest of the agent can be designed around them; calling
// AddNfqPort without the iptables side simply leaves dp listening on a
// queue that nothing is feeding.
type nfqPort struct {
	NetNS      string `json:"netns"`
	Iface      string `json:"iface"`
	Qnum       int    `json:"qnum"`
	EPMAC      string `json:"epmac,omitempty"`
	JumboFrame *bool  `json:"jumboframe,omitempty"`
}

type addNfqPortReq struct{ Add *nfqPort `json:"ctrl_add_nfq_port"` }
type delNfqPortReq struct{ Del *nfqPort `json:"ctrl_del_nfq_port"` }

// macPip is one element of DPAddMAC.PIPS — a pod IP that dp should associate
// with the registered MAC. Mirrors neuvector/agent/dp/dp_apis.go DPMacPip.
type macPip struct {
	IP string `json:"ip"`
}

// addMAC mirrors NeuVector's DPAddMAC. Most fields are vestigial in TAP-only
// mode (UCMAC/BCMAC are synthetic placeholders the inline-intercept model uses
// when MACs are rewritten); the load-bearing fields for tap observation are
// Iface (must match the tap iface) and MAC (the workload's identity).
type addMACPayload struct {
	Iface  string   `json:"iface"`
	MAC    string   `json:"mac"`
	UCMAC  string   `json:"ucmac"`
	BCMAC  string   `json:"bcmac"`
	OldMAC string   `json:"oldmac"`
	PMAC   string   `json:"pmac"`
	PIPS   []macPip `json:"pips"`
}

type addMACReq struct{ Add *addMACPayload `json:"ctrl_add_mac"` }

type delMACPayload struct {
	Iface string `json:"iface"`
	MAC   string `json:"mac"`
}

type delMACReq struct{ Del *delMACPayload `json:"ctrl_del_mac"` }

// protoPortApp is one listening-port app hint in ctrl_cfg_mac.apps. Mirrors
// the io_app_t seed fields dp reads in dp_ctrl_cfg_mac (third_party/neuvector/
// dp/ctrl.c:722-725): port/ip_proto identify the listening socket; app/server
// tag the L7 protocol. app/server may be 0 (unknown) — dp only needs the port
// present in ep->app_map with listen=true to fix mid-stream session direction
// (dpi_session.c:883-895), after which it recruits the real L7 parser itself.
type protoPortApp struct {
	Port    uint16 `json:"port"`
	IPProto uint8  `json:"ip_proto"`
	App     uint16 `json:"app"`
	Server  uint16 `json:"server"`
}

// macConfig is the ctrl_cfg_mac payload (dp_ctrl_cfg_mac, ctrl.c:671): macs
// selects the ep(s) by MAC; tap (re)asserts ep->tap; apps seeds ep->app_map
// with the pod's listening-port hints. Fields are pointers/slices so tap and
// apps are omitted when not set.
type macConfig struct {
	MACs []string       `json:"macs"`
	Tap  *bool          `json:"tap,omitempty"`
	Apps []protoPortApp `json:"apps,omitempty"`
}

type cfgMACReq struct{ Cfg *macConfig `json:"ctrl_cfg_mac"` }

// dpClient owns the dial-bound unixgram socket that requests go out on and
// replies arrive on. dp's responses to client requests come back on this
// same fd; async notifications (DPMsgConnect, threat logs, etc.) come in on
// the SEPARATE ctrl_listen.sock owned by ipcServer.
type dpClient struct {
	logger *slog.Logger

	// mu guards conn/seq state (connect/close/resetOnErr). It is held only
	// briefly to fetch the conn pointer — never across socket I/O.
	mu      sync.Mutex
	conn    *net.UnixConn
	seq     uint32 // last keepalive seq sent
	connWait time.Duration

	// txMu serializes whole request/reply transactions on the single shared
	// unixgram fd. dp's request socket has one receive queue, so a keepalive's
	// write+read MUST be atomic with respect to fire-and-forget sends
	// (AddMAC/AddTapPort/ListSessions); otherwise a concurrent send steals the
	// keepalive's reply datagram (ka_errors climb) and MAC registration races
	// (dp never emits connection reports, dp_rx_total stays 0). This mirrors
	// NeuVector's dpClientLock(), which is held across the entire transaction
	// (neuvector/agent/dp/ctrl.go dpSendMsgEx). Distinct from mu so the 3s
	// keepalive read never blocks connect/close/resetOnErr.
	txMu sync.Mutex

	// onReply, if non-nil, is invoked after every successful keepalive reply.
	// The supervisor installs it (before keepAliveLoop starts) to advance its
	// readiness generation. It must not block or take a mutex — it runs on the
	// keepalive hot path. Set-once before the loop launches, so reading it here
	// without synchronization is race-free.
	onReply func()

	// onSessionDump, if non-nil, receives each COMPLETE ctrl_list_session dump.
	// dp sends session-list datagrams to the CLIENT (request) socket via
	// dp_ctrl_send_binary → g_client_addr (main.c:420, ctrl.c:132) — the SAME
	// socket keepalive replies arrive on, NOT the notification socket. So the
	// keepalive reader is the only thing that sees them; it demuxes KindSessionList
	// here and hands the reassembled snapshot to the supervisor (→ SessionCache.Replace).
	// Set-once before keepAliveLoop launches. Touched only by the keepalive goroutine.
	onSessionDump func([]*Session)
	sessAsm       SessionDumpAssembler

	// Stats
	kaSent    atomic.Uint64
	kaReplied atomic.Uint64
	kaTimeout atomic.Uint64
	kaErrors  atomic.Uint64
}

func newDPClient(logger *slog.Logger) *dpClient {
	return &dpClient{
		logger:   logger,
		connWait: 200 * time.Millisecond,
	}
}

// connect dials dp's request socket. dp must have created /tmp/dp_listen.sock
// already; the supervisor waits a moment after starting dp before invoking us.
func (c *dpClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return nil
	}
	lpath := dpClientAddr()
	// Stale leftover from a previous process — best-effort remove.
	_ = os.Remove(lpath)
	laddr := &net.UnixAddr{Name: lpath, Net: "unixgram"}
	raddr := &net.UnixAddr{Name: DPServerSocket, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", laddr, raddr)
	if err != nil {
		_ = os.Remove(lpath)
		return fmt.Errorf("dp client: dial %s: %w", DPServerSocket, err)
	}
	c.conn = conn
	return nil
}

func (c *dpClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	_ = os.Remove(dpClientAddr())
}

// keepAliveLoop pings dp every 2s and verifies it replies with the same
// seq_num. Returns when ctx is canceled. On socket errors it reconnects
// before the next tick.
func (c *dpClient) keepAliveLoop(ctx context.Context) {
	// Wait briefly for dp's listener to materialize. dp creates the socket
	// in ctrl.c:3032 (make_named_socket) very early in main(), so 200ms is
	// usually plenty.
	select {
	case <-ctx.Done():
		return
	case <-time.After(c.connWait):
	}

	const interval = 2 * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.close()
			return
		case <-t.C:
			if err := c.keepAliveOnce(ctx); err != nil {
				c.logger.Debug("dp client: keepalive", slog.String("err", err.Error()))
			}
		}
	}
}

// keepAliveOnce sends one ctrl_keep_alive request and waits up to 3s for the
// matching reply. The reply is binary: 4-byte DPMsgHdr + 4-byte seq_num,
// both big-endian. See dp/ctrl.c:141-156.
func (c *dpClient) keepAliveOnce(ctx context.Context) error {
	if err := c.connect(); err != nil {
		c.kaErrors.Add(1)
		return err
	}

	c.mu.Lock()
	c.seq++
	seq := c.seq
	conn := c.conn
	c.mu.Unlock()

	req := keepAliveRequest{Alive: keepAlivePayload{SeqNum: seq}}
	msg, err := json.Marshal(&req)
	if err != nil {
		c.kaErrors.Add(1)
		return fmt.Errorf("marshal: %w", err)
	}

	// Hold txMu across the entire write+read so this keepalive's reply cannot
	// be consumed by a concurrent sendOneway write on the shared fd.
	c.txMu.Lock()
	defer c.txMu.Unlock()

	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		c.kaErrors.Add(1)
		return fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := conn.Write(msg); err != nil {
		c.kaErrors.Add(1)
		c.resetOnErr()
		return fmt.Errorf("write: %w", err)
	}
	c.kaSent.Add(1)

	// Reply. dp interleaves ctrl_list_session response datagrams (KindSessionList)
	// with keepalive replies on THIS socket, so read in a loop: demux session-list
	// datagrams into the session cache and keep reading until our keepalive reply
	// (matching seq) arrives. The overall 3s deadline bounds the whole drain.
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, DPMsgSize)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			c.kaErrors.Add(1)
			return fmt.Errorf("set read deadline: %w", err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				c.kaTimeout.Add(1)
				return fmt.Errorf("read: timeout waiting for reply (seq=%d)", seq)
			}
			c.kaErrors.Add(1)
			c.resetOnErr()
			return fmt.Errorf("read: %w", err)
		}
		if n < dpMsgHdrSize {
			c.kaErrors.Add(1)
			return fmt.Errorf("short datagram (%d bytes)", n)
		}
		hdr, off, err := decodeHdr(buf[:n])
		if err != nil {
			c.kaErrors.Add(1)
			return fmt.Errorf("decode hdr: %w", err)
		}
		// Session-list dump (dp → g_client_addr). Reassemble across datagrams;
		// hand each complete snapshot to the supervisor.
		if hdr.Kind == KindSessionList {
			sessions, derr := decodeSessions(buf[off:n])
			if derr == nil {
				if complete := c.sessAsm.Add(sessions, hdr.More != 0); complete {
					dump := c.sessAsm.Take()
					if c.onSessionDump != nil {
						c.onSessionDump(dump)
					}
				}
			}
			continue // keep reading for our keepalive reply
		}
		if hdr.Kind != KindKeepAlive {
			// Some other async datagram on the request socket — skip it, keep waiting.
			continue
		}
		if n < dpMsgHdrSize+4 {
			c.kaErrors.Add(1)
			return fmt.Errorf("short reply (%d bytes)", n)
		}
		gotSeq := binary.BigEndian.Uint32(buf[off : off+4])
		if gotSeq != seq {
			// A stale/duplicate keepalive reply — ignore and keep waiting for ours.
			continue
		}
		c.kaReplied.Add(1)
		if c.onReply != nil {
			c.onReply()
		}
		return nil
	}
}

// sendOneway marshals a request and writes it to dp's listening socket
// without waiting for a reply. dp's request handlers (other than keepalive)
// don't ack: they return an int internally but only log on failure. This is
// fire-and-forget by design — see neuvector/agent/dp/ctrl.go's `dpSendMsg`.
func (c *dpClient) sendOneway(req any) error {
	if err := c.connect(); err != nil {
		return err
	}
	msg, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("dp client: no connection")
	}
	// Serialize against keepalive's write+read transaction so this datagram is
	// never interleaved with a keepalive awaiting its reply on the shared fd.
	c.txMu.Lock()
	defer c.txMu.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := conn.Write(msg); err != nil {
		c.resetOnErr()
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// AddTapPort tells dp to open AF_PACKET on the given interface (inside the
// given netns, if non-empty) and start emitting DPMsgConnect / DPMsgThreatLog
// records for traffic seen there. epmac is the workload identity dp tags
// every record with — usually the pod-side veth MAC.
func (c *dpClient) AddTapPort(netns, iface, epmac string) error {
	return c.sendOneway(&addTapPortReq{Add: &tapPort{
		NetNS: netns, Iface: iface, EPMAC: epmac,
	}})
}

// DelTapPort tells dp to close the AF_PACKET socket on a previously-added
// (netns, iface). dp ignores epmac on the del side.
func (c *dpClient) DelTapPort(netns, iface string) error {
	return c.sendOneway(&delTapPortReq{Del: &tapPort{NetNS: netns, Iface: iface}})
}

// SetDebug pokes dp's runtime debug-flag bitmap. Helpful when chasing why dp
// isn't emitting events on a particular iface — set categories to {"ctrl",
// "packet"} to see per-packet trace lines in dp's stdout (which we already
// pipe through the agent's structured logger).
func (c *dpClient) SetDebug(categories []string) error {
	return c.sendOneway(&setDebugReq{Set: &setDebugPayload{Categories: categories}})
}

// AddMAC registers a workload identity with dp. Required for dp to emit
// DPMsgConnect for traffic involving this MAC — dp's session machinery keys
// off the MAC table to attribute packets, so a TAP without an AddMAC sees
// packets but doesn't emit them. Must be called AFTER AddTapPort (the iface
// must already be in dp's context table) and BEFORE we expect events.
//
// ucmac/bcmac/oldmac/pmac are inline-intercept-model fields; for pure TAP
// observation we pass synthetic placeholders matching NeuVector's clm driver
// (neuvector/agent/pipe/clm.go:14-17): UC = "4e:65:75:56:00:00", BC =
// "ff:ff:ff:00:00:00". pmac = mac so dp doesn't try to dedupe a non-existent
// peer.
func (c *dpClient) AddMAC(iface, mac string, ips []string) error {
	// Ordinary tap: the workload IS its own peer, so PMAC == MAC.
	return c.addMAC(iface, mac, mac, ips)
}

// AddProxyMeshMAC registers a service-mesh loopback (lo) tap identity. Unlike
// AddMAC, mac is a synthetic "lkst"-prefixed proxymesh MAC (dp keys its ep map
// and its loopback-packet attribution off this — third_party/neuvector/dp/dpi/
// dpi_entry.c:493, apis.h:42) while pmac carries the pod's REAL eth0 MAC (dp's
// policy handle) and ips the pod's loopback + eth0 IPs (xff match for the
// 127.0.0.x 5-tuples envoy<->app traffic uses). Mirrors NeuVector ctrl.c:491-497.
func (c *dpClient) AddProxyMeshMAC(iface, mac, pmac string, ips []string) error {
	return c.addMAC(iface, mac, pmac, ips)
}

func (c *dpClient) addMAC(iface, mac, pmac string, ips []string) error {
	pips := make([]macPip, 0, len(ips))
	for _, ip := range ips {
		pips = append(pips, macPip{IP: ip})
	}
	return c.sendOneway(&addMACReq{Add: &addMACPayload{
		Iface:  iface,
		MAC:    mac,
		UCMAC:  "4e:65:75:56:00:00",
		BCMAC:  "ff:ff:ff:00:00:00",
		OldMAC: "00:00:00:00:00:00",
		PMAC:   pmac,
		PIPS:   pips,
	}})
}

// ConfigMAC sends ctrl_cfg_mac for an already-registered MAC: it (re)asserts
// the ep's tap flag and seeds ep->app_map with the pod's listening-port app
// hints. This is the message NeuVector sends after every intercept and that we
// were missing — without it ep->app_map stays empty, so for TAP-copied sessions
// (where dp routinely misses the SYN) dp can't identify the pod as the server
// and falls back to a "smaller-port = server" guess (dpi_session.c:883-895).
// A misassigned direction makes the HTTP request parser bail on its first
// packet ("Not HTTP: First packet from server", dpi_http.c) so no L7 parser is
// ever recruited and DLP/WAF never scan. Seeding the listen ports fixes the
// direction and makes parser recruitment deterministic.
//
// MUST be called AFTER AddMAC/AddProxyMeshMAC — dp looks the MACs up in its ep
// map and skips ("mac not found") any that aren't registered yet (ctrl.c:699).
// Fire-and-forget like the other control messages.
func (c *dpClient) ConfigMAC(macs []string, tap *bool, apps []protoPortApp) error {
	return c.sendOneway(&cfgMACReq{Cfg: &macConfig{MACs: macs, Tap: tap, Apps: apps}})
}

// DelMAC removes a previously-registered workload MAC. The (iface, mac) pair
// must match what was passed to AddMAC.
func (c *dpClient) DelMAC(iface, mac string) error {
	return c.sendOneway(&delMACReq{Del: &delMACPayload{Iface: iface, MAC: mac}})
}

// AddNfqPort tells dp to open an NFQUEUE listener on the given queue number.
// In NFQUEUE mode dp is the kernel's verdict source for packets matched by
// the corresponding iptables rule — every packet hits ACCEPT or DROP per
// dp's policy table.
//
// Scaffold: this RPC works (dp accepts the JSON and binds the queue), but
// without the corresponding `iptables -A FORWARD -i <iface> -j NFQUEUE
// --queue-num <qnum>` rule installed elsewhere, no packets ever reach the
// queue. That iptables plumbing is the CNI-compatibility work of Wave 3c
// (full inline enforcement); this RPC exists so the agent can be designed
// around it now.
//
// jumboFrame controls dp's per-queue allocation: pass true for ≥9000 MTU
// interfaces. nil → false in dp.
func (c *dpClient) AddNfqPort(netns, iface string, qnum int, epmac string, jumboFrame *bool) error {
	return c.sendOneway(&addNfqPortReq{Add: &nfqPort{
		NetNS: netns, Iface: iface, Qnum: qnum, EPMAC: epmac, JumboFrame: jumboFrame,
	}})
}

// DelNfqPort tells dp to close the NFQUEUE listener for (netns, iface).
func (c *dpClient) DelNfqPort(netns, iface string) error {
	return c.sendOneway(&delNfqPortReq{Del: &nfqPort{NetNS: netns, Iface: iface}})
}

// listSessionsReq triggers dp to dump every active session via the
// notification socket (ctrl_listen.sock) as one or more DP_KIND_SESSION_LIST
// datagrams. The reply on the dp_client socket is just an empty ack; the
// real data flows to our ipcServer which the supervisor wires to a
// session-cache update.
type listSessionsReq struct{ Empty struct{} `json:"ctrl_list_session"` }

// ListSessions requests a session dump. Fire-and-forget: the records arrive
// asynchronously on the notification path. Wave C1's supervisor polls this
// every 30s by default.
func (c *dpClient) ListSessions() error {
	return c.sendOneway(&listSessionsReq{})
}

func (c *dpClient) resetOnErr() {
	c.mu.Lock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.mu.Unlock()
	_ = os.Remove(dpClientAddr())
}

// ClientStats is the keepalive snapshot exposed via Supervisor.Stats().
type ClientStats struct {
	Sent    uint64
	Replied uint64
	Timeout uint64
	Errors  uint64
}

func (c *dpClient) snapshot() ClientStats {
	return ClientStats{
		Sent:    c.kaSent.Load(),
		Replied: c.kaReplied.Load(),
		Timeout: c.kaTimeout.Load(),
		Errors:  c.kaErrors.Load(),
	}
}
