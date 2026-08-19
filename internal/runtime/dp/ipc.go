package dp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// ipcServer owns the unixgram listener at /tmp/ctrl_listen.sock and decodes
// every datagram dp sends into a typed Event on the out channel.
//
// The listener is unixgram (SOCK_DGRAM), matching dp's send-side: every
// notification is a complete message in a single datagram, no stream framing
// required beyond the DPMsgHdr.Length sanity check.
type ipcServer struct {
	path   string
	logger *slog.Logger
	out    chan<- Event

	// Stats — atomically updated, exposed via the agent's heartbeat summary.
	rxTotal  atomic.Uint64
	rxDrop   atomic.Uint64 // dropped because the consumer was full
	rxBadHdr atomic.Uint64 // failed DPMsgHdr decode
	rxBadPL  atomic.Uint64 // failed payload decode (corrupt / unexpected length)

	// sessAsm reassembles a multi-datagram ctrl_list_session dump (More flag)
	// into one snapshot. Driven only from the single IPC reader goroutine.
	sessAsm SessionDumpAssembler

	conn *net.UnixConn
}

// newIPCServer creates the server but doesn't start reading yet. Start with run().
func newIPCServer(path string, logger *slog.Logger, out chan<- Event) *ipcServer {
	return &ipcServer{path: path, logger: logger, out: out}
}

// listen opens the unixgram socket at s.path, removing any stale socket first
// (dp's socket cleanup is best-effort, so we always have to handle leftovers).
func (s *ipcServer) listen() error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		// Not fatal — dp may have already removed it. Log and continue.
		s.logger.Debug("dp ipc: pre-remove stale socket", slog.String("path", s.path), slog.String("err", err.Error()))
	}
	addr := &net.UnixAddr{Name: s.path, Net: "unixgram"}
	c, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return fmt.Errorf("dp ipc: listen %s: %w", s.path, err)
	}
	// Permissive perms — dp runs as the same uid as us so 0600 is fine, but on
	// some kernels SOCK_DGRAM auto-binds with mode 0755; we explicitly tighten.
	if err := os.Chmod(s.path, 0o600); err != nil {
		s.logger.Warn("dp ipc: chmod socket", slog.String("path", s.path), slog.String("err", err.Error()))
	}
	s.conn = c
	return nil
}

// run drains the socket until ctx is canceled. Returns nil on clean shutdown.
// Per-datagram decode errors are logged + counted; they never tear down the loop.
func (s *ipcServer) run(ctx context.Context) error {
	if s.conn == nil {
		return errors.New("dp ipc: run called before listen")
	}
	defer func() {
		_ = s.conn.Close()
		_ = os.Remove(s.path)
	}()

	// Close the socket when ctx is canceled so the blocking Read returns.
	go func() {
		<-ctx.Done()
		_ = s.conn.SetReadDeadline(time.Now())
	}()

	buf := make([]byte, DPMsgSize)
	for {
		// 1s read deadline so we periodically observe ctx.Err() even when dp
		// is silent. Without this the goroutine sits in syscall.Read forever
		// after socket close, which is fine on linux but harder to reason about
		// during shutdown.
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := s.conn.ReadFromUnix(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// Persistent error (eg. socket removed externally). Brief backoff
			// then keep trying — the supervisor will tear us down via ctx if
			// it decides to restart dp.
			s.logger.Warn("dp ipc: read", slog.String("err", err.Error()))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		s.rxTotal.Add(1)
		s.dispatch(buf[:n])
	}
}

// dispatch decodes a single datagram and pushes the resulting Event onto s.out.
// If out is full, the event is dropped and counted; we never block the IPC reader
// on consumer back-pressure.
func (s *ipcServer) dispatch(msg []byte) {
	hdr, off, err := decodeHdr(msg)
	if err != nil {
		s.rxBadHdr.Add(1)
		s.logger.Debug("dp ipc: bad header", slog.String("err", err.Error()))
		return
	}
	payload := msg[off:]

	var ev Event
	ev.At = time.Now().UTC()
	switch hdr.Kind {
	case KindConnection:
		conns, err := decodeConnections(payload)
		if err != nil {
			s.rxBadPL.Add(1)
			s.logger.Warn("dp ipc: decode connections", slog.String("err", err.Error()))
			return
		}
		// One Event per Connection — the supervisor's consumer treats them
		// individually anyway and this keeps the channel shape simple.
		for _, c := range conns {
			ev := Event{Kind: EventConnection, At: ev.At, Conn: c}
			s.emit(ev)
		}
		return
	case KindThreatLog:
		t, err := decodeThreatLog(payload)
		if err != nil {
			s.rxBadPL.Add(1)
			s.logger.Warn("dp ipc: decode threat-log", slog.String("err", err.Error()))
			return
		}
		ev.Kind = EventThreat
		ev.Threat = t
	case KindSessionList:
		sessions, err := decodeSessions(payload)
		if err != nil {
			s.rxBadPL.Add(1)
			s.logger.Warn("dp ipc: decode sessions", slog.String("err", err.Error()))
			return
		}
		// dp sends a ctrl_list_session dump as N datagrams: More=1 on all but
		// the last. Accumulate the whole dump and surface it as ONE event, so
		// the supervisor's session cache can Replace() atomically with the
		// COMPLETE snapshot. Emitting per datagram would make Replace evict all
		// but the final datagram's sessions.
		if complete := s.sessAsm.Add(sessions, hdr.More != 0); !complete {
			return
		}
		ev.Kind = EventSession
		ev.Sessions = s.sessAsm.Take()
	case KindKeepAlive:
		ev.Kind = EventKeepAlive
	default:
		// App / FQDN / session-list / etc — Wave 2 logs the kind and moves on.
		// Subsequent waves promote these to typed events as the agent grows
		// new feature surface.
		ev.Kind = EventOther
		ev.RawKind = hdr.Kind
	}
	s.emit(ev)
}

func (s *ipcServer) emit(ev Event) {
	select {
	case s.out <- ev:
	default:
		s.rxDrop.Add(1)
	}
}

// Stats exposes the running totals. Reads are atomic but the snapshot is
// not transactional across fields — close enough for telemetry.
type Stats struct {
	RxTotal  uint64
	RxDrop   uint64
	RxBadHdr uint64
	RxBadPL  uint64
}

func (s *ipcServer) snapshot() Stats {
	return Stats{
		RxTotal:  s.rxTotal.Load(),
		RxDrop:   s.rxDrop.Load(),
		RxBadHdr: s.rxBadHdr.Load(),
		RxBadPL:  s.rxBadPL.Load(),
	}
}
