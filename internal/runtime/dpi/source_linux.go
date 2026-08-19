//go:build linux && cgo

package dpi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	nfqueue "github.com/florianl/go-nfqueue"
	"golang.org/x/sys/unix"
)

// SourceConfig configures the NFQUEUE inline source.
type SourceConfig struct {
	// QueueNum matches the iptables rule: `-j NFQUEUE --queue-num N`.
	QueueNum uint16
	// MaxPacketLen caps how many bytes per packet the kernel copies to userspace.
	// 65535 is the safe default; smaller values save memory if you only need headers.
	MaxPacketLen uint32
	// VerdictAccept — when true, the source issues NF_ACCEPT for every packet after
	// dispatch. WAF wrappers should set this to false and emit verdicts themselves.
	VerdictAccept bool
	// Logger for slog.
	Logger *slog.Logger
}

// Source attaches to NFQUEUE, parses each captured packet's L4 payload, and feeds it
// to the engine. The kernel-mode WAF wraps this with its own callback to issue
// per-packet verdicts (allow/deny).
type Source struct {
	cfg    SourceConfig
	engine *Engine
	q      *nfqueue.Nfqueue
	verdictHook func(packetID uint32, evt *L7Event) int // optional
}

// NewSource opens the NFQUEUE handle but does not start the dispatch loop yet.
func NewSource(engine *Engine, cfg SourceConfig) (*Source, error) {
	if cfg.MaxPacketLen == 0 {
		cfg.MaxPacketLen = 65535
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	q, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      cfg.QueueNum,
		MaxPacketLen: cfg.MaxPacketLen,
		MaxQueueLen:  0xffff,
		Copymode:     nfqueue.NfQnlCopyPacket,
	})
	if err != nil {
		return nil, fmt.Errorf("dpi: nfqueue open: %w", err)
	}
	return &Source{cfg: cfg, engine: engine, q: q}, nil
}

// SetVerdictHook wires a per-packet verdict callback. The hook must return one of
// nfqueue.NfAccept / nfqueue.NfDrop / nfqueue.NfRepeat. If unset the source either
// issues NF_ACCEPT (VerdictAccept=true) or never sets a verdict (the test-only path).
func (s *Source) SetVerdictHook(h func(packetID uint32, evt *L7Event) int) {
	s.verdictHook = h
}

// Run starts the dispatch loop. Blocks until ctx is cancelled.
func (s *Source) Run(ctx context.Context) error {
	if s.q == nil {
		return errors.New("dpi: source closed")
	}
	fn := func(attr nfqueue.Attribute) int {
		pktID := uint32(0)
		if attr.PacketID != nil {
			pktID = *attr.PacketID
		}
		if attr.Payload == nil {
			s.maybeAccept(pktID)
			return 0
		}
		flow, payload, ok := parseIP(*attr.Payload)
		if !ok {
			s.maybeAccept(pktID)
			return 0
		}
		evt := s.engine.Process(flow, DirRequest, payload)
		if s.verdictHook != nil {
			verdict := s.verdictHook(pktID, evt)
			_ = s.q.SetVerdict(pktID, verdict)
			return 0
		}
		s.maybeAccept(pktID)
		return 0
	}
	errFn := func(e error) int {
		s.cfg.Logger.Warn("dpi: nfqueue error", slog.String("err", e.Error()))
		return 0
	}
	if err := s.q.RegisterWithErrorFunc(ctx, fn, errFn); err != nil {
		return fmt.Errorf("dpi: nfqueue register: %w", err)
	}
	<-ctx.Done()
	return s.q.Close()
}

func (s *Source) maybeAccept(pktID uint32) {
	if s.cfg.VerdictAccept {
		_ = s.q.SetVerdict(pktID, nfqueue.NfAccept)
	}
}

// Close releases the NFQUEUE handle.
func (s *Source) Close() error {
	if s.q == nil {
		return nil
	}
	return s.q.Close()
}

// parseIP cracks an IPv4 / IPv6 packet's L4 payload + builds a Flow. Currently
// supports TCP and UDP; ICMP returns false.
func parseIP(raw []byte) (Flow, []byte, bool) {
	if len(raw) < 1 {
		return Flow{}, nil, false
	}
	switch raw[0] >> 4 {
	case 4:
		return parseIPv4(raw)
	case 6:
		return parseIPv6(raw)
	}
	return Flow{}, nil, false
}

func parseIPv4(raw []byte) (Flow, []byte, bool) {
	if len(raw) < 20 {
		return Flow{}, nil, false
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < 20 || ihl > len(raw) {
		return Flow{}, nil, false
	}
	proto := raw[9]
	src := netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
	dst := netip.AddrFrom4([4]byte{raw[16], raw[17], raw[18], raw[19]})
	return parseL4(src, dst, proto, raw[ihl:])
}

func parseIPv6(raw []byte) (Flow, []byte, bool) {
	if len(raw) < 40 {
		return Flow{}, nil, false
	}
	nh := raw[6]
	var s, d [16]byte
	copy(s[:], raw[8:24])
	copy(d[:], raw[24:40])
	return parseL4(netip.AddrFrom16(s), netip.AddrFrom16(d), nh, raw[40:])
}

func parseL4(src, dst netip.Addr, proto byte, l4 []byte) (Flow, []byte, bool) {
	switch proto {
	case unix.IPPROTO_TCP:
		if len(l4) < 20 {
			return Flow{}, nil, false
		}
		sport := uint16(l4[0])<<8 | uint16(l4[1])
		dport := uint16(l4[2])<<8 | uint16(l4[3])
		dataOff := int(l4[12]>>4) * 4
		if dataOff < 20 || dataOff > len(l4) {
			return Flow{}, nil, false
		}
		return Flow{
			Src: netip.AddrPortFrom(src, sport),
			Dst: netip.AddrPortFrom(dst, dport),
			Protocol: "tcp",
		}, l4[dataOff:], true
	case unix.IPPROTO_UDP:
		if len(l4) < 8 {
			return Flow{}, nil, false
		}
		sport := uint16(l4[0])<<8 | uint16(l4[1])
		dport := uint16(l4[2])<<8 | uint16(l4[3])
		return Flow{
			Src: netip.AddrPortFrom(src, sport),
			Dst: netip.AddrPortFrom(dst, dport),
			Protocol: "udp",
		}, l4[8:], true
	}
	return Flow{}, nil, false
}
