//go:build linux

package main

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"golang.org/x/sys/unix"
)

// ethPAll is ETH_P_ALL in network byte order, for the AF_PACKET socket protocol
// argument. 0x0003 host → 0x0300 wire on little-endian hosts.
const ethPAll = 0x0300

// runDNSSnoop opens a passive AF_PACKET socket and feeds every UDP/53 packet's
// payload through a dpi engine that updates the FQDN resolver via FeedDNS. It is
// best-effort: if the socket can't be opened (no CAP_NET_RAW) it logs once and
// returns, leaving the rest of the agent unaffected. SOCK_DGRAM strips the link
// header so reads start at the IP header.
func runDNSSnoop(ctx context.Context, dpSup *dp.Supervisor, logger *slog.Logger, up *atomic.Uint64) {
	if dpSup == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, ethPAll)
	if err != nil {
		logger.Info("dns snoop: disabled (cannot open AF_PACKET socket)", slog.String("err", err.Error()))
		return
	}
	defer unix.Close(fd)

	// A receive timeout lets the blocking Recvfrom wake up periodically so we
	// can honor ctx cancellation without a separate fd-close goroutine.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
		&unix.Timeval{Sec: 1})

	engine := newDNSSnoopEngine(dpSup)
	logger.Info("dns snoop: started (AF_PACKET UDP/53 → FQDN resolver)")
	// #10: publish liveness so operators can alarm when the resolver feeder
	// dies. Set 1 now that we're looping; the fatal recv path below clears it.
	if up != nil {
		up.Store(1)
	}

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			logger.Warn("dns snoop: recv failed", slog.String("err", err.Error()))
			if up != nil {
				up.Store(0)
			}
			return
		}
		if n <= 0 {
			continue
		}
		feedDNSPacket(engine, buf[:n])
	}
}
