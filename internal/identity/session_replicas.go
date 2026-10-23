package identity

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// New cookies become visible on every live replica before a login response is
// sent. Existing sessions keep the bounded 250ms revocation window. A missing
// acknowledgement fails closed; no request-time database fallback is needed.
func (s *Service) publishSession(ctx context.Context) error {
	if err := s.RefreshSessions(ctx); err != nil {
		return err
	}
	target := s.sessions.current.Load().Revision
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		ready, err := s.store.replicasReady(bounded, target)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-bounded.Done():
			return errors.New("session replicas unavailable")
		case <-tick.C:
		}
	}
}

func (s *Service) listenSessions(ctx context.Context, wake chan<- struct{}) {
	for ctx.Err() == nil {
		err := s.receiveSessionChanges(ctx, wake)
		if ctx.Err() != nil {
			return
		}
		slog.WarnContext(ctx, "session notification listener reconnecting", "error", err)
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (s *Service) receiveSessionChanges(ctx context.Context, wake chan<- struct{}) error {
	conn, err := s.store.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	// LISTEN connections are dedicated; never return their session state to the pool.
	raw := conn.Hijack()
	defer func() { _ = raw.Close(context.WithoutCancel(ctx)) }()
	if _, err = raw.Exec(ctx, `LISTEN constellation_identity_sessions`); err != nil {
		return err
	}
	for {
		if _, err = raw.WaitForNotification(ctx); err != nil {
			return err
		}
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}
