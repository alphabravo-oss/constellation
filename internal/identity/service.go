package identity

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type Service struct {
	store     Store
	oidc      *OIDCConfig
	emergency BreakGlassConfig
	rp        atomic.Pointer[RP]
	audit     *audit.Logger
	counter   *prometheus.CounterVec
}

func New(ctx context.Context, store Store, oidc *OIDCConfig, emergency BreakGlassConfig, log *audit.Logger, registry prometheus.Registerer) (*Service, error) {
	if err := emergency.validate(); err != nil {
		return nil, err
	}
	if oidc != nil {
		oidc.defaults()
		if err := oidc.validate(); err != nil {
			return nil, err
		}
	}
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "constellation_break_glass_logins_total", Help: "Emergency administrator login attempts; every use requires investigation."}, []string{"outcome"})
	if err := registry.Register(counter); err != nil {
		return nil, err
	}
	counter.WithLabelValues("success")
	counter.WithLabelValues("failure")
	counter.WithLabelValues("rate_limited")
	s := &Service{store: store, oidc: oidc, emergency: emergency, audit: log, counter: counter}
	// Discovery failure must never prevent emergency login or API readiness.
	// Retry after startup and preserve last-good keys throughout an issuer outage.
	if oidc != nil {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		rp, err := NewRP(bounded, *oidc)
		cancel()
		if err == nil {
			s.rp.Store(rp)
		} else {
			slog.WarnContext(ctx, "OIDC provider unavailable; retrying in background")
		}
	}
	return s, nil
}

func (s *Service) Run(ctx context.Context) {
	nextRefresh := time.Now().Add(15 * time.Minute)
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if s.oidc == nil {
				continue
			}
			rp := s.rp.Load()
			if rp == nil {
				if next, err := NewRP(ctx, *s.oidc); err == nil {
					s.rp.Store(next)
				}
			} else if time.Now().After(nextRefresh) {
				if rp.Keys.Refresh(ctx) == nil {
					nextRefresh = time.Now().Add(15 * time.Minute)
				}
			}
		}
	}
}

func (s *Service) Authenticate(ctx context.Context, raw string) (authctx.Subject, error) {
	if strings.HasPrefix(raw, "csi_") {
		return s.store.session(ctx, raw)
	}
	rp := s.rp.Load()
	if rp == nil {
		return authctx.Subject{}, errors.New("OIDC unavailable")
	}
	p, err := rp.Access.Verify(raw)
	if err != nil {
		return authctx.Subject{}, err
	}
	if len(p.Roles) == 0 {
		return authctx.Subject{}, errors.New("no mapped roles")
	}
	subj, _, err := s.store.resolve(ctx, s.oidc.OrgName, s.oidc.IssuerURL, p)
	return subj, err
}
