package identity

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	columncrypto "github.com/alphabravocompany/constellation/internal/crypto"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type runtimeConfig struct {
	settingsRecord
	RP *RP
}
type Service struct {
	sessions      sessionCache
	store         Store
	emergency     BreakGlassConfig
	org           string
	current       atomic.Pointer[runtimeConfig]
	enc           *columncrypto.Encryptor
	audit         *audit.Logger
	counter       *prometheus.CounterVec
	dummyHash     string
	passwordSlots chan struct{}
}

func New(ctx context.Context, store Store, oidc *OIDCConfig, emergency BreakGlassConfig, local LocalConfig, log *audit.Logger, registry prometheus.Registerer) (*Service, error) {
	if err := emergency.validate(); err != nil {
		return nil, err
	}
	local.defaults()
	if err := local.validate(); err != nil {
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
	for _, v := range []string{"success", "failure", "rate_limited"} {
		counter.WithLabelValues(v)
	}
	enc, _ := columncrypto.Default()
	s := &Service{store: store, emergency: emergency, org: local.OrgName, enc: enc, audit: log, counter: counter, passwordSlots: make(chan struct{}, 1)}
	var err error
	s.dummyHash, err = HashPassword(randomToken())
	if err != nil {
		return nil, err
	}
	v := settingsRecord{Local: local, OIDC: oidc}
	sealed, err := s.sealClientSecret(oidc)
	if err != nil {
		return nil, err
	}
	if err = store.writeSettings(ctx, v, sealed, nil, log); err != nil {
		return nil, err
	}
	if err = s.reload(ctx); err != nil {
		return nil, err
	}
	if err = s.bootstrap(ctx, local); err != nil {
		return nil, err
	}
	if err = s.RefreshSessions(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Service) sealClientSecret(oidc *OIDCConfig) (columncrypto.Sealed, error) {
	if oidc == nil || oidc.ClientSecret == "" {
		return columncrypto.Sealed{}, nil
	}
	if s.enc == nil {
		return columncrypto.Sealed{}, columncrypto.ErrNoKey
	}
	return s.enc.Encrypt([]byte(oidc.ClientSecret))
}
func (s *Service) reload(ctx context.Context) error {
	v, err := s.store.readSettings(ctx, s.enc)
	if err != nil {
		return err
	}
	old := s.current.Load()
	if old != nil && old.Revision == v.Revision && (old.OIDC == nil || old.RP != nil) {
		return nil
	}
	next := &runtimeConfig{settingsRecord: v}
	if old != nil && reflect.DeepEqual(old.OIDC, v.OIDC) {
		next.RP = old.RP
	}
	if v.OIDC != nil && next.RP == nil {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		next.RP, err = NewRP(bounded, *v.OIDC)
		cancel()
		if err != nil {
			slog.WarnContext(ctx, "single sign-on provider unavailable; retrying in background")
		}
	}
	s.current.Store(next)
	return nil
}
func (s *Service) Run(ctx context.Context) {
	go s.runSessions(ctx)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	nextRefresh := time.Now().Add(15 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := s.reload(ctx); err != nil {
				slog.ErrorContext(ctx, "reload sign-in settings", "error", err)
			}
			cfg := s.current.Load()
			if cfg.RP != nil && time.Now().After(nextRefresh) {
				if cfg.RP.Keys.Refresh(ctx) == nil {
					nextRefresh = time.Now().Add(15 * time.Minute)
				}
			}
			_, _ = s.store.Pool.Exec(ctx, `DELETE FROM local_login_ips WHERE ip_hash IN (SELECT ip_hash FROM local_login_ips WHERE window_start<now()-interval '10 minutes' LIMIT 1000)`)
		}
	}
}
func (s *Service) runSessions(ctx context.Context) {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			bounded, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
			if err := s.RefreshSessions(bounded); err != nil {
				slog.ErrorContext(ctx, "refresh session snapshot", "error", err)
			}
			cancel()
		}
	}
}
func (s *Service) Authenticate(ctx context.Context, raw string) (authctx.Subject, error) {
	if strings.HasPrefix(raw, "csi_") {
		return s.session(raw)
	}
	cfg := s.current.Load()
	if cfg.RP == nil {
		return authctx.Subject{}, errors.New("OIDC unavailable")
	}
	p, err := cfg.RP.Access.Verify(raw)
	if err != nil {
		return authctx.Subject{}, err
	}
	if len(p.Roles) == 0 {
		return authctx.Subject{}, errors.New("no mapped roles")
	}
	subj, _, err := s.store.resolve(ctx, cfg.OIDC.OrgName, cfg.OIDC.IssuerURL, p)
	return subj, err
}
