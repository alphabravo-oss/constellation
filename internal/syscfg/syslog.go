package syscfg

import (
	"context"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/notify"
)

// CONSUMER (b): syslog/SIEM target for the audit/notifier sender.
//
// SyslogSender returns a configured *notify.Syslog for org's LIVE syslog/SIEM target,
// or (nil, false) when no target is configured. The audit/notifier path calls this on
// each send so a PATCH to syslog_siem_target switches the destination WITHOUT a restart
// (the Provider cache is refreshed by the reloader). Returning a fresh sender per call
// is cheap — notify.Syslog dials lazily inside Send.
func (p *Provider) SyslogSender(ctx context.Context, orgID uuid.UUID) (*notify.Syslog, bool) {
	t := p.Get(ctx, orgID).SyslogSIEM
	addr := t.Addr()
	if addr == "" {
		return nil, false
	}
	network := t.Protocol
	if network == "" {
		network = "udp"
	}
	// The TLS toggle (or protocol "tls") selects the crypto/tls transport.
	if t.TLS || network == "tls" {
		network = "tls"
	}
	s := notify.NewSyslog(network, addr)
	s.CACertPEM = t.CACert
	s.ClientCertPEM = t.ClientCert
	s.ClientKeyPEM = t.ClientKey
	s.Format = t.Format
	s.MinLevel = t.MinLevel
	s.Categories = t.Categories
	return s, true
}
