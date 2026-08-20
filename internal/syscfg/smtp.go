package syscfg

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/notify"
)

// SMTPSender returns the org's LIVE global SMTP server as a notify.Email (server
// half only; the dispatcher fills recipients per-receiver), or (_, false) when no
// SMTP host is configured. Called per-send so a PATCH to smtp.* switches the relay
// WITHOUT a restart, mirroring SyslogSender.
func (p *Provider) SMTPSender(ctx context.Context, orgID uuid.UUID) (notify.Email, bool) {
	cfg := p.Get(ctx, orgID)
	if strings.TrimSpace(cfg.SMTP.Host) == "" {
		return notify.Email{}, false
	}
	port := cfg.SMTP.Port
	if port == 0 {
		port = 587
	}
	return notify.Email{
		Host:     cfg.SMTP.Host,
		Port:     port,
		Username: cfg.SMTP.Username,
		Password: cfg.SMTP.Password,
		From:     cfg.SMTP.From,
		STARTTLS: cfg.SMTP.STARTTLS,
	}, true
}
