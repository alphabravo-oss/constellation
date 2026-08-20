package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Email is the SMTP transport for the "email" receiver kind. Unlike the HTTP
// receivers it is NOT subject to the SSRF guard: a corporate SMTP relay is
// legitimately an internal host (e.g. smtp.internal:587), so blocking private
// destinations here would break the common case.
//
// The server half (Host/Port/auth/From) is global org config resolved live from
// syscfg; the recipient list is per-receiver. SendMail uses net/smtp, which
// negotiates STARTTLS automatically when the server advertises it.
//
// ponytail: stdlib net/smtp + STARTTLS on submission (587). Implicit-TLS on 465
// is not supported — add a tls.Dial path if a customer needs SMTPS.
type Email struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	STARTTLS bool // advisory: require STARTTLS (net/smtp uses it when offered regardless)
}

// SendMail sends one message to every recipient. Blocking; the dispatcher runs it
// on a worker goroutine. ctx bounds only the TCP dial (net/smtp itself is not
// context-aware).
func (e Email) SendMail(ctx context.Context, to []string, subject, body string) error {
	if strings.TrimSpace(e.Host) == "" {
		return errors.New("email: SMTP host not configured")
	}
	if len(to) == 0 {
		return errors.New("email: no recipients")
	}
	from := strings.TrimSpace(e.From)
	if from == "" {
		return errors.New("email: from address not configured")
	}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))

	// Bound the dial with ctx; hand the live connection to net/smtp so a hung
	// relay can't wedge a worker forever.
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("email: dial %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("email: smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("email: starttls: %w", err)
		}
	} else if e.STARTTLS {
		return errors.New("email: server does not offer STARTTLS but it is required")
	}

	if strings.TrimSpace(e.Username) != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return fmt.Errorf("email: auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("email: MAIL FROM: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(strings.TrimSpace(rcpt)); err != nil {
			return fmt.Errorf("email: RCPT TO %s: %w", rcpt, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("email: DATA: %w", err)
	}
	if _, err := wc.Write(buildMessage(from, to, subject, body)); err != nil {
		_ = wc.Close()
		return fmt.Errorf("email: write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("email: close body: %w", err)
	}
	return c.Quit()
}

// buildMessage renders a minimal RFC 5322 text/plain message. Subject and body are
// already plain strings (the "email" template renders a readable body).
func buildMessage(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + sanitizeHeader(subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	// Dot-stuff so a line that is just "." can't terminate the DATA stream early.
	b.WriteString(strings.ReplaceAll(body, "\r\n.", "\r\n.."))
	return []byte(b.String())
}

// sanitizeHeader strips CR/LF so a crafted title can't inject extra headers
// (SMTP header injection).
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
