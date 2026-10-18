package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"time"
)

const smtpDeliveryTimeout = 30 * time.Second

// One total deadline covers dialing, greeting, TLS, AUTH, DATA and QUIT.
// WithTimeout retains any earlier caller deadline; cancellation also closes the
// connection so blocked protocol I/O does not wait for the socket deadline.
func sendReportSMTP(parent context.Context, address string, auth smtp.Auth, message reportEmail, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	connection, err := new(net.Dialer).DialContext(ctx, "tcp", address)
	if err != nil {
		return smtpFailure(ctx, "connect", err)
	}
	defer func() { _ = connection.Close() }()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = connection.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return smtpFailure(ctx, "deadline", err)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return smtpFailure(ctx, "address", err)
	}
	return sendSMTPClient(ctx, connection, host, auth, message)
}

func sendSMTPClient(ctx context.Context, connection net.Conn, host string, auth smtp.Auth, message reportEmail) error {
	client, err := smtp.NewClient(connection, host)
	if err != nil {
		return smtpFailure(ctx, "greeting", err)
	}
	defer func() { _ = client.Close() }()
	err = client.Hello("localhost")
	if err != nil {
		return smtpFailure(ctx, "hello", err)
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		// Match SendMail: opportunistic STARTTLS with normal certificate and
		// hostname verification, and no plaintext fallback after an error.
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return smtpFailure(ctx, "starttls", err)
		}
	}
	if auth != nil {
		if ok, _ := client.Extension("AUTH"); !ok {
			return smtpFailure(ctx, "auth", errors.New("smtp: server doesn't support AUTH"))
		}
		if err := client.Auth(auth); err != nil {
			return smtpFailure(ctx, "auth", err)
		}
	}
	return sendSMTPContent(ctx, client, message)
}

func sendSMTPContent(ctx context.Context, client *smtp.Client, message reportEmail) error {
	if err := client.Mail(message.from); err != nil {
		return smtpFailure(ctx, "sender", err)
	}
	if err := client.Rcpt(message.to); err != nil {
		return smtpFailure(ctx, "recipient", err)
	}
	writer, err := client.Data()
	if err != nil {
		return smtpFailure(ctx, "data", err)
	}
	if _, err := writer.Write(message.body); err != nil {
		return smtpFailure(ctx, "message", err)
	}
	if err := writer.Close(); err != nil {
		return smtpFailure(ctx, "message finalization", err)
	}
	if err := client.Quit(); err != nil {
		return smtpFailure(ctx, "quit", err)
	}
	return nil
}

func smtpFailure(ctx context.Context, operation string, err error) error {
	cause := context.Cause(ctx)
	// A socket deadline can win the race with the context timer. Preserve the
	// deadline identity even when the runtime has not yet published ctx.Err().
	if deadline, ok := ctx.Deadline(); cause == nil && ok && !time.Now().Before(deadline) {
		cause = context.DeadlineExceeded
	}
	return &deliveryFailure{operation: "smtp " + operation, cause: errors.Join(err, ctx.Err(), cause)}
}
