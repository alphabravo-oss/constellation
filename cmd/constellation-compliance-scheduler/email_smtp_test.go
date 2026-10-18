package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	compliancehandler "github.com/alphabravocompany/constellation/internal/handler/compliance"
)

type smtpWireFixture struct {
	address  string
	finished chan error
}

type smtpWire struct {
	connection net.Conn
	reader     *bufio.Reader
}

func newSMTPWireFixture(t *testing.T, serve func(*smtpWire) error) *smtpWireFixture {
	t.Helper()
	var config net.ListenConfig
	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &smtpWireFixture{address: listener.Addr().String(), finished: make(chan error, 1)}
	var mutex sync.Mutex
	var active net.Conn
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		connection, err := listener.Accept()
		if err != nil {
			fixture.finished <- err
			return
		}
		defer func() { _ = connection.Close() }()
		mutex.Lock()
		active = connection
		mutex.Unlock()
		if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			fixture.finished <- err
			return
		}
		fixture.finished <- serve(&smtpWire{connection: connection, reader: bufio.NewReader(connection)})
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mutex.Lock()
		if active != nil {
			_ = active.Close()
		}
		mutex.Unlock()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Error("owned SMTP fixture did not stop")
		}
	})
	return fixture
}

func (f *smtpWireFixture) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-f.finished:
		if err != nil {
			t.Fatal("SMTP wire fixture failed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP peer did not observe client closure")
	}
}

func (w *smtpWire) reply(response string) error {
	_, err := io.WriteString(w.connection, response)
	return err
}

func (w *smtpWire) exchange(command, response string) error {
	line, err := w.reader.ReadString('\n')
	if err != nil {
		return err
	}
	if line != command+"\r\n" {
		return errors.New("unexpected SMTP command")
	}
	return w.reply(response)
}

func (w *smtpWire) closedByClient() error {
	body, err := io.ReadAll(io.LimitReader(w.reader, 4096))
	if err != nil {
		return err
	}
	if len(body) != 0 {
		return errors.New("unexpected plaintext or protocol command after refusal/cancellation")
	}
	return nil
}

func (w *smtpWire) envelope(esmtp bool) error {
	from := "MAIL FROM:<sender@example.test>"
	if esmtp {
		from += " BODY=8BITMIME"
	}
	if err := w.exchange(from, "250 sender accepted\r\n"); err != nil {
		return err
	}
	if err := w.exchange("RCPT TO:<reader@example.test>", "250 recipient accepted\r\n"); err != nil {
		return err
	}
	return w.exchange("DATA", "354 send message\r\n")
}

func (w *smtpWire) message() ([]byte, error) {
	var body bytes.Buffer
	for body.Len() <= 1<<20 {
		line, err := w.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == ".\r\n" {
			return body.Bytes(), nil
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		body.WriteString(line)
	}
	return nil, errors.New("SMTP fixture message exceeds bound")
}

func smtpEmailFixture(t *testing.T, address, user string) *daemon {
	t.Helper()
	t.Setenv("SMTP_HOST", address)
	t.Setenv("SMTP_USER", user)
	t.Setenv("SMTP_PASS", "owned-password-canary")
	t.Setenv("SMTP_FROM", "Constellation <sender@example.test>")
	return &daemon{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func (w *smtpWire) hello(user string) error {
	if err := w.reply("220 fixture ESMTP\r\n"); err != nil {
		return err
	}
	extensions := "250-fixture\r\n250 8BITMIME\r\n"
	if user != "" {
		extensions = "250-fixture\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n"
	}
	if err := w.exchange("EHLO localhost", extensions); err != nil {
		return err
	}
	if user != "" {
		auth := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00owned-password-canary"))
		return w.exchange("AUTH PLAIN "+auth, "235 authenticated\r\n")
	}
	return nil
}

func receiveSMTPReport(w *smtpWire, user string, received chan<- []byte) error {
	if err := w.hello(user); err != nil {
		return err
	}
	if err := w.envelope(true); err != nil {
		return err
	}
	message, err := w.message()
	if err != nil {
		return err
	}
	received <- message
	if err := w.reply("250 message accepted\r\n"); err != nil {
		return err
	}
	return w.exchange("QUIT", "221 goodbye\r\n")
}

func TestSMTPDeliveryPreservesEnvelopeMIMEAndAuth(t *testing.T) {
	for _, user := range []string{"", "owned-user-canary"} {
		t.Run(fmt.Sprintf("auth=%t", user != ""), func(t *testing.T) {
			received := make(chan []byte, 1)
			fixture := newSMTPWireFixture(t, func(w *smtpWire) error { return receiveSMTPReport(w, user, received) })
			d := smtpEmailFixture(t, fixture.address, user)
			report := bytes.Repeat([]byte("{\"private\":\"é\"}\x00\n"), 100)
			err := d.deliver(t.Context(), compliancehandler.DeliveryTarget{Kind: "email", Target: "Operator <reader@example.test>"}, dueSchedule{Name: "résumé", Framework: "cis"}, "/report.json", report, "signature-fixture", "json")
			if err != nil {
				t.Fatal(err)
			}
			fixture.wait(t)
			assertSMTPReportMessage(t, <-received, report)
		})
	}
}

func assertSMTPReportMessage(t *testing.T, body, report []byte) {
	t.Helper()
	message, err := mail.ReadMessage(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if message.Header.Get("From") != `"Constellation" <sender@example.test>` || message.Header.Get("To") != `"Operator" <reader@example.test>` || message.Header.Get("X-Constellation-Cosign-Signature") != "signature-fixture" {
		t.Fatal("SMTP delivery changed recorded headers")
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil || subject != "Compliance report — résumé (cis)" {
		t.Fatal("SMTP delivery changed subject")
	}
	_, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	parts := multipart.NewReader(message.Body, params["boundary"])
	text, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	_ = text.Close()
	attachment, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = attachment.Close() }()
	data, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, attachment))
	if err != nil || attachment.FileName() != "report.json" || !bytes.Equal(data, report) {
		t.Fatal("SMTP delivery changed attachment bytes or filename", err)
	}
}

func awaitSMTPFinalization(w *smtpWire) error {
	if err := w.hello(""); err != nil {
		return err
	}
	if err := w.envelope(true); err != nil {
		return err
	}
	if _, err := w.message(); err != nil {
		return err
	}
	return w.closedByClient()
}

func TestSMTPDeliveryTotalTimeoutClosesNonresponsiveServer(t *testing.T) {
	for _, stage := range []string{"greeting", "data-finalization"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newSMTPWireFixture(t, func(w *smtpWire) error {
				if stage == "data-finalization" {
					return awaitSMTPFinalization(w)
				}
				return w.closedByClient()
			})
			message := reportEmail{from: "sender@example.test", to: "reader@example.test", body: []byte("Subject: fixture\r\n\r\nreport\r\n")}
			start := time.Now()
			err := sendReportSMTP(t.Context(), fixture.address, nil, message, 250*time.Millisecond)
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
				t.Fatalf("SMTP timeout not bounded/context-inspectable: %v", err)
			}
			fixture.wait(t)
		})
	}
}

func TestSMTPDeliveryParentCancellationClosesBlockedConnection(t *testing.T) {
	ready := make(chan struct{})
	fixture := newSMTPWireFixture(t, func(w *smtpWire) error {
		close(ready)
		return w.closedByClient()
	})
	d := smtpEmailFixture(t, fixture.address, "")
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	finished := make(chan error, 1)
	go func() {
		finished <- d.deliver(ctx, compliancehandler.DeliveryTarget{Kind: "email", Target: "reader@example.test"}, dueSchedule{}, "/report.json", []byte("report"), "", "json")
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP connection never opened")
	}
	cause := errors.New("owned-cancellation-private-canary")
	cancel(cause)
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), "private-canary") {
			t.Fatal("cancellation cause lost or diagnostic disclosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP ignored parent cancellation")
	}
	fixture.wait(t)
}

func TestSMTPDeliveryPreservesShorterParentDeadline(t *testing.T) {
	fixture := newSMTPWireFixture(t, func(w *smtpWire) error { return w.closedByClient() })
	d := smtpEmailFixture(t, fixture.address, "")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := d.deliver(ctx, compliancehandler.DeliveryTarget{Kind: "email", Target: "reader@example.test"}, dueSchedule{}, "/report.json", []byte("report"), "", "json")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatal("SMTP extended the caller deadline", err)
	}
	fixture.wait(t)
}

func TestSMTPDeliveryRedactsServerFailureAndContinuesFileTarget(t *testing.T) {
	const secret = "owned-server-endpoint-credential-canary"
	fixture := newSMTPWireFixture(t, func(w *smtpWire) error {
		if err := w.hello("owned-user-canary"); err != nil {
			return err
		}
		if err := w.exchange("MAIL FROM:<sender@example.test> BODY=8BITMIME", "250 sender accepted\r\n"); err != nil {
			return err
		}
		response := "550 " + secret + " endpoint=" + w.connection.LocalAddr().String() + " user=owned-user-canary password=owned-password-canary\r\n"
		if err := w.exchange("RCPT TO:<reader@example.test>", response); err != nil {
			return err
		}
		return w.closedByClient()
	})
	d := smtpEmailFixture(t, fixture.address, "owned-user-canary")
	var logs bytes.Buffer
	d.logger = slog.New(slog.NewTextHandler(&logs, nil))
	d.outDir = t.TempDir()
	destination := filepath.Join(d.outDir, "later")
	body := []byte("private exact report\x00\n")
	schedule := dueSchedule{Delivery: []compliancehandler.DeliveryTarget{{Kind: "email", Target: "reader@example.test"}, {Kind: "file", Target: "file://" + destination}}}
	uri, err := d.deliverAll(t.Context(), schedule, filepath.Join(d.outDir, "report.json"), body, "", "json")
	var smtpError *textproto.Error
	if err == nil || !errors.As(err, &smtpError) || smtpError.Code != 550 || !strings.Contains(smtpError.Msg, secret) || !strings.Contains(smtpError.Msg, "owned-password-canary") {
		t.Fatal("SMTP server cause was lost", err)
	}
	for _, value := range []string{secret, fixture.address, "owned-password-canary", "owned-user-canary"} {
		if strings.Contains(err.Error(), value) || strings.Contains(logs.String(), value) {
			t.Fatal("SMTP error/log disclosed private diagnostics")
		}
	}
	data, readErr := fs.ReadFile(os.DirFS(destination), "report.json")
	if readErr != nil || !bytes.Equal(data, body) || uri != "file://"+filepath.Join(destination, "report.json") {
		t.Fatal("failed SMTP prevented later owned file delivery", readErr)
	}
	fixture.wait(t)
}

func TestSMTPDeliveryPreservesUnauthenticatedLegacyHELO(t *testing.T) {
	fixture := newSMTPWireFixture(t, func(w *smtpWire) error {
		if err := w.reply("220 fixture SMTP\r\n"); err != nil {
			return err
		}
		if err := w.exchange("EHLO localhost", "500 use HELO\r\n"); err != nil {
			return err
		}
		if err := w.exchange("HELO localhost", "250 fixture\r\n"); err != nil {
			return err
		}
		if err := w.envelope(false); err != nil {
			return err
		}
		if _, err := w.message(); err != nil {
			return err
		}
		if err := w.reply("250 message accepted\r\n"); err != nil {
			return err
		}
		return w.exchange("QUIT", "221 goodbye\r\n")
	})
	d := smtpEmailFixture(t, fixture.address, "")
	if err := d.deliver(t.Context(), compliancehandler.DeliveryTarget{Kind: "email", Target: "reader@example.test"}, dueSchedule{}, "/report.json", []byte("report"), "", "json"); err != nil {
		t.Fatal("unauthenticated legacy HELO delivery changed", err)
	}
	fixture.wait(t)
}

func rejectSMTPNegotiation(w *smtpWire, stage string) error {
	if err := w.reply("220 fixture ESMTP\r\n"); err != nil {
		return err
	}
	extensions := "250 fixture\r\n"
	if stage == "starttls" {
		extensions = "250-fixture\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n"
	}
	if err := w.exchange("EHLO localhost", extensions); err != nil {
		return err
	}
	if stage == "starttls" {
		if err := w.exchange("STARTTLS", "454 owned-tls-private-canary\r\n"); err != nil {
			return err
		}
	}
	return w.closedByClient()
}

func TestSMTPDeliveryRejectsUnadvertisedAuthAndSTARTTLSFailure(t *testing.T) {
	for _, stage := range []string{"auth", "starttls"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newSMTPWireFixture(t, func(w *smtpWire) error { return rejectSMTPNegotiation(w, stage) })
			d := smtpEmailFixture(t, fixture.address, "owned-user-canary")
			err := d.deliver(t.Context(), compliancehandler.DeliveryTarget{Kind: "email", Target: "reader@example.test"}, dueSchedule{}, "/report.json", []byte("report"), "", "json")
			var failure *deliveryFailure
			if !errors.As(err, &failure) || failure.operation != "smtp "+stage || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("SMTP negotiation failure changed or disclosed diagnostics", err)
			}
			fixture.wait(t)
		})
	}
}

func TestSMTPDeliveryRejectsConfiguredAuthAfterLegacyHELO(t *testing.T) {
	fixture := newSMTPWireFixture(t, func(w *smtpWire) error {
		if err := w.reply("220 fixture SMTP\r\n"); err != nil {
			return err
		}
		if err := w.exchange("EHLO localhost", "500 use HELO\r\n"); err != nil {
			return err
		}
		if err := w.exchange("HELO localhost", "250 fixture\r\n"); err != nil {
			return err
		}
		return w.closedByClient()
	})
	d := smtpEmailFixture(t, fixture.address, "owned-user-canary")
	err := d.deliver(t.Context(), compliancehandler.DeliveryTarget{Kind: "email", Target: "reader@example.test"}, dueSchedule{}, "/report.json", []byte("report"), "", "json")
	var failure *deliveryFailure
	if !errors.As(err, &failure) || failure.operation != "smtp auth" {
		t.Fatal("configured AUTH silently skipped after legacy HELO", err)
	}
	for _, secret := range []string{fixture.address, "owned-user-canary", "owned-password-canary"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("legacy AUTH refusal disclosed diagnostics")
		}
	}
	fixture.wait(t)
}
