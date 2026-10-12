package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

func TestReportEmailRejectsHeaderInjection(t *testing.T) {
	base := []string{"sender@example.test", "reader@example.test", "report", "cis", "signature", "report.json"}
	for field := range base {
		for _, injection := range []string{"\r\nBcc: attacker@example.test", "\nBcc: attacker@example.test", "\x00"} {
			args := append([]string{}, base...)
			args[field] += injection
			if _, err := makeReportEmail(args[0], args[1], args[2], args[3], args[4], args[5], nil); err == nil {
				t.Errorf("field %d accepted injection %q", field, injection)
			}
		}
	}
	for _, address := range []string{"invalid", "one@example.test, two@example.test"} {
		if _, err := makeReportEmail(base[0], address, base[2], base[3], base[4], base[5], nil); err == nil {
			t.Errorf("accepted non-single mailbox %q", address)
		}
	}
}

func TestReportEmailMIMEAttachmentRoundTrip(t *testing.T) {
	report := bytes.Repeat([]byte("{\"evidence\":\"é\"}\n"), 500)
	message, err := makeReportEmail("Constellation <sender@example.test>", "Operator <reader@example.test>", "résumé", "cis", "signed", "résumé.json", report)
	if err != nil {
		t.Fatal(err)
	}
	if message.from != "sender@example.test" || message.to != "reader@example.test" {
		t.Fatal("SMTP envelope contains display names")
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(message.body))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil || subject != "Compliance report — résumé (cis)" {
		t.Fatalf("subject=%q err=%v", subject, err)
	}
	if parsed.Header.Get("Bcc") != "" {
		t.Fatal("injected header")
	}
	_, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	parts := multipart.NewReader(parsed.Body, params["boundary"])
	first, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	attachment, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	defer attachment.Close()
	if attachment.FileName() != "résumé.json" {
		t.Fatalf("filename=%q", attachment.FileName())
	}
	encoded, err := io.ReadAll(attachment)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(encoded)), "\r\n") {
		if len(line) > 76 {
			t.Fatal("attachment line exceeds MIME limit")
		}
	}
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(encoded)))
	if err != nil || !bytes.Equal(decoded, report) {
		t.Fatalf("attachment changed: %v", err)
	}
}
