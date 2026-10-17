package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	compliancehandler "github.com/alphabravocompany/constellation/internal/handler/compliance"
)

func TestEmailDeliveryRejectsMissingConfigurationAndRecipient(t *testing.T) {
	d := daemon{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, tc := range []struct{ name, host, recipient, want string }{
		{"missing host", "", "reader@example.test", "SMTP_HOST is required"},
		{"blank host", " \t", "reader@example.test", "SMTP_HOST is required"},
		{"missing recipient", "smtp.example.test", "", "target email required"},
		{"blank recipient", "smtp.example.test", " \t", "target email required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SMTP_HOST", tc.host)
			err := d.deliver(context.Background(), compliancehandler.DeliveryTarget{Kind: "email", Target: tc.recipient}, dueSchedule{}, "/report.csv", []byte("evidence"), "", "csv")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("delivery must fail before SMTP dispatch: %v", err)
			}
		})
	}
}
