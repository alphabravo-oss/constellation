package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/google/uuid"

	compliancehandler "github.com/alphabravocompany/constellation/internal/handler/compliance"
)

const schedulerDeliveryCanary = "scheduler-private-diagnostic-canary"

type schedulerDeliveryRoundTrip func(*http.Request) (*http.Response, error)

func (f schedulerDeliveryRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestWebhookMalformedURLFailsWithoutDispatchOrDiagnosticLeak(t *testing.T) {
	var logs bytes.Buffer
	var requests int
	d := daemon{
		logger: slog.New(slog.NewTextHandler(&logs, nil)),
		http: &http.Client{Transport: schedulerDeliveryRoundTrip(func(*http.Request) (*http.Response, error) {
			requests++
			return nil, errors.New("unexpected dispatch")
		})},
	}
	s := dueSchedule{Delivery: []compliancehandler.DeliveryTarget{{Kind: "webhook", URL: "http://" + schedulerDeliveryCanary + "@%zz/hook?token=" + schedulerDeliveryCanary}}}
	_, err := d.deliverAll(t.Context(), s, "/report.csv", []byte("evidence"), "signature", "csv")
	if err == nil || !strings.Contains(err.Error(), "webhook request construction failed") || requests != 0 {
		t.Fatalf("malformed webhook did not fail before dispatch: error=%v requests=%d", err, requests)
	}
	var cause *url.Error
	if !errors.As(err, &cause) || !strings.Contains(cause.URL, schedulerDeliveryCanary) {
		t.Fatal("request-construction cause was not retained for local inspection")
	}
	if strings.Contains(err.Error()+logs.String(), schedulerDeliveryCanary) {
		t.Fatal("request-construction diagnostics escaped through logs or public error")
	}
}

func TestWebhookFailuresKeepPrivateCausesAndStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{name: "transport"},
		{name: "upstream status", status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cause := errors.New(schedulerDeliveryCanary)
			var logs bytes.Buffer
			d := daemon{logger: slog.New(slog.NewTextHandler(&logs, nil)), http: &http.Client{Transport: schedulerDeliveryRoundTrip(func(*http.Request) (*http.Response, error) {
				if tc.status == 0 {
					return nil, cause
				}
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(schedulerDeliveryCanary))}, nil
			})}}
			err := d.deliverWebhook(t.Context(), compliancehandler.DeliveryTarget{URL: "http://10.23.4.5/hook?token=" + schedulerDeliveryCanary}, dueSchedule{}, "signature", "report.csv")
			if err == nil || strings.Contains(err.Error()+logs.String(), schedulerDeliveryCanary) {
				t.Fatal("webhook failure accepted or disclosed private diagnostics")
			}
			if tc.status == 0 && (!errors.Is(err, cause) || !strings.Contains(err.Error(), "webhook transport failed")) {
				t.Fatal("transport cause or categorical operation was lost")
			}
			if tc.status != 0 && !strings.Contains(err.Error(), "HTTP 503") {
				t.Fatal("upstream failure lost its categorical status")
			}
		})
	}
}

func TestWebhookPrivateEndpointAndPayloadRemainSupported(t *testing.T) {
	endpoint := "http://10.23.4.5:8080/operator/hook?token=" + schedulerDeliveryCanary
	schedule := dueSchedule{ID: uuid.New(), Name: "private endpoint", Framework: "cis", ReportFormat: "csv"}
	var requests int
	var logs bytes.Buffer
	d := daemon{logger: slog.New(slog.NewTextHandler(&logs, nil)), http: &http.Client{Transport: schedulerDeliveryRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.String() != endpoint || r.Method != http.MethodPost || r.Header.Get("X-Constellation-Cosign-Signature") != "fixture-signature" {
			t.Error("private destination, method or signature header changed")
		}
		var payload struct {
			ScheduleID string `json:"schedule_id"`
			Filename   string `json:"filename"`
			Signature  string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.ScheduleID != schedule.ID.String() || payload.Filename != "report.csv" || payload.Signature != "fixture-signature" {
			t.Error("webhook payload changed")
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}, nil
	})}}
	if err := d.deliverWebhook(t.Context(), compliancehandler.DeliveryTarget{URL: endpoint}, schedule, "fixture-signature", "report.csv"); err != nil || requests != 1 {
		t.Fatalf("private endpoint refused or repeated: error=%v requests=%d", err, requests)
	}
	if strings.Contains(logs.String(), schedulerDeliveryCanary) {
		t.Fatal("successful delivery logged the private endpoint query")
	}
}

type schedulerS3Call struct {
	path      string
	body      string
	signature string
}

type schedulerS3Probe struct {
	server *httptest.Server
	mu     sync.Mutex
	calls  []schedulerS3Call
}

func configureSchedulerS3Fixture(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"config", "credentials"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for key, value := range map[string]string{
		"AWS_ACCESS_KEY_ID":                "owned-fixture-access",
		"AWS_SECRET_ACCESS_KEY":            uuid.NewString(),
		"AWS_SESSION_TOKEN":                "",
		"AWS_PROFILE":                      "",
		"AWS_REGION":                       "us-east-1",
		"AWS_EC2_METADATA_DISABLED":        "true",
		"AWS_MAX_ATTEMPTS":                 "1",
		"AWS_REQUEST_CHECKSUM_CALCULATION": "WHEN_REQUIRED",
		"AWS_RESPONSE_CHECKSUM_VALIDATION": "WHEN_REQUIRED",
		"AWS_CONFIG_FILE":                  filepath.Join(dir, "config"),
		"AWS_SHARED_CREDENTIALS_FILE":      filepath.Join(dir, "credentials"),
	} {
		t.Setenv(key, value)
	}
}

func newSchedulerS3Probe(t *testing.T, failure string) *schedulerS3Probe {
	t.Helper()
	p := new(schedulerS3Probe)
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || r.Method != http.MethodPut {
			t.Error("unexpected S3 request")
		}
		p.mu.Lock()
		p.calls = append(p.calls, schedulerS3Call{path: r.URL.Path, body: string(body), signature: r.Header.Get("X-Amz-Meta-Cosign-Signature")})
		p.mu.Unlock()
		sidecar := strings.HasSuffix(r.URL.Path, ".sig")
		if failure == "artifact" && !sidecar || failure == "signature" && sidecar {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>"+schedulerDeliveryCanary+"</Message></Error>")
			return
		}
		w.Header().Set("ETag", `"owned-fixture-etag"`)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *schedulerS3Probe) recorded() []schedulerS3Call {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]schedulerS3Call(nil), p.calls...)
}

func assertSchedulerS3DeliveryError(t *testing.T, err error, want, logs string) {
	t.Helper()
	switch {
	case want == "":
		if err != nil {
			t.Fatalf("valid S3 delivery failed: %v", err)
		}
	case err == nil || !strings.Contains(err.Error(), want):
		t.Fatalf("requested upload failure was ignored: %v", err)
	default:
		var cause smithy.APIError
		if !errors.As(err, &cause) || cause.ErrorCode() != "AccessDenied" || !strings.Contains(cause.ErrorMessage(), schedulerDeliveryCanary) {
			t.Fatal("typed SDK cause was not retained for local inspection")
		}
	}
	if err != nil && strings.Contains(err.Error()+logs, schedulerDeliveryCanary) {
		t.Fatal("provider diagnostics escaped through logs or public error")
	}
}

func TestS3DeliveryRequiresEveryRequestedUpload(t *testing.T) {
	configureSchedulerS3Fixture(t)
	for _, tc := range []struct {
		name      string
		failure   string
		signature string
		want      string
		calls     int
	}{
		{name: "artifact failure", failure: "artifact", signature: "fixture-signature", want: "s3 artifact upload failed", calls: 1},
		{name: "signature failure", failure: "signature", signature: "fixture-signature", want: "s3 signature upload failed", calls: 2},
		{name: "both uploaded", signature: "fixture-signature", calls: 2},
		{name: "no signature requested", calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := newSchedulerS3Probe(t, tc.failure)
			var logs bytes.Buffer
			d := daemon{logger: slog.New(slog.NewTextHandler(&logs, nil))}
			err := d.deliverS3(t.Context(), compliancehandler.DeliveryTarget{Bucket: "reports", Prefix: "operator-prefix", Endpoint: probe.server.URL}, []byte("retained-artifact"), tc.signature, "report.csv")
			assertSchedulerS3DeliveryError(t, err, tc.want, logs.String())
			calls := probe.recorded()
			if len(calls) != tc.calls || calls[0].path != "/reports/operator-prefix/report.csv" || calls[0].body != "retained-artifact" || calls[0].signature != tc.signature {
				t.Fatal("artifact target, body, signature metadata or request count changed")
			}
			if tc.calls == 2 && (calls[1].path != calls[0].path+".sig" || calls[1].body != tc.signature) {
				t.Fatal("signature sidecar target or bytes changed")
			}
		})
	}
}
