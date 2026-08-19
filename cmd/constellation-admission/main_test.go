package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

func TestValidateEndpoint_AdmissionReviewFixtures(t *testing.T) {
	engine := admission.NewEngine()
	srv := httptest.NewServer(validateHandler(engine, nil))
	defer srv.Close()

	cases := []struct {
		name          string
		fixture       string
		wantAllowed   bool
		wantWarnings  bool
		wantUID       string
		wantMsgSubstr string
	}{
		{
			name: "privileged pod denied", fixture: "testdata/admissionreviews/pod-privileged.json",
			wantAllowed: false, wantUID: "fixture-privileged",
			wantMsgSubstr: `denied by constellation policy "block-privileged": container "app" is privileged`,
		},
		{
			name: "privileged ephemeral container denied", fixture: "testdata/admissionreviews/pod-ephemeral-privileged.json",
			wantAllowed: false, wantUID: "fixture-ephemeral",
			wantMsgSubstr: `denied by constellation policy "block-privileged": container "debugger" is privileged`,
		},
		{
			name: "compliant pod allowed", fixture: "testdata/admissionreviews/pod-compliant.json",
			wantAllowed: true, wantUID: "fixture-compliant",
		},
		{
			name: "unsigned writable pod allowed with warnings", fixture: "testdata/admissionreviews/pod-monitor-warnings.json",
			wantAllowed: true, wantWarnings: true, wantUID: "fixture-monitor",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := os.ReadFile(tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status: %d", resp.StatusCode)
			}
			var out admissionv1.AdmissionReview
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			if out.Response == nil {
				t.Fatal("missing AdmissionReview response")
			}
			if string(out.Response.UID) != tc.wantUID {
				t.Fatalf("uid=%q want %q", out.Response.UID, tc.wantUID)
			}
			if out.Response.Allowed != tc.wantAllowed {
				t.Fatalf("allowed=%v want %v response=%+v", out.Response.Allowed, tc.wantAllowed, out.Response)
			}
			if tc.wantWarnings && len(out.Response.Warnings) == 0 {
				t.Fatalf("expected monitor warnings, got none")
			}
			if !tc.wantWarnings && len(out.Response.Warnings) != 0 {
				t.Fatalf("unexpected warnings: %v", out.Response.Warnings)
			}
			msg := ""
			if out.Response.Result != nil {
				msg = out.Response.Result.Message
			}
			if tc.wantMsgSubstr != "" && !strings.Contains(msg, tc.wantMsgSubstr) {
				t.Fatalf("message=%q want substring %q", msg, tc.wantMsgSubstr)
			}
		})
	}
}

func TestValidateEndpoint_RejectsMalformedAdmissionReview(t *testing.T) {
	srv := httptest.NewServer(validateHandler(admission.NewEngine(), nil))
	defer srv.Close()

	cases := []struct {
		name string
		body string
		want int
	}{
		{name: "bad json", body: `{"kind":`, want: http.StatusBadRequest},
		{name: "missing request", body: `{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1"}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(srv.URL, "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status=%d want %d", resp.StatusCode, tc.want)
			}
		})
	}
}
