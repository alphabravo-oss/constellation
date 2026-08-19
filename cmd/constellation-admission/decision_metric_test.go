package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admission/v1"

	"github.com/alphabravocompany/constellation/pkg/observability"
)

type allowEngine struct{}

func (allowEngine) Evaluate(_ context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
}

// TestValidateHandlerRecordsAllow asserts validateHandler wires the real decision
// path into the admission_decisions_total Prometheus counter (allow branch).
func TestValidateHandlerRecordsAllow(t *testing.T) {
	tel, err := observability.Init(context.Background(), "test-admission-metric")
	if err != nil {
		t.Fatalf("observability init: %v", err)
	}
	h := validateHandler(allowEngine{}, tel)
	body, _ := json.Marshal(admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{}})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body)))

	if got := testutil.ToFloat64(tel.AdmissionDecisions.WithLabelValues("allow", "")); got != 1 {
		t.Fatalf("admission_decisions_total{result=allow} = %v, want 1", got)
	}
}
