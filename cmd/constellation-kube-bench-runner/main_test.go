package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostReportShapesPayload(t *testing.T) {
	report := []byte(`{"Controls":[{"id":"1","text":"Master Node"}]}`)

	var gotAuth, gotContentType, gotMethod, gotQuery string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotQuery = r.URL.RawQuery
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"inserted":1}`)
	}))
	defer srv.Close()

	endpoint := srv.URL + "/api/v1/compliance/ingest?profile=kube-bench"
	if err := postReport(context.Background(), srv.Client(), endpoint, "secret-token", report); err != nil {
		t.Fatalf("postReport: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want Bearer secret-token", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotQuery != "profile=kube-bench" {
		t.Errorf("query = %q, want profile=kube-bench", gotQuery)
	}
	if string(gotBody) != string(report) {
		t.Errorf("body = %q, want %q (must POST the raw report unchanged)", gotBody, report)
	}
}

func TestPostReportSurfacesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"unknown profile"}`)
	}))
	defer srv.Close()

	err := postReport(context.Background(), srv.Client(), srv.URL+"/api/v1/compliance/ingest?profile=bogus", "tok", []byte(`{}`))
	if err == nil {
		t.Fatal("expected error on 4xx response, got nil")
	}
}
