package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/internal/serverless/awslambda"
)

const testPolicyJSON = `{
  "name": "deny-latest",
  "severity": "medium",
  "source": "declarative",
  "lifecycle_stages": ["DEPLOY"],
  "group": {
    "operator": "AND",
    "criteria": [
      {"field": "image.tag", "operator": "EQ", "values": ["latest"]}
    ]
  }
}`

func TestPolicyValidateCommand(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(testPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := policyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"validate", policyPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "valid Constellation policy (deny-latest)") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestPolicyValidateCommandRejectsInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"name":""}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := policyCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"validate", policyPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected invalid policy error")
	}
}

func TestPolicyCheckCommandEvaluatesRecord(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	recordPath := filepath.Join(dir, "record.json")
	if err := os.WriteFile(policyPath, []byte(testPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, []byte(`{"image":{"tag":"latest"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := policyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"check", policyPath, "--record", recordPath})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "MATCH: deny-latest matched") || !strings.Contains(out.String(), "fields=image.tag") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestBuildBackupS3URI(t *testing.T) {
	at := time.Date(2026, 6, 13, 12, 30, 0, 0, time.UTC)
	got, err := buildBackupS3URI("s3://backups/prod", "acme", at)
	if err != nil {
		t.Fatal(err)
	}
	want := "s3://backups/prod/constellation-backup-acme-2026-06-13T12:30:00Z.tar.gz"
	if got != want {
		t.Fatalf("uri = %q want %q", got, want)
	}
	if _, err := buildBackupS3URI("backups/prod", "acme", at); err == nil {
		t.Fatal("expected non-s3 destination to fail")
	}
}

func TestAWSLambdaPackageReporterPostsServerlessPayload(t *testing.T) {
	var gotPath, gotAuth string
	var got awslambda.PackageReport
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(awslambda.ReportResponse{OK: true, PackageCount: len(got.Packages)})
	}))
	defer ts.Close()

	reporter := awsLambdaPackageReporter{client: &authedClient{
		server: ts.URL,
		token:  "token-1",
		http:   ts.Client(),
	}}
	resp, err := reporter.Report(context.Background(), awslambda.PackageReport{
		FunctionRef: "arn:aws:lambda:us-east-1:123456789012:function:payments",
		Provider:    "aws",
		SourceType:  "discoverer",
		Packages: []scanner.Package{{
			Ecosystem: "pypi",
			Name:      "django",
			Version:   "4.2.0",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/serverless-packages:report" || gotAuth != "Bearer token-1" || !resp.OK || resp.PackageCount != 1 {
		t.Fatalf("path=%s auth=%s resp=%+v", gotPath, gotAuth, resp)
	}
	if got.FunctionRef == "" || len(got.Packages) != 1 || got.Packages[0].Name != "django" {
		t.Fatalf("payload = %+v", got)
	}
}

func TestRepositoryPackageReporterPostsPayload(t *testing.T) {
	var gotPath, gotAuth string
	var got repositoryPackageReport
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(repositoryReportResponse{OK: true, PackageCount: len(got.Packages), ScanTargetID: "target-1", ScanEvidenceID: "evidence-1"})
	}))
	defer ts.Close()

	var resp repositoryReportResponse
	err := repositoryPackageReporter{client: &authedClient{
		server: ts.URL,
		token:  "token-1",
		http:   ts.Client(),
	}}.Report(context.Background(), repositoryPackageReport{
		RepositoryRef: "github.com/acme/payments",
		SourceType:    "repository",
		CommitSHA:     "abcdef1234567890",
		Packages: []scanner.Package{{
			Ecosystem: "npm",
			Name:      "lodash",
			Version:   "4.17.20",
		}},
	}, &resp)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/repository-packages:report" || gotAuth != "Bearer token-1" || !resp.OK || resp.PackageCount != 1 {
		t.Fatalf("path=%s auth=%s resp=%+v", gotPath, gotAuth, resp)
	}
	if got.RepositoryRef != "github.com/acme/payments" || got.CommitSHA == "" || len(got.Packages) != 1 || got.Packages[0].Name != "lodash" {
		t.Fatalf("payload = %+v", got)
	}
}

func TestNormalizeRepositoryRemoteRef(t *testing.T) {
	cases := map[string]string{
		"https://github.com/acme/payments.git":   "github.com/acme/payments",
		"git@github.com:acme/payments.git":       "github.com/acme/payments",
		"ssh://git@github.com/acme/payments.git": "github.com/acme/payments",
	}
	for raw, want := range cases {
		if got := normalizeRepositoryRemoteRef(raw); got != want {
			t.Fatalf("normalizeRepositoryRemoteRef(%q) = %q want %q", raw, got, want)
		}
	}
}
