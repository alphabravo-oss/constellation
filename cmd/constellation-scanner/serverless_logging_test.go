package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerlessFailureDoesNotLogOrReportPresignedCredentials(t *testing.T) {
	for _, useSource := range []bool{false, true} {
		t.Run(map[bool]string{false: "target_ref", true: "source_ref"}[useSource], func(t *testing.T) {
			var logs bytes.Buffer
			reported := make(chan string, 1)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				if err != nil {
					t.Error(err)
				}
				reported <- string(body)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer api.Close()
			w := &worker{logger: slog.New(slog.NewTextHandler(&logs, nil)), controlPlane: api.URL,
				artifactHTTPClient: &http.Client{Transport: &http.Transport{}}}
			job := &scanJob{ID: "redaction-job", TargetID: "function-id", TargetType: "serverless"}
			artifactURL := "http://127.0.0.1/bundle.zip?X-Amz-Signature=" + t.Name()
			if useSource {
				job.SourceRef = artifactURL
			} else {
				job.TargetRef = artifactURL
			}
			w.executeJob(t.Context(), job)
			assertArtifactFailureRedacted(t, reported, logs.String(), w.lastError())
		})
	}
}

func assertArtifactFailureRedacted(t *testing.T, reported <-chan string, outputs ...string) {
	t.Helper()
	select {
	case body := <-reported:
		outputs = append(outputs, body)
	default:
		t.Fatal("failed artifact scan was not reported")
	}
	for _, output := range outputs {
		if strings.Contains(output, t.Name()) || strings.Contains(output, "X-Amz-Signature") {
			t.Fatal("presigned artifact credential reached logs or failure report")
		}
	}
}
