package gcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type httpFunc func(*http.Request) (*http.Response, error)

func (client httpFunc) Do(request *http.Request) (*http.Response, error) {
	return client(request)
}

func responseJSON(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func TestScanStoragePaginatesAndRetainsEvidenceOnFailure(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "partial"}[failSecond], func(t *testing.T) {
			pages := 0
			connector := New("token", "project")
			connector.HTTP = httpFunc(func(request *http.Request) (*http.Response, error) {
				if request.Header.Get("Authorization") != "Bearer token" {
					t.Fatal("missing request authentication")
				}
				if strings.HasSuffix(request.URL.Path, "/iam") {
					if failSecond && strings.Contains(request.URL.Path, "/second/") {
						return responseJSON(http.StatusForbidden, "SECRET-BODY"), nil
					}
					return responseJSON(http.StatusOK, `{"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"]}]}`), nil
				}
				pages++
				if request.URL.Query().Get("pageToken") == "next+/=" {
					return responseJSON(http.StatusOK, `{"items":[{"name":"second"}]}`), nil
				}
				return responseJSON(http.StatusOK, `{"items":[{"name":"first"}],"nextPageToken":"next+/="}`), nil
			})
			findings, err := connector.ScanStorage(context.Background())
			if pages != 2 {
				t.Fatalf("expected two pages, got %d", pages)
			}
			if failSecond {
				if err == nil || len(findings) != 1 || strings.Contains(err.Error(), "SECRET-BODY") {
					t.Fatalf("expected partial evidence and redacted error, findings=%+v err=%v", findings, err)
				}
			} else if err != nil || len(findings) != 2 {
				t.Fatalf("missing second-page finding: %+v, %v", findings, err)
			}
		})
	}
}

func TestScanStorageNestedFailuresNeverReportComplete(t *testing.T) {
	for _, failure := range []string{"http", "transport", "malformed", "null", "oversized"} {
		t.Run(failure, func(t *testing.T) {
			connector := New("token", "project")
			connector.HTTP = httpFunc(func(request *http.Request) (*http.Response, error) {
				if strings.Contains(request.URL.Path, "getIamPolicy") {
					return responseJSON(200, `{"bindings":[]}`), nil
				}
				if !strings.HasSuffix(request.URL.Path, "/iam") {
					return responseJSON(200, `{"items":[{"name":"bucket"}]}`), nil
				}
				switch failure {
				case "http":
					return responseJSON(403, "SECRET-BODY"), nil
				case "transport":
					return nil, errors.New("transport unavailable")
				case "malformed":
					return responseJSON(200, "SECRET-BODY"), nil
				case "null":
					return responseJSON(200, "null"), nil
				default:
					return responseJSON(200, `{"padding":"`+strings.Repeat("x", 4<<20)+`"}`), nil
				}
			})
			_, err := connector.Scan(context.Background())
			if err == nil || !strings.Contains(err.Error(), "scan incomplete") || strings.Contains(err.Error(), "SECRET-BODY") {
				t.Fatalf("expected redacted incomplete-scan error: %v", err)
			}
		})
	}
}

func TestScanStorageRejectsPaginationCycle(t *testing.T) {
	requests := 0
	connector := New("token", "project")
	connector.HTTP = httpFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests > 2 {
			t.Fatal("pagination did not stop on repeated token")
		}
		return responseJSON(200, `{"items":[],"nextPageToken":"repeat"}`), nil
	})
	if _, err := connector.ScanStorage(context.Background()); err == nil {
		t.Fatal("pagination cycle reported as complete")
	}
}
