package backup

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScheduleDestination(t *testing.T) {
	for _, tc := range []struct {
		name  string
		s     schedule
		valid bool
	}{
		{"local", schedule{}, true},
		{"remote", schedule{S3Bucket: "backups", S3Prefix: "team//one/"}, true},
		{"missing bucket", schedule{S3Endpoint: "https://example.com"}, false},
		{"bucket contains path", schedule{S3Bucket: "backups/team"}, false},
		{"endpoint credentials", schedule{S3Bucket: "backups", S3Endpoint: "https://user:password@example.com"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scheduleDestination(tc.s, "archive.tar.gz")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestScheduledArtifactReadBack(t *testing.T) {
	for _, mode := range []string{"success", "corrupt", "truncated", "extra", "upload failure", "read failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("AWS_ACCESS_KEY_ID", "test")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
			t.Setenv("AWS_REGION", "us-east-1")
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
			t.Setenv("AWS_REQUEST_CHECKSUM_CALCULATION", "WHEN_REQUIRED")
			var mu sync.Mutex
			var body []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path != "/backups/team/archive.tar.gz" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				switch r.Method {
				case http.MethodPut:
					if mode == "upload failure" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					var err error
					body, err = io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
				case http.MethodGet:
					if mode == "read failure" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					output := append([]byte(nil), body...)
					switch mode {
					case "corrupt":
						output[0] ^= 1
					case "truncated":
						output = output[:len(output)-1]
					case "extra":
						output = append(output, 'x')
					}
					_, _ = w.Write(output)
				default:
					t.Errorf("unexpected method: %s", r.Method)
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "backup")
			if err := os.WriteFile(path, []byte("signed archive contents"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			digest, err := uploadScheduledArtifact(ctx, "s3://backups/team/archive.tar.gz", server.URL, path, int64(len("signed archive contents")))
			if mode == "success" {
				if err != nil || len(digest) != 64 {
					t.Fatalf("digest=%s err=%v", digest, err)
				}
			} else if err == nil {
				t.Fatal("accepted failed upload/read-back")
			}
			if err != nil && strings.Contains(err.Error(), server.URL) {
				t.Fatal("error exposed destination")
			}
		})
	}
}

func TestRetentionNeverDeletesLastCopy(t *testing.T) {
	now := time.Now()
	records := []backupRecord{{StartedAt: now.Add(-100 * 24 * time.Hour)}}
	if victims := retentionVictims(records, 0, 1, now); len(victims) != 0 {
		t.Fatal("age deleted last copy")
	}
	if victims := retentionVictims(records, 5, 1, now); len(victims) != 0 {
		t.Fatal("age violated keep floor")
	}
}
