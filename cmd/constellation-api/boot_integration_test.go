//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// Guide ch.02 proof: two API replicas boot at the same time against a fresh
// database. Exactly one applies the embedded migration set (the other waits on
// the advisory lock and finds nothing pending) and both end up serving
// /healthz.
func TestTwoReplicasBootConcurrentlyOnFreshDatabase(t *testing.T) {
	t.Parallel()
	bin := buildAPI(t)
	dsn := pgtest.FreshURL(t)

	type replica struct {
		cmd    *exec.Cmd
		stdout *lockedBuffer
		api    string
		admin  string
	}
	const n = 2
	replicas := make([]*replica, n)
	for i := range n {
		r := &replica{api: freeAddr(t), admin: freeAddr(t), stdout: &lockedBuffer{}}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		r.cmd = exec.CommandContext(ctx, bin, "--listen", r.api)
		r.cmd.Env = append(os.Environ(),
			"DATABASE_URL="+dsn,
			"ADMIN_LISTEN_ADDR="+r.admin,
			"LOG_LEVEL=info",
			"CONSTELLATION_HEARTBEAT_DISABLED=true",
		)
		r.cmd.Stdout = r.stdout
		r.cmd.Stderr = r.stdout
		r.cmd.Cancel = func() error { return r.cmd.Process.Signal(syscall.SIGTERM) }
		r.cmd.WaitDelay = 10 * time.Second
		replicas[i] = r
	}
	// Start both as close together as the OS allows.
	var wg sync.WaitGroup
	for _, r := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.cmd.Start(); err != nil {
				t.Errorf("start replica: %v", err)
			}
		}()
	}
	wg.Wait()
	t.Cleanup(func() {
		for _, r := range replicas {
			if r.cmd.Process != nil {
				_ = r.cmd.Process.Signal(syscall.SIGTERM)
				_ = r.cmd.Wait()
			}
		}
	})

	for i, r := range replicas {
		waitHealthy(t, "http://"+r.api+"/healthz", 2*time.Minute, func() string { return r.stdout.String() })
		waitHealthy(t, "http://"+r.admin+"/readyz", 30*time.Second, func() string { return r.stdout.String() })
		t.Logf("replica %d healthy on %s (admin %s)", i, r.api, r.admin)
	}

	appliers, total := 0, 0
	for i, r := range replicas {
		applied, ok := migratedLine(r.stdout.String())
		if !ok {
			t.Fatalf("replica %d never logged \"database migrated\":\n%s", i, r.stdout.String())
		}
		total++
		if applied > 0 {
			appliers++
			if applied != database.Count() {
				t.Fatalf("replica %d applied %d migrations, embedded set has %d", i, applied, database.Count())
			}
		}
	}
	if total != n || appliers != 1 {
		t.Fatalf("expected exactly one of %d replicas to apply migrations, got %d", n, appliers)
	}
}

func buildAPI(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "constellation-api")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, ".")
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitHealthy(t *testing.T, url string, timeout time.Duration, logs func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not healthy after %s (last err %v)\n%s", url, timeout, err, logs())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// migratedLine finds the runner's summary line and returns its applied count.
func migratedLine(logs string) (int, bool) {
	sc := bufio.NewScanner(strings.NewReader(logs))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "database migrated") {
			continue
		}
		var rec struct {
			Msg     string `json:"msg"`
			Message string `json:"message"` // zerolog's default message key
			Applied int    `json:"applied"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err == nil && (rec.Msg == "database migrated" || rec.Message == "database migrated") {
			return rec.Applied, true
		}
		// text handler fallback
		if _, after, ok := strings.Cut(line, "applied="); ok {
			var n int
			_, _ = fmt.Sscanf(after, "%d", &n)
			return n, true
		}
	}
	return 0, false
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
