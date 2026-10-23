//go:build integration

package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/telemetry"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

//go:embed testdata/efficiency.sql
var efficiencySeed string

type efficiencyCounterKey struct{}
type efficiencyTracer struct{}

func (efficiencyTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	if count, ok := ctx.Value(efficiencyCounterKey{}).(*atomic.Int64); ok {
		count.Add(1)
	}
	return ctx
}
func (efficiencyTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Inventory routes selected from live request counters, with the owner's required
// image, CVE, audit and network-rule surfaces added. Summaries exercise the same
// 10k source rows but naturally return fewer than 10k aggregate rows.
var efficiencyRoutes = []string{
	"/findings", "/findings/by-cve", "/assets", "/image-scan-results", "/deployments", "/clusters",
	"/clusters/22222222-2222-2222-2222-222222222222/nodes",
	"/clusters/22222222-2222-2222-2222-222222222222/containers",
	"/clusters/22222222-2222-2222-2222-222222222222/network-rules/inventory",
	"/network/sessions", "/runtime-threats", "/compliance/checks", "/audit/events", "/cve/search",
	"/scan-jobs", "/policies", "/groups", "/runtime-policies", "/components", "/security/timeline",
	"/compliance/evidence", "/compliance/nodes", "/network/policies/lifecycle", "/compliance/summary", "/dashboard/summary",
}

var efficiencyQueryBudgets = map[string]int{
	"/findings": 3, "/findings/by-cve": 3, "/assets": 6, "/image-scan-results": 5, "/deployments": 5, "/clusters": 3,
	"/clusters/22222222-2222-2222-2222-222222222222/nodes":                   3,
	"/clusters/22222222-2222-2222-2222-222222222222/containers":              3,
	"/clusters/22222222-2222-2222-2222-222222222222/network-rules/inventory": 3,
	"/network/sessions": 6, "/runtime-threats": 6, "/compliance/checks": 6, "/audit/events": 3, "/cve/search": 2,
	"/scan-jobs": 7, "/policies": 3, "/groups": 3, "/runtime-policies": 3, "/components": 4, "/security/timeline": 4,
	"/compliance/evidence": 3, "/compliance/nodes": 3, "/network/policies/lifecycle": 7, "/compliance/summary": 3, "/dashboard/summary": 15,
}

func efficiencyServer(t testing.TB) (*httptest.Server, string, func() string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	url := os.Getenv("EFFICIENCY_DATABASE_URL")
	if url == "" {
		url = pgtest.URL(t)
	} else if !strings.Contains(url, "/efficiency_probe?") {
		t.Fatal("external benchmark requires the disposable efficiency_probe database")
	}
	database, err := db.Connect(ctx, url, db.WithTracer(efficiencyTracer{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); database.Close() })
	var seeded bool
	if err := database.Pool().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM orgs WHERE name='efficiency-fixture')").Scan(&seeded); err != nil {
		t.Fatal(err)
	}
	if !seeded {
		tx, err := database.Pool().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, efficiencySeed); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Pool().Exec(ctx, "ANALYZE"); err != nil {
			t.Fatal(err)
		}
	}
	tel, err := telemetry.Init(ctx, telemetry.Config{ServiceName: "efficiency", LogLevel: slog.LevelError})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })
	srv, err := New(ctx, Config{DatabaseURL: url, CORSOrigins: []string{"https://constellation.dev.alphabravo.io"}}, tel, database)
	if err != nil {
		t.Fatal(err)
	}
	signer := testSessionIssuer{pool: database.Pool()}
	raw, _, err := signer.Issue(uuid.MustParse("33333333-3333-3333-3333-333333333333"), uuid.MustParse("11111111-1111-1111-1111-111111111111"), "perf@example.test", []string{"GlobalAdmin"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.identity.RefreshSessions(ctx); err != nil {
		t.Fatal(err)
	}
	go srv.identity.Run(ctx)
	if _, err := database.Pool().Exec(ctx, "UPDATE identity_sessions SET expires_at=now()+interval '1 hour'"); err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := &atomic.Int64{}
		r = r.WithContext(context.WithValue(r.Context(), efficiencyCounterKey{}, count))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Set("X-Efficiency-Queries", fmt.Sprint(count.Load()))
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	if os.Getenv("EFFICIENCY_LIVE") != "" {
		live := &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = live.ListenAndServe() }()
		t.Cleanup(func() { _ = live.Close() })
	}
	renew := func() string {
		next, _, err := signer.Issue(uuid.MustParse("33333333-3333-3333-3333-333333333333"), uuid.MustParse("11111111-1111-1111-1111-111111111111"), "perf@example.test", []string{"GlobalAdmin"}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.identity.RefreshSessions(ctx); err != nil {
			t.Fatal(err)
		}
		return next
	}
	return ts, raw, renew
}

func TestEfficiencyQueryBudgets(t *testing.T) {
	ts, token, _ := efficiencyServer(t)
	base := ts.URL
	if value := os.Getenv("EFFICIENCY_BASE_URL"); value != "" {
		base = value
	}
	samples := 1
	if os.Getenv("EFFICIENCY_LIVE") != "" {
		samples = 20
		if n, err := strconv.Atoi(os.Getenv("EFFICIENCY_SAMPLES")); err == nil && n > 0 {
			samples = n
		}
	}
	client := &http.Client{Timeout: 90 * time.Second}
	if os.Getenv("EFFICIENCY_LIVE") != "" {
		for attempt := 0; attempt < 300; attempt++ {
			res, err := client.Get(base + "/healthz")
			if err == nil {
				_ = res.Body.Close()
				if res.StatusCode == 200 {
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	for _, route := range efficiencyRoutes {
		if filter := os.Getenv("EFFICIENCY_ROUTE_FILTER"); filter != "" && !strings.Contains(route, filter) {
			continue
		}
		t.Run(route, func(t *testing.T) {
			var times []float64
			var counts []string
			responseBytes := 0
			for _, limit := range []string{"1", "50"} {
				measured := samples
				if limit == "1" {
					measured = 1
				}
				for i := 0; i < measured+1; i++ {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/api/v1"+route+"?cluster_id=22222222-2222-2222-2222-222222222222&limit="+limit, nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Authorization", "Bearer "+token)
					req.Header.Set("Origin", "https://constellation.dev.alphabravo.io")
					req.Header.Set("X-Constellation-Client", "browser")
					start := time.Now()
					res, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(res.Body)
					_ = res.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if res.StatusCode != 200 {
						t.Logf("EFFICIENCY_RESULT {\"route\":%q,\"status\":%d,\"elapsed_ms\":%f}", route, res.StatusCode, float64(time.Since(start).Microseconds())/1000)
						t.Fatalf("status %d: %s", res.StatusCode, body)
					}
					if key, ok := map[string]string{"/clusters": "clusters", "/groups": "groups", "/policies": "policies", "/runtime-policies": "policies"}[route]; ok {
						var response map[string]json.RawMessage
						if err := json.Unmarshal(body, &response); err != nil {
							t.Fatal(err)
						}
						var page []json.RawMessage
						if err := json.Unmarshal(response[key], &page); err != nil {
							t.Fatal(err)
						}
						size, _ := strconv.Atoi(limit)
						if len(page) != size {
							t.Fatalf("bounded %s page: got %d, want %d", route, len(page), size)
						}
					}
					responseBytes = len(body)
					if i == 0 {
						if time.Since(start) > time.Second && measured > 3 {
							measured = 3
						}
						continue
					}
					counts = append(counts, res.Header.Get("X-Efficiency-Queries"))
					if limit == "50" {
						times = append(times, float64(time.Since(start).Microseconds())/1000)
					}
				}
			}
			// One cache refresh may add a role lookup. Budgets include that cold
			// path and all transaction/authentication queries, at both page sizes.
			budget := efficiencyQueryBudgets[route]
			if budget == 0 {
				t.Fatal("route has no query budget")
			}
			minCount, maxCount := 1000000, 0
			for _, raw := range counts {
				count, err := strconv.Atoi(raw)
				if err != nil || count < 1 || count > budget {
					t.Fatalf("query span budget %d exceeded: %v", budget, counts)
				}
				if count < minCount {
					minCount = count
				}
				if count > maxCount {
					maxCount = count
				}
			}
			sort.Float64s(times)
			percentile := func(p float64) float64 { return times[int(math.Ceil(float64(len(times))*p))-1] }
			result := map[string]any{"route": route, "samples": len(times), "p50_ms": percentile(.50), "p95_ms": percentile(.95), "p99_ms": percentile(.99), "queries": minCount, "queries_max": maxCount, "response_bytes": responseBytes}
			out, _ := json.Marshal(result)
			t.Log("EFFICIENCY_RESULT " + string(out))
		})
	}
}

func BenchmarkEfficiencyHandlers(b *testing.B) {
	ts, token, renew := efficiencyServer(b)
	for _, route := range efficiencyRoutes {
		if filter := os.Getenv("EFFICIENCY_ROUTE_FILTER"); filter != "" && !strings.Contains(route, filter) {
			continue
		}
		b.Run(route, func(b *testing.B) {
			token = renew()
			b.ReportAllocs()
			iterations := 0
			for b.Loop() {
				// Respect the normal per-token ceiling without timing credential issuance.
				if iterations > 0 && iterations%300 == 0 {
					b.StopTimer()
					token = renew()
					b.StartTimer()
				}
				iterations++
				req, err := http.NewRequestWithContext(b.Context(), http.MethodGet, ts.URL+"/api/v1"+route+"?cluster_id=22222222-2222-2222-2222-222222222222&limit=50", nil)
				if err != nil {
					b.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				res, err := ts.Client().Do(req)
				if err != nil {
					b.Fatal(err)
				}
				_, err = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				if err != nil {
					b.Fatal(err)
				}
				if res.StatusCode != 200 {
					b.Fatal(res.StatusCode)
				}
			}
		})
	}
}
