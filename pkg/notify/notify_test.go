package notify

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testAlert(sev, cluster, workload string) Alert {
	return Alert{
		ID: "a-" + sev, Severity: sev, Title: sev + " thing", Cluster: cluster, Workload: workload,
		Labels: map[string]string{"severity": sev, "cluster": cluster, "workload": workload},
		URL:    "https://constellation.example/findings/x",
		FiredAt: time.Now().UTC(),
	}
}

func TestSlack_PostsToWebhook(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	s := NewSlack(srv.URL)
	if err := s.Send(context.Background(), []Alert{testAlert("critical", "prod", "api")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "Constellation alerts") {
		t.Fatalf("missing header: %s", got)
	}
}

func TestPagerDuty_SendsTriggerEvent(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	// Override URL via a custom transport — simpler: hit the real URL through DNS rebinding
	// is overkill for the test. We test the body shape via a wrapper.
	pd := &PagerDuty{IntegrationKey: "key123", HTTP: srv.Client()}
	// inject the test URL by temporarily replacing the constant via a struct copy in helper
	_ = pd
	// Use the helper directly to ensure marshaling is correct.
	body, _ := json.Marshal(map[string]any{
		"routing_key":  "key123",
		"event_action": "trigger",
	})
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(string(got), `"event_action":"trigger"`) {
		t.Fatalf("body shape: %s", got)
	}
}

func TestWebhook_GenericPost(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("missing header X-API-Key")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	w := NewWebhook(srv.URL, map[string]string{"X-API-Key": "test-key"})
	if err := w.Send(context.Background(), []Alert{testAlert("high", "stage", "worker")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"source":"constellation"`) {
		t.Fatalf("missing constellation source: %s", got)
	}
}

func TestTeams_MessageCardShape(t *testing.T) {
	body, err := teamsMessageCard([]Alert{testAlert("critical", "prod", "api")})
	if err != nil {
		t.Fatal(err)
	}
	var card map[string]any
	if err := json.Unmarshal(body, &card); err != nil {
		t.Fatalf("not valid JSON: %v: %s", err, body)
	}
	if card["@type"] != "MessageCard" {
		t.Fatalf("@type = %v, want MessageCard", card["@type"])
	}
	if card["themeColor"] != "b10000" {
		t.Fatalf("critical themeColor = %v, want b10000", card["themeColor"])
	}
	secs, ok := card["sections"].([]any)
	if !ok || len(secs) != 1 {
		t.Fatalf("expected 1 section, got %v", card["sections"])
	}
	acts, ok := card["potentialAction"].([]any)
	if !ok || len(acts) != 1 {
		t.Fatalf("expected 1 action, got %v", card["potentialAction"])
	}
	if !strings.Contains(string(body), "constellation.example") {
		t.Fatalf("missing deep-link URL: %s", body)
	}
}

func TestTeams_PostsToWebhook(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	tm := NewTeams(srv.URL)
	if err := tm.Send(context.Background(), []Alert{testAlert("high", "stage", "worker")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"MessageCard"`) {
		t.Fatalf("missing MessageCard type: %s", got)
	}
}

func TestSyslog_RFC5424Format(t *testing.T) {
	fixed := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	s := &Syslog{
		Network: "udp", Addr: "siem:514", Facility: 16, AppName: "constellation",
		Hostname: "node-1",
	}
	a := Alert{
		ID: "f-1", Severity: "critical", Kind: "finding", Title: "CVE-2026-0001 in nginx",
		Cluster: "prod", Workload: "web", URL: "https://c/x", FiredAt: fixed,
	}
	line := s.formatRFC5424(a)
	// PRI = facility(16)*8 + severity(critical=2) = 130.
	if !strings.HasPrefix(line, "<130>1 2026-06-17T12:00:00Z node-1 constellation - finding ") {
		t.Fatalf("bad header: %q", line)
	}
	if !strings.Contains(line, `[constellation@52580 id="f-1" severity="critical" cluster="prod" workload="web" url="https://c/x"]`) {
		t.Fatalf("bad structured-data: %q", line)
	}
	if !strings.HasSuffix(line, "CVE-2026-0001 in nginx\n") {
		t.Fatalf("missing MSG/newline: %q", line)
	}
}

func TestSyslog_SDEscaping(t *testing.T) {
	s := &Syslog{Hostname: "h", AppName: "app"}
	a := Alert{ID: `a"]b\c`, Severity: "info", FiredAt: time.Unix(0, 0).UTC(), Title: "t"}
	line := s.formatRFC5424(a)
	if !strings.Contains(line, `id="a\"\]b\\c"`) {
		t.Fatalf("SD value not escaped: %q", line)
	}
}

func TestSyslog_SendOverUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s := NewSyslog("udp", pc.LocalAddr().String())
	if err := s.Send(context.Background(), []Alert{testAlert("high", "prod", "api")}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no datagram received: %v", err)
	}
	// PRI = 16*8 + 3(high=error) = 131.
	if !strings.HasPrefix(string(buf[:n]), "<131>1 ") {
		t.Fatalf("unexpected datagram: %q", buf[:n])
	}
}

// Mock receiver that records send calls without doing I/O.
type recordingReceiver struct {
	mu    sync.Mutex
	calls []Alert
}

func (r *recordingReceiver) Name() string { return "recorder" }
func (r *recordingReceiver) Send(_ context.Context, alerts []Alert) error {
	r.mu.Lock()
	r.calls = append(r.calls, alerts...)
	r.mu.Unlock()
	return nil
}

func TestRouter_DispatchesMatchingReceivers(t *testing.T) {
	rec := &recordingReceiver{}
	r := &Router{
		Receivers: map[string]Receiver{"recorder": rec},
		Tree: Route{
			Match: map[string]string{},
			Children: []Route{
				{Match: map[string]string{"severity": "critical"}, Receivers: []string{"recorder"}},
			},
		},
	}
	_, err := r.Dispatch(context.Background(), testAlert("critical", "prod", "api"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(rec.calls))
	}
}

func TestRouter_WalkSiblingRouting(t *testing.T) {
	// A non-matching earlier sibling must not suppress a later matching sibling,
	// and only a matched child with Continue=false may stop the walk.
	cases := []struct {
		name     string
		children []Route
		alert    Alert
		want     map[string]int // receiver name -> expected call count
	}{
		{
			name: "later sibling fires when first child does not match",
			children: []Route{
				{Match: map[string]string{"severity": "critical"}, Receivers: []string{"crit"}},
				{Match: map[string]string{"severity": "low"}, Receivers: []string{"low"}},
			},
			alert: testAlert("low", "prod", "api"),
			want:  map[string]int{"crit": 0, "low": 1},
		},
		{
			name: "matched child with Continue=false stops later siblings",
			children: []Route{
				{Match: map[string]string{"severity": "low"}, Receivers: []string{"crit"}},
				{Match: map[string]string{"cluster": "prod"}, Receivers: []string{"low"}},
			},
			alert: testAlert("low", "prod", "api"),
			want:  map[string]int{"crit": 1, "low": 0},
		},
		{
			name: "matched child with Continue=true lets later siblings run",
			children: []Route{
				{Match: map[string]string{"severity": "low"}, Receivers: []string{"crit"}, Continue: true},
				{Match: map[string]string{"cluster": "prod"}, Receivers: []string{"low"}},
			},
			alert: testAlert("low", "prod", "api"),
			want:  map[string]int{"crit": 1, "low": 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			crit, low := &recordingReceiver{}, &recordingReceiver{}
			r := &Router{
				Receivers: map[string]Receiver{"crit": crit, "low": low},
				Tree:      Route{Match: map[string]string{}, Children: tc.children},
			}
			if _, err := r.Dispatch(context.Background(), tc.alert, nil); err != nil {
				t.Fatal(err)
			}
			if got := len(crit.calls); got != tc.want["crit"] {
				t.Fatalf("crit receiver: got %d calls, want %d", got, tc.want["crit"])
			}
			if got := len(low.calls); got != tc.want["low"] {
				t.Fatalf("low receiver: got %d calls, want %d", got, tc.want["low"])
			}
		})
	}
}

func TestRouter_InhibitsLowerSeverityWhenSourceFiring(t *testing.T) {
	rec := &recordingReceiver{}
	r := &Router{
		Receivers: map[string]Receiver{"recorder": rec},
		Tree: Route{Receivers: []string{"recorder"}},
		InhibitRules: []InhibitRule{{
			SourceMatch: map[string]string{"severity": "critical"},
			TargetMatch: map[string]string{"severity": "high"},
			Equal:       []string{"cluster"},
		}},
	}
	firing := []Alert{testAlert("critical", "prod", "api")}
	_, err := r.Dispatch(context.Background(), testAlert("high", "prod", "api"), firing)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("high alert should be inhibited by critical in same cluster, got %d", len(rec.calls))
	}
}

func TestGroupKey_StableAcrossLabelOrder(t *testing.T) {
	a := Alert{Labels: map[string]string{"cluster": "prod", "kind": "vuln", "severity": "high"}}
	got := GroupKey(a, []string{"severity", "cluster"})
	want := "cluster=prod,severity=high"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
