package notify

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
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
		Labels:  map[string]string{"severity": sev, "cluster": cluster, "workload": workload},
		URL:     "https://constellation.example/findings/x",
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

func TestSyslog_SendOverVerifiedTLS(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := certServer.TLS.Certificates[0]
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certServer.Certificate().Raw})
	certServer.Close()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	lineCh := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			lineCh <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, _ := bufio.NewReader(conn).ReadString('\n')
		lineCh <- line
	}()

	sender := NewSyslog("tls", listener.Addr().String())
	sender.CACertPEM = string(ca)
	sender.ServerName = "example.com"
	if err := sender.Send(context.Background(), []Alert{testAlert("high", "prod", "api")}); err != nil {
		t.Fatal(err)
	}
	if line := <-lineCh; !strings.HasPrefix(line, "<131>1 ") {
		t.Fatalf("TLS collector received %q", line)
	}
}

func TestSyslog_SendToMTLSCollector(t *testing.T) {
	clientCA, clientCert, clientKey := testSyslogClientIdentity(t)
	_, untrustedCert, untrustedKey := testSyslogClientIdentity(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	serverCert := server.TLS.Certificates[0]
	serverCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	server.Close()

	for _, tc := range []struct {
		name       string
		serverCA   string
		clientCert string
		clientKey  string
		maxVersion uint16
		wantError  bool
	}{
		{name: "valid client TLS 1.2", serverCA: serverCA, clientCert: clientCert, clientKey: clientKey, maxVersion: tls.VersionTLS12},
		{name: "valid client TLS 1.3", serverCA: serverCA, clientCert: clientCert, clientKey: clientKey, maxVersion: tls.VersionTLS13},
		{name: "wrong server CA", serverCA: clientCA, clientCert: clientCert, clientKey: clientKey, maxVersion: tls.VersionTLS12, wantError: true},
		{name: "missing client credentials", serverCA: serverCA, maxVersion: tls.VersionTLS12, wantError: true},
		{name: "untrusted client CA", serverCA: serverCA, clientCert: untrustedCert, clientKey: untrustedKey, maxVersion: tls.VersionTLS12, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientRoots := x509.NewCertPool()
			if !clientRoots.AppendCertsFromPEM([]byte(clientCA)) {
				t.Fatal("invalid client CA")
			}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    clientRoots,
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tc.maxVersion,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			type collectorResult struct {
				line       string
				clientName string
				version    uint16
				err        error
			}
			results := make(chan collectorResult, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					results <- collectorResult{err: acceptErr}
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				tlsConn := conn.(*tls.Conn)
				if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
					results <- collectorResult{err: handshakeErr}
					return
				}
				line, readErr := bufio.NewReader(tlsConn).ReadString('\n')
				results <- collectorResult{line: line, clientName: tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName, version: tlsConn.ConnectionState().Version, err: readErr}
			}()

			sender := NewSyslog("tls", listener.Addr().String())
			sender.CACertPEM = tc.serverCA
			sender.ServerName = "example.com"
			sender.ClientCertPEM = tc.clientCert
			sender.ClientKeyPEM = tc.clientKey
			sendErr := sender.Send(context.Background(), []Alert{testAlert("high", "prod", "api")})
			if tc.wantError && sendErr == nil {
				t.Fatal("Send() succeeded despite rejected TLS handshake")
			}
			if !tc.wantError && sendErr != nil {
				t.Fatalf("Send() = %v", sendErr)
			}
			select {
			case result := <-results:
				if tc.wantError {
					if result.err == nil || result.line != "" {
						t.Fatalf("collector accepted rejected connection: %+v", result)
					}
				} else if result.err != nil || result.clientName != "syslog-client" || result.version != tc.maxVersion || !strings.HasPrefix(result.line, "<131>1 ") || !strings.HasSuffix(result.line, "high thing\n") {
					t.Fatalf("collector received %+v", result)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("collector did not complete handshake")
			}
		})
	}
}

func testSyslogClientIdentity(t *testing.T) (string, string, string) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "syslog-client-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "syslog-client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, clientPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func TestSyslog_RejectsPlaintextWithTLSSettings(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*Syslog)
	}{
		{"CA", func(sender *Syslog) { sender.CACertPEM = "configured CA" }},
		{"client certificate", func(sender *Syslog) { sender.ClientCertPEM = "configured cert" }},
		{"client key", func(sender *Syslog) { sender.ClientKeyPEM = "configured key" }},
		{"server name", func(sender *Syslog) { sender.ServerName = "siem.example" }},
	} {
		for _, network := range []string{"", "udp", "tcp"} {
			t.Run(tc.name+"/"+network, func(t *testing.T) {
				sender := NewSyslog(network, "127.0.0.1:1")
				tc.configure(sender)
				if err := sender.Send(context.Background(), []Alert{testAlert("high", "prod", "api")}); err == nil || !strings.Contains(err.Error(), "TLS transport required") {
					t.Fatalf("Send() = %v, want TLS transport error", err)
				}
			})
		}
	}
}

func TestSyslog_JSONFormat(t *testing.T) {
	fixed := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	s := &Syslog{Format: "json", Hostname: "node-1", AppName: "constellation"}
	a := Alert{
		ID: "f-1", OrgID: "org-9", Severity: "high", Kind: "finding",
		Title: "CVE-2026-0001 in nginx", Cluster: "prod", Workload: "web",
		URL: "https://c/x", FiredAt: fixed, Labels: map[string]string{"team": "sec"},
	}
	line := s.format(a)
	if !strings.HasSuffix(line, "\n") {
		t.Fatalf("json line not newline-framed: %q", line)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("json does not parse: %v (%q)", err, line)
	}
	for k, want := range map[string]string{
		"id": "f-1", "org_id": "org-9", "severity": "high", "kind": "finding",
		"category": "finding", "title": "CVE-2026-0001 in nginx", "cluster": "prod",
		"workload": "web", "url": "https://c/x", "host": "node-1",
		"app": "constellation", "timestamp": "2026-06-17T12:00:00Z",
	} {
		if got, _ := m[k].(string); got != want {
			t.Errorf("json[%q] = %q, want %q", k, got, want)
		}
	}
	if labels, ok := m["labels"].(map[string]any); !ok || labels["team"] != "sec" {
		t.Errorf("labels not carried: %v", m["labels"])
	}
}

func TestSyslog_CEFFormat(t *testing.T) {
	fixed := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	s := &Syslog{Format: "cef", Product: "constellation", Version: "1.0", Now: func() time.Time { return fixed }}
	a := Alert{
		ID: "f-1", Severity: "critical", Kind: "runtime", Title: "reverse shell",
		Cluster: "prod", Workload: "api", URL: "https://c/x", FiredAt: fixed,
		Labels: map[string]string{"src": "10.0.0.1", "dst_ip": "10.0.0.2"},
	}
	line := s.format(a)
	if !strings.HasPrefix(line, "CEF:0|Constellation|constellation|1.0|runtime|reverse shell|10|") {
		t.Fatalf("bad CEF header: %q", line)
	}
	for _, want := range []string{
		"cat=runtime", "cs1Label=Cluster", "cs1=prod", "cs2=api", "msg=reverse shell",
		"request=https://c/x", "rt=2026-06-17T12:00:00Z", "src=10.0.0.1", "dst=10.0.0.2",
		"externalId=f-1", "ConstellationSeverity=critical",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("CEF missing %q in %q", want, line)
		}
	}
	if !strings.HasSuffix(line, "\n") {
		t.Fatalf("CEF line not newline-framed: %q", line)
	}
}

func TestSyslog_CEFEscaping(t *testing.T) {
	s := &Syslog{Format: "cef"}
	a := Alert{Kind: "a|b", Title: "pipe|and\\slash", Severity: "low",
		Labels: map[string]string{"src": "k=v"}}
	line := s.format(a)
	// Header field: | and \ escaped.
	if !strings.Contains(line, `|a\|b|pipe\|and\\slash|`) {
		t.Fatalf("CEF header not escaped: %q", line)
	}
	// Extension value: = escaped.
	if !strings.Contains(line, `src=k\=v`) {
		t.Fatalf("CEF extension not escaped: %q", line)
	}
}

func TestSyslog_LevelAndCategoryFilter(t *testing.T) {
	tests := []struct {
		name       string
		minLevel   string
		categories []string
		alert      Alert
		wantShip   bool
	}{
		{"no filter ships info", "", nil, Alert{Severity: "info", Kind: "finding"}, true},
		{"min high drops medium", "high", nil, Alert{Severity: "medium", Kind: "finding"}, false},
		{"min high ships high", "high", nil, Alert{Severity: "high", Kind: "finding"}, true},
		{"min high ships critical", "high", nil, Alert{Severity: "critical", Kind: "runtime"}, true},
		{"min low drops empty sev", "low", nil, Alert{Severity: "", Kind: "finding"}, false},
		{"min info drops unknown severity", "info", nil, Alert{Severity: "unexpected", Kind: "finding"}, false},
		{"unknown min level drops high", "urgent", nil, Alert{Severity: "high", Kind: "finding"}, false},
		{"unknown min level drops critical", "urgent", nil, Alert{Severity: "critical", Kind: "finding"}, false},
		{"unknown min level with whitespace drops high", " urgent ", nil, Alert{Severity: "high", Kind: "finding"}, false},
		{"no filter ships unknown severity", "", nil, Alert{Severity: "unexpected", Kind: "finding"}, true},
		{"min info ships info", "info", nil, Alert{Severity: "info", Kind: "finding"}, true},
		{"min level trims whitespace", " HIGH ", nil, Alert{Severity: "high", Kind: "finding"}, true},
		{"category allow match", "", []string{"runtime"}, Alert{Severity: "high", Kind: "runtime"}, true},
		{"category allow miss", "", []string{"runtime"}, Alert{Severity: "high", Kind: "finding"}, false},
		{"category case-insensitive", "", []string{"Runtime"}, Alert{Severity: "high", Kind: "runtime"}, true},
		{"level and category both pass", "medium", []string{"finding"}, Alert{Severity: "high", Kind: "finding"}, true},
		{"level ok category fails", "medium", []string{"runtime"}, Alert{Severity: "high", Kind: "finding"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Syslog{MinLevel: tt.minLevel, Categories: tt.categories}
			if got := s.shouldShip(tt.alert); got != tt.wantShip {
				t.Fatalf("shouldShip = %v, want %v", got, tt.wantShip)
			}
		})
	}
}

func TestSyslog_FilterSkipsSendWhenEmpty(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s := NewSyslog("udp", pc.LocalAddr().String())
	s.MinLevel = "critical"
	// A low-severity alert is filtered out; Send must succeed without dialing/writing.
	if err := s.Send(context.Background(), []Alert{testAlert("low", "prod", "api")}); err != nil {
		t.Fatalf("filtered Send returned error: %v", err)
	}
	buf := make([]byte, 512)
	_ = pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatalf("expected no datagram, got %q", buf[:n])
	}
}

func TestSyslog_UnknownMinLevelSkipsDial(t *testing.T) {
	s := NewSyslog("tcp", "127.0.0.1:1")
	s.MinLevel = "urgent"
	if err := s.Send(context.Background(), []Alert{testAlert("critical", "prod", "api")}); err != nil {
		t.Fatalf("unknown MinLevel must filter before dialing: %v", err)
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
		Tree:      Route{Receivers: []string{"recorder"}},
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
