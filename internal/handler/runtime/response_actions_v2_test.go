//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/pkg/response"
)

type processAPIResponseFixture struct {
	database     *db.DB
	handler      *ResponseActions
	org, cluster uuid.UUID
	token        *handler.RuntimeAgentToken
	target       *response.ProcessTarget
}

func newProcessAPIResponseFixture(t *testing.T) *processAPIResponseFixture {
	t.Helper()
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, cluster := uuid.New(), uuid.New()
	token := seedBoundRuntimeAgentScope(t, d, org, cluster)
	return &processAPIResponseFixture{database: d, handler: NewResponseActions(d), org: org, cluster: cluster, token: token, target: &response.ProcessTarget{Node: "node-a", PID: 4242, Comm: "nginx", ContainerID: "containerd://" + strings.Repeat("a", 64), BootID: uuid.NewString(), StartTicks: "1234", StartBootNS: "12349999999"}}
}
func (f *processAPIResponseFixture) queue(t *testing.T, node string) processActionV2 {
	t.Helper()
	target := *f.target
	target.Node = node
	q := &quarantineRuntime{db: f.database, orgID: f.org, clusterID: f.cluster, processTarget: &target, processWorkload: "test/pod/worker", sourceAt: time.Now().UTC()}
	if err := q.Kill(t.Context(), "test/pod/worker", "fixture reason"); err != nil {
		t.Fatal(err)
	}
	var a processActionV2
	a.Version = 2
	a.Type = "kill_process"
	err := f.database.Pool().QueryRow(t.Context(), `SELECT id,action_token,node,workload_id,container_id,pid,comm,boot_id,process_start_ticks::text,start_boot_ns::text FROM runtime_response_actions_v2 WHERE org_id=$1 AND node=$2 ORDER BY created_at DESC LIMIT 1`, f.org, node).Scan(&a.ID, &a.ActionToken, &a.Node, &a.WorkloadID, &a.ContainerID, &a.PID, &a.Comm, &a.BootID, &a.StartTicks, &a.StartBootNS)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func (f *processAPIResponseFixture) request(t *testing.T, method, path string, body []byte, token *handler.RuntimeAgentToken) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(body))
	if token != nil {
		r = r.WithContext(handler.WithRuntimeAgentToken(r.Context(), token))
	}
	w := httptest.NewRecorder()
	if method == http.MethodGet {
		f.handler.PendingV2(w, r)
	} else {
		f.handler.ResultV2(w, r)
	}
	return w
}
func processAPIResult(a processActionV2) processResultV2 {
	return processResultV2{Version: 2, ID: a.ID, ActionToken: a.ActionToken, Type: a.Type, Node: a.Node, Outcome: "applied", Reason: "", At: time.Now().UTC()}
}
func TestProcessResponseV2ExactNodeQueueAndReceipts(t *testing.T) {
	f := newProcessAPIResponseFixture(t)
	a := f.queue(t, "node-a")
	f.queue(t, "node-b")
	sibling := uuid.New()
	if _, err := f.database.Pool().Exec(t.Context(), `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'sibling')`, sibling, f.org); err != nil {
		t.Fatal(err)
	}
	foreign := newProcessAPIResponseFixture(t)
	foreign.queue(t, "node-a")
	path := "/runtime/response-actions/v2/pending?cluster_id=" + f.cluster.String() + "&node=node-a"
	w := f.request(t, http.MethodGet, path, nil, f.token)
	var envelope struct {
		Actions []processActionV2 `json:"actions"`
		Cluster string            `json:"cluster_id"`
		Node    string            `json:"node"`
		Version int               `json:"protocol_version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || w.Code != 200 || len(envelope.Actions) != 1 || envelope.Actions[0] != a || envelope.Cluster != f.cluster.String() || envelope.Node != "node-a" || envelope.Version != 2 {
		t.Fatalf("wrong exact queue %d %s err=%v", w.Code, w.Body.String(), err)
	}
	for _, suffix := range []string{"&node=node-b", "&cluster_id=" + sibling.String()} {
		if got := f.request(t, http.MethodGet, path+suffix, nil, f.token); got.Code != 400 {
			t.Fatalf("duplicate selectors %d %s", got.Code, got.Body.String())
		}
	}
	if got := f.request(t, http.MethodGet, "/pending?cluster_id="+sibling.String()+"&node=node-a", nil, f.token); got.Code != 403 {
		t.Fatalf("sibling request=%d", got.Code)
	}
	assertProcessResultScope(t, f, a, foreign.token)
	result := processAPIResult(a)
	body, _ := json.Marshal(result)
	for i := 0; i < 2; i++ {
		w = f.request(t, http.MethodPost, "/result", body, f.token)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"acknowledged":true`) {
			t.Fatalf("result receipt %d %s", w.Code, w.Body.String())
		}
	}
	var count int
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='runtime.response_action.result' AND target_id=$2`, f.org, a.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate audit count%d err=%v", count, err)
	}
	result.Reason = "different result"
	body, _ = json.Marshal(result)
	if w = f.request(t, http.MethodPost, "/result", body, f.token); w.Code != 409 {
		t.Fatalf("terminal result overwritten %d %s", w.Code, w.Body.String())
	}
	w = f.request(t, http.MethodGet, path, nil, f.token)
	if strings.Contains(w.Body.String(), a.ID) {
		t.Fatal("terminal process request offered again")
	}
	// Legacy handlers see no V2 rows, including during a rolling upgrade.
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/pending?cluster_id="+f.cluster.String()+"&node=node-b", nil)
	r = r.WithContext(handler.WithRuntimeAgentToken(r.Context(), f.token))
	w = httptest.NewRecorder()
	f.handler.Pending(w, r)
	if w.Code != 200 || w.Body.String() != "{\"actions\":[]}\n" {
		t.Fatalf("legacy queue saw V2 process action %d %s", w.Code, w.Body.String())
	}
}
func assertProcessResultScope(t *testing.T, f *processAPIResponseFixture, a processActionV2, foreign *handler.RuntimeAgentToken) {
	t.Helper()
	for _, change := range []string{"node", "token", "id", "foreign org"} {
		result := processAPIResult(a)
		tok := f.token
		switch change {
		case "node":
			result.Node = "node-b"
		case "token":
			result.ActionToken = uuid.NewString()
		case "id":
			result.ID = uuid.NewString()
		case "foreign org":
			tok = foreign
		}
		body, _ := json.Marshal(result)
		w := f.request(t, http.MethodPost, "/result", body, tok)
		if w.Code != 404 || strings.Contains(w.Body.String(), a.ID) {
			t.Fatalf("%s accepted/disclosed result %d %s", change, w.Code, w.Body.String())
		}
	}
}
func TestProcessResponseV2RequiresSourceAndSingleBody(t *testing.T) {
	f := newProcessAPIResponseFixture(t)
	q := &quarantineRuntime{db: f.database, orgID: f.org, clusterID: f.cluster}
	if err := q.Kill(t.Context(), "test/pod/worker", "legacy"); err == nil {
		t.Fatal("workload-only kill selected an arbitrary process")
	}
	a := f.queue(t, "node-a")
	body, _ := json.Marshal(processAPIResult(a))
	for _, raw := range [][]byte{append(append([]byte{}, body...), []byte(` {"outcome":"applied"}`)...), []byte(`{"protocol_version":2}`), append(append([]byte{}, body...), []byte(` garbage`)...)} {
		if w := f.request(t, http.MethodPost, "/result", raw, f.token); w.Code != 400 {
			t.Fatalf("malformed result accepted %d %s", w.Code, w.Body.String())
		}
	}
	if w := f.request(t, http.MethodPost, "/result", body, nil); w.Code != 401 {
		t.Fatalf("unauthenticated result=%d", w.Code)
	}
}
func TestProcessResponseV2AuditFailureRollsBackReceipt(t *testing.T) {
	f := newProcessAPIResponseFixture(t)
	a := f.queue(t, "node-a")
	// Isolated disposable DB only: fail this organization's result audit insert.
	name := "response_fail_" + strings.ReplaceAll(f.org.String(), "-", "")
	sql := `CREATE FUNCTION ` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='` + f.org.String() + `'::uuid AND NEW.action='runtime.response_action.result' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$`
	if _, err := f.database.Pool().Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.Pool().Exec(t.Context(), `CREATE TRIGGER `+name+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION `+name+`() `); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.database.Pool().Exec(context.WithoutCancel(t.Context()), `DROP TRIGGER IF EXISTS `+name+` ON audit_events; DROP FUNCTION IF EXISTS `+name+`()`)
	})
	body, _ := json.Marshal(processAPIResult(a))
	w := f.request(t, http.MethodPost, "/result", body, f.token)
	if w.Code != 500 || strings.Contains(w.Body.String(), "fixture audit failure") {
		t.Fatalf("false/sensitive receipt %d %s", w.Code, w.Body.String())
	}
	var state string
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT state FROM runtime_response_actions_v2 WHERE id=$1`, a.ID).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("audit failure committed effect receipt %q %v", state, err)
	}
}

func TestProcessResponseV2RejectsOversizedSourceIdentity(t *testing.T) {
	f := newProcessAPIResponseFixture(t)
	for _, field := range []string{"node", "workload", "container", "comm"} {
		t.Run(field, func(t *testing.T) {
			target := *f.target
			workload := "test/pod/worker"
			switch field {
			case "node":
				target.Node = strings.Repeat("x", 254)
			case "workload":
				workload = strings.Repeat("x", 4097)
			case "container":
				target.ContainerID = strings.Repeat("x", 257)
			case "comm":
				target.Comm = strings.Repeat("x", 17)
			}
			q := &quarantineRuntime{db: f.database, orgID: f.org, clusterID: f.cluster, processTarget: &target, processWorkload: workload, sourceAt: time.Now().UTC()}
			if err := q.Kill(t.Context(), workload, "fixture"); err == nil {
				t.Fatal("oversized source queued a poison action")
			}
		})
	}
	var count int
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM runtime_response_actions_v2 WHERE org_id=$1`, f.org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid source wrote queue: count%d err%v", count, err)
	}
}

func TestProcessResponseV2PendingEscapedEnvelopeBound(t *testing.T) {
	f := newProcessAPIResponseFixture(t)
	workload := strings.Repeat("\x01", 4096)
	// JSON expands each byte sixfold, so 100 individually valid actions exceed
	// the agent's 1MiB decode boundary. The oldest fitting prefix must progress.
	_, err := f.database.Pool().Exec(t.Context(), `INSERT INTO runtime_response_actions_v2(org_id,cluster_id,node,workload_id,container_id,pid,comm,boot_id,process_start_ticks,start_boot_ns,source_at) SELECT $1,$2,'node-a',$3,$4,4242,'nginx',$5,1234,12349999999,now() FROM generate_series(1,100)`, f.org, f.cluster, workload, f.target.ContainerID, f.target.BootID)
	if err != nil {
		t.Fatal(err)
	}
	w := f.request(t, http.MethodGet, "/pending?cluster_id="+f.cluster.String()+"&node=node-a", nil, f.token)
	var envelope struct {
		Actions []processActionV2 `json:"actions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || w.Code != 200 || len(w.Body.Bytes()) > 1<<20 || len(envelope.Actions) == 0 || len(envelope.Actions) >= 100 {
		t.Fatalf("invalid bounded prefix code%d bytes%d rows%d err%v", w.Code, w.Body.Len(), len(envelope.Actions), err)
	}
	for _, a := range envelope.Actions {
		if a.WorkloadID != workload {
			t.Fatal("response truncated identity instead of batch")
		}
	}
}
