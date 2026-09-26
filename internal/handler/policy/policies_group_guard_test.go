package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func rawAdmissionSpec(selectors ...string) string {
	groups, _ := json.Marshal(selectors)
	return "kind: AdmissionRule\nspec:\n  match:\n    groups: " + string(groups) + "\n  action: deny\n"
}

func rawPolicyRequest(t *testing.T, method, path string, body any, orgID, userID uuid.UUID, policyID uuid.UUID) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	if policyID != uuid.Nil {
		route := chi.NewRouteContext()
		route.URLParams.Add("id", policyID.String())
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
	}
	request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: userID}))
	return request, httptest.NewRecorder()
}

func rawAdmissionCreate(t *testing.T, handler *Policies, orgID, userID uuid.UUID, path, name, spec string) *httptest.ResponseRecorder {
	t.Helper()
	request, response := rawPolicyRequest(t, http.MethodPost, path, createPolicyBody{
		Name: name, Engine: "constellation-admission", Category: "admission", SpecYAML: spec, Mode: "monitor",
	}, orgID, userID, uuid.Nil)
	handler.Create(response, request)
	return response
}

func rawAdmissionUpdate(t *testing.T, handler *Policies, orgID, userID, policyID uuid.UUID, body updatePolicyBody) *httptest.ResponseRecorder {
	t.Helper()
	request, response := rawPolicyRequest(t, http.MethodPatch, "/policies/"+policyID.String(), body, orgID, userID, policyID)
	handler.Update(response, request)
	return response
}

func seedRawPolicyCluster(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID) uuid.UUID {
	t.Helper()
	clusterID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO clusters (id,org_id,name,distro,state) VALUES ($1,$2,$3,'k3s','connected')`,
		clusterID, orgID, "raw-policy-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	return clusterID
}

func seedRawPolicyGroup(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, clusterID any, name string) uuid.UUID {
	t.Helper()
	groupID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO groups (id,org_id,cluster_id,name,kind) VALUES ($1,$2,$3,$4,'ground')`,
		groupID, orgID, clusterID, name); err != nil {
		t.Fatal(err)
	}
	return groupID
}

func rawPolicyID(t *testing.T, response *httptest.ResponseRecorder) uuid.UUID {
	t.Helper()
	var body struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.ID == uuid.Nil {
		t.Fatalf("invalid policy ID: %s (%v)", response.Body.String(), err)
	}
	return body.ID
}

func TestRawAdmissionPolicyCreateScopesAllGroupSelectors(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	orgID, userID := seedOrgUser(t, pool)
	otherOrgID, _ := seedOrgUser(t, pool)
	clusterID := seedRawPolicyCluster(t, pool, orgID)
	otherClusterID := seedRawPolicyCluster(t, pool, orgID)
	globalID := seedRawPolicyGroup(t, pool, orgID, nil, "Raw-Global")
	seedRawPolicyGroup(t, pool, orgID, clusterID, "raw-cluster")
	seedRawPolicyGroup(t, pool, orgID, otherClusterID, "raw-other-cluster")
	seedRawPolicyGroup(t, pool, otherOrgID, nil, "raw-foreign")
	handler := NewPolicies(database, audit.New(pool), nil)
	for _, test := range []struct {
		name       string
		path       string
		selectors  []string
		wantStatus int
	}{
		{"ungrouped", "/policies", nil, http.StatusCreated},
		{"global-by-id-and-name", "/policies", []string{globalID.String(), "raw-global"}, http.StatusCreated},
		{"cluster-without-scope", "/policies", []string{"raw-cluster"}, http.StatusBadRequest},
		{"cluster-with-scope", "/policies?cluster_id=" + clusterID.String(), []string{"raw-cluster"}, http.StatusCreated},
		{"other-cluster", "/policies?cluster_id=" + clusterID.String(), []string{"raw-other-cluster"}, http.StatusBadRequest},
		{"foreign-org", "/policies", []string{"raw-foreign"}, http.StatusBadRequest},
		{"missing-among-valid", "/policies", []string{"raw-global", "missing"}, http.StatusBadRequest},
	} {
		response := rawAdmissionCreate(t, handler, orgID, userID, test.path, test.name, rawAdmissionSpec(test.selectors...))
		if response.Code != test.wantStatus {
			t.Errorf("%s: status=%d body=%s", test.name, response.Code, response.Body.String())
		}
	}
	request, response := rawPolicyRequest(t, http.MethodPost, "/policies", createPolicyBody{
		Name: "other-engine", Engine: "kyverno", Category: "admission", SpecYAML: rawAdmissionSpec("missing"), Mode: "monitor",
	}, orgID, userID, uuid.Nil)
	handler.Create(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("other engine changed: status=%d body=%s", response.Code, response.Body.String())
	}
	response = rawAdmissionCreate(t, handler, orgID, userID, "/policies", "malformed-ungrouped", "spec: [")
	if response.Code != http.StatusCreated {
		t.Fatalf("malformed ungrouped policy changed: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRawAdmissionPolicyUpdateValidatesResultingGroups(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	orgID, userID := seedOrgUser(t, pool)
	otherOrgID, _ := seedOrgUser(t, pool)
	validID := seedRawPolicyGroup(t, pool, orgID, nil, "raw-update-valid")
	clusterID := seedRawPolicyCluster(t, pool, orgID)
	seedRawPolicyGroup(t, pool, orgID, clusterID, "raw-update-cluster")
	seedRawPolicyGroup(t, pool, otherOrgID, nil, "raw-update-foreign")
	handler := NewPolicies(database, audit.New(pool), nil)
	created := rawAdmissionCreate(t, handler, orgID, userID, "/policies", "update-target", rawAdmissionSpec())
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	policyID := rawPolicyID(t, created)
	validSpec := rawAdmissionSpec(validID.String())
	for _, test := range []struct {
		name       string
		body       updatePolicyBody
		wantStatus int
	}{
		{"reject-foreign", updatePolicyBody{SpecYAML: ptrRawPolicyString(rawAdmissionSpec("raw-update-foreign"))}, http.StatusBadRequest},
		{"reject-missing", updatePolicyBody{SpecYAML: ptrRawPolicyString(rawAdmissionSpec("missing"))}, http.StatusBadRequest},
		{"reject-cluster-without-scope", updatePolicyBody{SpecYAML: ptrRawPolicyString(rawAdmissionSpec("raw-update-cluster"))}, http.StatusBadRequest},
		{"accept-valid", updatePolicyBody{SpecYAML: &validSpec}, http.StatusOK},
	} {
		response := rawAdmissionUpdate(t, handler, orgID, userID, policyID, test.body)
		if response.Code != test.wantStatus {
			t.Fatalf("%s: status=%d body=%s", test.name, response.Code, response.Body.String())
		}
	}
	var stored string
	if err := pool.QueryRow(context.Background(), `SELECT spec_yaml FROM policies WHERE id=$1`, policyID).Scan(&stored); err != nil || stored != validSpec {
		t.Fatalf("stored spec=%q err=%v", stored, err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE policies SET spec_yaml=$2 WHERE id=$1`, policyID, rawAdmissionSpec("missing")); err != nil {
		t.Fatal(err)
	}
	enabled := true
	response := rawAdmissionUpdate(t, handler, orgID, userID, policyID, updatePolicyBody{Enabled: &enabled})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("dangling existing selector: status=%d body=%s", response.Code, response.Body.String())
	}
	var storedEnabled bool
	if err := pool.QueryRow(context.Background(), `SELECT enabled FROM policies WHERE id=$1`, policyID).Scan(&storedEnabled); err != nil || storedEnabled {
		t.Fatalf("invalid update persisted enabled=%v err=%v", storedEnabled, err)
	}
	response = rawAdmissionUpdate(t, handler, orgID, userID, policyID, updatePolicyBody{SpecYAML: ptrRawPolicyString(rawAdmissionSpec())})
	if response.Code != http.StatusOK {
		t.Fatalf("remove dangling selector: status=%d body=%s", response.Code, response.Body.String())
	}
	clusterPolicy := rawAdmissionCreate(t, handler, orgID, userID, "/policies?cluster_id="+clusterID.String(), "cluster-update-target", rawAdmissionSpec())
	if clusterPolicy.Code != http.StatusCreated {
		t.Fatalf("cluster policy create: status=%d body=%s", clusterPolicy.Code, clusterPolicy.Body.String())
	}
	response = rawAdmissionUpdate(t, handler, orgID, userID, rawPolicyID(t, clusterPolicy),
		updatePolicyBody{SpecYAML: ptrRawPolicyString(rawAdmissionSpec("raw-update-cluster"))})
	if response.Code != http.StatusOK {
		t.Fatalf("cluster-scoped update: status=%d body=%s", response.Code, response.Body.String())
	}
}

func ptrRawPolicyString(value string) *string { return &value }

func TestRawAdmissionPolicyWriteWaitsForGroupMutation(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		for _, mutationKind := range []string{"rename", "delete"} {
			t.Run(operation+"-"+mutationKind, func(t *testing.T) {
				database := openTestDB(t)
				defer database.Close()
				pool := database.Pool()
				orgID, userID := seedOrgUser(t, pool)
				groupID := seedRawPolicyGroup(t, pool, orgID, nil, "raw-race-"+uuid.NewString())
				var oldName string
				if err := pool.QueryRow(context.Background(), `SELECT name FROM groups WHERE id=$1`, groupID).Scan(&oldName); err != nil {
					t.Fatal(err)
				}
				handler := NewPolicies(database, audit.New(pool), nil)
				var policyID uuid.UUID
				if operation == "update" {
					created := rawAdmissionCreate(t, handler, orgID, userID, "/policies", "raw-race-policy-"+uuid.NewString(), rawAdmissionSpec())
					if created.Code != http.StatusCreated {
						t.Fatalf("create: %d %s", created.Code, created.Body.String())
					}
					policyID = rawPolicyID(t, created)
				}
				mutation, err := pool.Begin(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer mutation.Rollback(context.Background())
				if _, err := mutation.Exec(context.Background(), `LOCK TABLE policies IN SHARE MODE`); err != nil {
					t.Fatal(err)
				}
				if mutationKind == "rename" {
					if _, err := mutation.Exec(context.Background(), `UPDATE groups SET name=$2 WHERE id=$1`, groupID, oldName+"-renamed"); err != nil {
						t.Fatal(err)
					}
				} else if _, err := mutation.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, groupID); err != nil {
					t.Fatal(err)
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					if operation == "create" {
						result <- rawAdmissionCreate(t, handler, orgID, userID, "/policies", "raw-race-created-"+uuid.NewString(), rawAdmissionSpec(oldName))
					} else {
						result <- rawAdmissionUpdate(t, handler, orgID, userID, policyID, updatePolicyBody{SpecYAML: ptrRawPolicyString(rawAdmissionSpec(oldName))})
					}
				}()
				deadline := time.Now().Add(5 * time.Second)
				for {
					select {
					case response := <-result:
						t.Fatalf("%s completed before %s committed: %d %s", operation, mutationKind, response.Code, response.Body.String())
					default:
					}
					var waiting int
					if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'LOCK TABLE policies IN ROW EXCLUSIVE MODE%' AND wait_event_type='Lock'`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("writer did not wait for group mutation")
					}
					time.Sleep(10 * time.Millisecond)
				}
				if err := mutation.Commit(context.Background()); err != nil {
					t.Fatal(err)
				}
				select {
				case response := <-result:
					if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "group not found") {
						t.Fatalf("%s: status=%d body=%s", operation, response.Code, response.Body.String())
					}
				case <-time.After(5 * time.Second):
					t.Fatal("writer did not complete after mutation")
				}
				var count int
				if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM policies WHERE org_id=$1 AND spec_yaml LIKE $2`, orgID, "%"+oldName+"%").Scan(&count); err != nil || count != 0 {
					t.Fatalf("dangling policies=%d err=%v", count, err)
				}
			})
		}
	}
}
