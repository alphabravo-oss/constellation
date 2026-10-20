package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func TestPolicyWireIdentityBounds(t *testing.T) {
	for _, id := range []int64{-1, math.MaxUint32 + 1, math.MaxInt64} {
		p := RuntimePolicy{DPPolicyID: id, Mode: PolicyModeEnforce, Rules: json.RawMessage(`[{"action":7}]`)}
		if got, err := p.ToWorkloadPolicy(nil); err == nil || got != nil {
			t.Fatalf("accepted overflowing policy ID %d", id)
		}
	}
	for _, tc := range []struct {
		id   int64
		wire uint32
	}{{0, 0}, {1, 1}, {math.MaxUint32, math.MaxUint32}} {
		id := tc.id
		p := RuntimePolicy{DPPolicyID: id, Mode: PolicyModeMonitor, Rules: json.RawMessage(`[{"action":7}]`)}
		got, err := p.ToWorkloadPolicy(nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.Rules[0].ID != tc.wire || got.Rules[0].Action != dp.PolicyActionViolate {
			t.Fatalf("identity/mode changed for %d: %+v", id, got.Rules[0])
		}
	}
}

func TestPolicyMalformedRulesRefused(t *testing.T) {
	for _, raw := range []string{`[null]`, `[{"action":255}]`, `{}`, `[true]`} {
		p := RuntimePolicy{Mode: PolicyModeMonitor, Rules: json.RawMessage(raw)}
		if got, err := p.ToWorkloadPolicy(nil); err == nil || got != nil {
			t.Fatalf("accepted malformed rule set %s", raw)
		}
	}
}

func TestPolicyMutationRejectsInvalidFieldsBeforeStorage(t *testing.T) {
	for _, patch := range []string{`{"apply_dir":65539}`, `{"apply_dir":-65533}`, `{"apply_dir":4}`, `{"def_action":255}`, `{"rules":[null]}`, `{"rules":[{"action":255}]}`} {
		for _, operation := range []string{"create", "update", "reviewed"} {
			t.Run(operation+patch, func(t *testing.T) { assertPolicyMutationRefused(t, operation, patch) })
		}
	}
}

func assertPolicyMutationRefused(t *testing.T, operation, patch string) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(patch), &body); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	body["cluster_id"] = uuid.New().String()
	body["expected_version"] = "1"
	body["workload"], body["namespace"], body["name"] = "app/api", "app", "test"
	if operation == "reviewed" {
		delete(body, "workload")
		delete(body, "namespace")
		delete(body, "name")
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id.String())
	ctx := context.WithValue(t.Context(), chi.RouteCtxKey, rc)
	ctx = authctx.WithSubject(ctx, authctx.Subject{OrgID: uuid.New(), UserID: uuid.New()})
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/runtime-policies/"+id.String(), bytes.NewReader(encoded))
	res := httptest.NewRecorder()
	// A nil store proves that rejected input cannot even reach persistence.
	h := &RuntimePoliciesHTTP{}
	switch operation {
	case "create":
		h.Create(res, req)
	case "update":
		h.Update(res, req)
	case "reviewed":
		h.ReviewedUpdate(res, req)
	}
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d: %s", res.Code, res.Body.String())
	}
}

func TestPolicyDirectionsPreserveLegacyAndRejectOverflow(t *testing.T) {
	for _, direction := range []int{-1, 4, 32768, 65539} {
		if _, err := policyDirection(direction); err == nil {
			t.Fatalf("accepted direction %d", direction)
		}
	}
	for _, direction := range []int{0, 1, 2, 3} {
		got, err := policyDirection(direction)
		if err != nil || int(got) != direction {
			t.Fatalf("direction %d changed: %d %v", direction, got, err)
		}
	}
}

type policyActionRow int16

func (r policyActionRow) Scan(dest ...any) error {
	*dest[8].(*int16) = int16(r)
	return nil
}

func TestStoredPolicyActionDoesNotWrap(t *testing.T) {
	for _, action := range []int16{-1, 256} {
		if p, err := scanPolicy(policyActionRow(action)); err == nil || p != nil {
			t.Fatalf("stored action %d wrapped into a wire action", action)
		}
	}
	p, err := scanPolicy(policyActionRow(dp.PolicyActionDeny))
	if err != nil || p.DefAction != dp.PolicyActionDeny {
		t.Fatalf("valid action changed: %v %v", p, err)
	}
}
