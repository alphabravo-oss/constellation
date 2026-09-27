package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestRuntimeThreatsLargeFixtureFiltersAndPages(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := context.Background()
	orgID, clusterID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "threat-page-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'threat-page')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO runtime_threats (org_id, cluster_id, threat_id, severity, action, application, src_ip, src_port, dst_ip, dst_port, reported_at, at)
SELECT $1, $2, 1001, 8, 0, 7, '10.0.0.1', 40000 + seq, '10.0.0.2', 443, NOW(), NOW()
  FROM generate_series(1, 250) AS seq`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 100, 200} {
		path := fmt.Sprintf("/api/v1/runtime-threats?cluster_id=%s&limit=100&offset=%d&port=443&peer=10.0.0.2&application=7", clusterID, offset)
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: uuid.New()}))
		response := httptest.NewRecorder()
		NewRuntimeThreats(database).List(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("offset %d: status %d: %s", offset, response.Code, response.Body.String())
		}
		var body struct {
			Threats []RuntimeThreatRow `json:"threats"`
			Total   int                `json:"total"`
			HasMore bool               `json:"has_more"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		wantRows := 100
		if offset == 200 {
			wantRows = 50
		}
		if len(body.Threats) != wantRows || body.Total != 250 || body.HasMore != (offset < 200) {
			t.Fatalf("offset %d: rows=%d total=%d has_more=%t", offset, len(body.Threats), body.Total, body.HasMore)
		}
	}
}
