package runtime

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
)

func TestPcapAgentEndpointsRejectCrossClusterAndAmbiguousTokens(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	t.Setenv("CONSTELLATION_DATA_DIR", t.TempDir())
	ctx := context.Background()
	pool := database.Pool()
	orgID, clusterA, clusterB := uuid.New(), uuid.New(), uuid.New()
	tokenA := seedBoundRuntimeAgentScope(t, database, orgID, clusterA)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_pcap_captures WHERE org_id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'pcap-other')`, clusterB, orgID); err != nil {
		t.Fatal(err)
	}
	_, freeID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, "pcap-free-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	freeToken := &handler.RuntimeAgentToken{ID: freeID, OrgID: orgID}
	var pendingID, runningID uuid.UUID
	for _, row := range []struct {
		state string
		id    *uuid.UUID
	}{{"pending", &pendingID}, {"running", &runningID}} {
		if err := pool.QueryRow(ctx, `
INSERT INTO runtime_pcap_captures (org_id, cluster_id, workload, namespace, requested_by, status)
VALUES ($1, $2, 'team/app', 'team', $3, $4) RETURNING id`,
			orgID, clusterB, uuid.New(), row.state).Scan(row.id); err != nil {
			t.Fatal(err)
		}
	}
	h := NewPcapHTTP(database)
	for _, testCase := range []struct {
		name      string
		token     *handler.RuntimeAgentToken
		writeCode int
	}{
		{"other cluster", tokenA, http.StatusNotFound},
		{"ambiguous token", freeToken, http.StatusForbidden},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			claim := httptest.NewRequest(http.MethodGet, "/api/v1/runtime-pcap/claim?cluster_id="+clusterB.String()+"&node=node-a", nil)
			claim = claim.WithContext(handler.WithRuntimeAgentToken(claim.Context(), testCase.token))
			claimResult := httptest.NewRecorder()
			h.Claim(claimResult, claim)
			if claimResult.Code != http.StatusForbidden {
				t.Fatalf("claim status=%d body=%s", claimResult.Code, claimResult.Body.String())
			}

			upload := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-pcap/"+runningID.String()+"/upload", bytes.NewBufferString("pcap bytes"))
			upload = upload.WithContext(handler.WithRuntimeAgentToken(upload.Context(), testCase.token))
			uploadResult := httptest.NewRecorder()
			h.Upload(uploadResult, upload)
			if uploadResult.Code != testCase.writeCode {
				t.Fatalf("upload status=%d body=%s", uploadResult.Code, uploadResult.Body.String())
			}

			status := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-pcap/"+runningID.String()+"/status", bytes.NewBufferString(`{"status":"failed"}`))
			status = status.WithContext(handler.WithRuntimeAgentToken(status.Context(), testCase.token))
			statusResult := httptest.NewRecorder()
			h.UpdateStatus(statusResult, status)
			if statusResult.Code != testCase.writeCode {
				t.Fatalf("status update=%d body=%s", statusResult.Code, statusResult.Body.String())
			}
			for id, want := range map[uuid.UUID]string{pendingID: "pending", runningID: "running"} {
				var got string
				if err := pool.QueryRow(ctx, `SELECT status FROM runtime_pcap_captures WHERE id = $1`, id).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("capture %s status=%s, want %s", id, got, want)
				}
			}
			if _, err := os.Stat(pcapFilePath(runningID)); !os.IsNotExist(err) {
				t.Fatalf("rejected upload created a file: %v", err)
			}
		})
	}
	var uploadID, statusID uuid.UUID
	for _, captureID := range []*uuid.UUID{&uploadID, &statusID} {
		if err := pool.QueryRow(ctx, `
INSERT INTO runtime_pcap_captures (org_id, cluster_id, workload, namespace, requested_by, status)
VALUES ($1, $2, 'team/app', 'team', $3, 'running') RETURNING id`,
			orgID, clusterA, uuid.New()).Scan(captureID); err != nil {
			t.Fatal(err)
		}
	}
	upload := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-pcap/"+uploadID.String()+"/upload", bytes.NewBufferString("pcap bytes"))
	upload = upload.WithContext(handler.WithRuntimeAgentToken(upload.Context(), tokenA))
	uploadResult := httptest.NewRecorder()
	h.Upload(uploadResult, upload)
	if uploadResult.Code != http.StatusOK {
		t.Fatalf("bound upload status=%d body=%s", uploadResult.Code, uploadResult.Body.String())
	}
	file, err := os.ReadFile(pcapFilePath(uploadID))
	if err != nil || string(file) != "pcap bytes" {
		t.Fatalf("bound upload file=%q err=%v", file, err)
	}
	status := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-pcap/"+statusID.String()+"/status", bytes.NewBufferString(`{"status":"failed"}`))
	status = status.WithContext(handler.WithRuntimeAgentToken(status.Context(), tokenA))
	statusResult := httptest.NewRecorder()
	h.UpdateStatus(statusResult, status)
	if statusResult.Code != http.StatusOK {
		t.Fatalf("bound status update=%d body=%s", statusResult.Code, statusResult.Body.String())
	}
	for id, want := range map[uuid.UUID]string{uploadID: "completed", statusID: "failed"} {
		var got string
		if err := pool.QueryRow(ctx, `SELECT status FROM runtime_pcap_captures WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("bound capture %s status=%s, want %s", id, got, want)
		}
	}
}
