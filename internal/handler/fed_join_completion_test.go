//go:build integration

package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type remoteJoinCompletionCase struct {
	name     string
	payload  string
	tailErr  error
	closeErr error
	accept   bool
}

func remoteJoinStoredRows(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID) [2]string {
	t.Helper()
	var rows [2]string
	if err := pool.QueryRow(t.Context(), `SELECT row_to_json(j)::text FROM fed_joint_secret j WHERE org_id=$1`, orgID).Scan(&rows[0]); err != nil {
		t.Fatal("cannot snapshot owned joint credential")
	}
	if err := pool.QueryRow(t.Context(), `SELECT row_to_json(s)::text FROM federation_state s WHERE org_id=$1`, orgID).Scan(&rows[1]); err != nil {
		t.Fatal("cannot snapshot owned federation state")
	}
	return rows
}

func checkRemoteJoinCompletionCase(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, test remoteJoinCompletionCase) {
	t.Helper()
	if err := PersistJointJoin(t.Context(), pool, nil, orgID, "owned-prior-cluster", "owned-prior-ticket", "", "", ""); err != nil {
		t.Fatal("cannot prepare prior owned credential")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE federation_state SET state='standalone', master_id='https://owned-prior.example', cluster_name='owned-prior-cluster', revision=17 WHERE org_id=$1`, orgID); err != nil {
		t.Fatal("cannot prepare prior owned federation state")
	}
	before := remoteJoinStoredRows(t, pool, orgID)
	body := &remoteJoinTestBody{reader: strings.NewReader(test.payload), tailErr: test.tailErr, closeErr: test.closeErr}
	client := &http.Client{Transport: remoteJoinTestTransport(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://127.0.0.1:8443/owned/api/v1/federation/join" {
			t.Fatal("join changed the explicitly configured private endpoint")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: request}, nil
	})}
	result, err := performRemoteJoin(t.Context(), pool, nil, client, orgID, "https://127.0.0.1:8443/owned", "owned-join-token", "owned-new-cluster", "owned-new-cluster")
	if body.closed != 1 {
		t.Fatal("join response did not close exactly once")
	}
	after := remoteJoinStoredRows(t, pool, orgID)
	if !test.accept {
		if err == nil || before != after {
			t.Fatal("incomplete join response changed stored credentials or federation state")
		}
		return
	}
	if err != nil || before == after || result.ClusterID != "owned-new-cluster" || result.State != "joint" || result.MTLS {
		t.Fatal("complete bearer-only join did not preserve intended success behavior")
	}
	var clusterID, secret, state string
	if err := pool.QueryRow(t.Context(), `SELECT cluster_id, secret FROM fed_joint_secret WHERE org_id=$1`, orgID).Scan(&clusterID, &secret); err != nil {
		t.Fatal("cannot read completed owned join")
	}
	if err := pool.QueryRow(t.Context(), `SELECT state FROM federation_state WHERE org_id=$1`, orgID).Scan(&state); err != nil {
		t.Fatal("cannot read completed owned federation state")
	}
	if clusterID != "owned-new-cluster" || secret != "owned-new-ticket" || state != "joint" {
		t.Fatal("complete response did not persist its exact credential and state")
	}
}

func TestPerformRemoteJoinCompletenessGatesCredentialWrites(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	orgID, _ := fedTrustPreflight(t, t.Context(), pool)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM fed_joint_secret WHERE org_id=$1`, orgID) })
	cause := errors.New("owned read/close " + remoteJoinDiagnosticCanary)
	for _, test := range []remoteJoinCompletionCase{
		{name: "exact bound accepted", payload: remoteJoinPaddedJSON(), accept: true},
		{name: "over bound whitespace rejected", payload: remoteJoinPaddedJSON() + " "},
		{name: "trailing data beyond old bound rejected", payload: remoteJoinPaddedJSON() + "x"},
		{name: "hidden tail read failure rejected", payload: remoteJoinPaddedJSON(), tailErr: cause},
		{name: "ordinary read failure rejected", payload: `{"secret":"owned-new-ticket"}`, tailErr: cause},
		{name: "close failure rejected", payload: `{"secret":"owned-new-ticket"}`, closeErr: cause},
	} {
		t.Run(test.name, func(t *testing.T) { checkRemoteJoinCompletionCase(t, pool, orgID, test) })
	}
}
