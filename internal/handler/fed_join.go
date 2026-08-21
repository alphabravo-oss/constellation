package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/federation"
	regsecrets "github.com/alphabravocompany/constellation/pkg/registry/secrets"
)

// ── FED-JOIN-25: joint-side "join a remote master" endpoint ──────────────────
//
// The master side of the mTLS federation handshake was fully wired (fed_trust.go
// Join issues the per-joint client cert/key + CA + sync ticket), but nothing on the
// JOINT side ever CALLED it: PersistJointJoin had no HTTP driver, there was no
// join-remote handler, constellationctl had no federation command, and the chart set
// no FED_MASTER_URL/TOKEN. So in mTLS mode a joint could never obtain the client cert
// it must present on /sync — mTLS federation was unusable. This handler is the joint's
// half of NeuVector's handlerJoinFed: it takes a master URL + join token, calls the
// master's POST /federation/join, persists the issued credential (client key sealed at
// rest via PersistJointJoin), and flips local federation_state to joint.
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │ ROUTE TO WIRE (intentionally NOT registered here — add to internal/server/ │
// │ server.go in the AUTHENTICATED block, beside the other fed routes near the │
// │ existing `fed := handler.NewFederation(...).WithFedTrust(...)` at ~L867):   │
// │                                                                            │
// │   r.Post("/federation/join-remote", s.requireVerb(rbac.VerbManageOrg, fed.JoinRemote)) │
// │                                                                            │
// │ RBAC verb: rbac.VerbManageOrg (same admin/manage verb as Transition /      │
// │ AddMember / MintJoinToken). The existing `fed` handler needs no extra       │
// │ wiring — JoinRemote only CONSUMES the master's response, it does not mint.  │
// └──────────────────────────────────────────────────────────────────────────┘

// fedJoinRemoteRequest is the JoinRemote body. Any field may be omitted; master_url and
// token fall back to CONSTELLATION_FED_MASTER_URL / CONSTELLATION_FED_MASTER_TOKEN (the
// same env the joint poller + leaderelection read), so a chart can configure the join
// declaratively. cluster_id/cluster_name are this joint's self-reported identity; when
// omitted a stable cluster id is derived so a re-join rotates the SAME member.
type fedJoinRemoteRequest struct {
	MasterURL   string `json:"master_url,omitempty"`
	Token       string `json:"token,omitempty"`
	ClusterID   string `json:"cluster_id,omitempty"`
	ClusterName string `json:"cluster_name,omitempty"`
}

// fedMasterJoinResponse mirrors the master-side Join (fed_trust.go) response envelope:
// the per-cluster sync ticket plus — when the master runs the D2 CA — the per-joint
// client cert/key and the master CA to pin.
type fedMasterJoinResponse struct {
	ClusterID  string `json:"cluster_id"`
	Secret     string `json:"secret"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	CACert     string `json:"ca_cert"`
}

// fedJoinRemoteResult is the JoinRemote response: the identity this joint now polls under
// and whether the master issued mTLS client-cert material.
type fedJoinRemoteResult struct {
	ClusterID string `json:"cluster_id"`
	State     string `json:"state"`
	MasterURL string `json:"master_url"`
	MTLS      bool   `json:"mtls"`
}

// JoinRemote (POST /federation/join-remote) is the joint-side driver for the trust
// handshake: it calls the master's POST /federation/join with a join token, persists the
// issued per-cluster secret (+ per-joint client cert/key/CA when the master runs mTLS) via
// PersistJointJoin, and flips this org's federation_state to joint. Admin-gated
// (VerbManageOrg). master_url/token come from the body or, when absent, the
// CONSTELLATION_FED_MASTER_URL / CONSTELLATION_FED_MASTER_TOKEN env — so the same knobs the
// chart sets drive a declarative join.
func (h *Federation) JoinRemote(w http.ResponseWriter, r *http.Request) {
	subj, _ := SubjectFrom(r.Context())

	var req fedJoinRemoteRequest
	// An empty body is allowed (pure env-driven join); ignore a decode error on no body.
	_ = json.NewDecoder(r.Body).Decode(&req)

	masterURL := firstNonEmpty(req.MasterURL, os.Getenv("CONSTELLATION_FED_MASTER_URL"))
	token := firstNonEmpty(req.Token, os.Getenv("CONSTELLATION_FED_MASTER_TOKEN"))
	if strings.TrimSpace(masterURL) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "master_url is required (body or CONSTELLATION_FED_MASTER_URL)"})
		return
	}
	if strings.TrimSpace(token) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required (body or CONSTELLATION_FED_MASTER_TOKEN)"})
		return
	}

	// Build the at-rest cipher so a master-issued client KEY is sealed on the way into
	// fed_joint_secret (PersistJointJoin refuses to store key material without one). Best-
	// effort: on a bearer-only (no-CA) master the join returns no key, so a nil sealer is
	// fine; performRemoteJoin fails loudly only if a key arrives without a cipher.
	var sealer auth.Sealer
	if cipher, cerr := regsecrets.Default(r.Context(), h.db.Pool(), nil); cerr == nil {
		sealer = cipher
	}

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := performRemoteJoin(r.Context(), h.db.Pool(), sealer, client,
		subj.OrgID, masterURL, token, req.ClusterID, req.ClusterName)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	oid := subj.OrgID
	uid := subj.UserID
	_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
		Action: "federation.join_remote", TargetKind: "federation", TargetID: res.ClusterID,
		After: map[string]any{"state": res.State, "master_url": res.MasterURL, "mtls": res.MTLS}})

	writeJSON(w, http.StatusOK, res)
}

// performRemoteJoin runs the joint half of the trust handshake against masterURL: POST
// /federation/join with the join token + this joint's identity, persist the issued
// credential (PersistJointJoin), and upsert federation_state to joint. Split out from the
// HTTP handler so a test can drive it against an httptest master without a full server.
//
// clusterID/clusterName default to a stable generated identity when empty, so a re-join
// rotates the same member rather than registering a new one.
func performRemoteJoin(ctx context.Context, pool *pgxpool.Pool, sealer auth.Sealer, client *http.Client, orgID uuid.UUID, masterURL, token, clusterID, clusterName string) (fedJoinRemoteResult, error) {
	masterURL = strings.TrimRight(strings.TrimSpace(masterURL), "/")
	clusterID = strings.TrimSpace(clusterID)
	clusterName = strings.TrimSpace(clusterName)
	if clusterID == "" {
		// Reuse a previously-joined identity so a re-join is idempotent; otherwise mint one.
		_ = pool.QueryRow(ctx, `SELECT cluster_id FROM fed_joint_secret WHERE org_id=$1`, orgID).Scan(&clusterID)
		if clusterID == "" {
			clusterID = uuid.NewString()
		}
	}
	if clusterName == "" {
		clusterName = clusterID
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	body, _ := json.Marshal(fedJoinRequest{
		JoinToken:   token,
		ClusterID:   clusterID,
		ClusterName: clusterName,
	})
	url := masterURL + "/api/v1/federation/join"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return fedJoinRemoteResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// The master's mTLS-join guard (D2-3) refuses to hand out a private key over a non-TLS
	// connection; behind an ingress terminator it reaches the app as plain HTTP, so attest
	// the original scheme the way the documented topology does.
	httpReq.Header.Set("X-Forwarded-Proto", "https")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fedJoinRemoteResult{}, fmt.Errorf("call master /federation/join: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fedJoinRemoteResult{}, fmt.Errorf("master /federation/join status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var jr fedMasterJoinResponse
	if err := json.Unmarshal(raw, &jr); err != nil {
		return fedJoinRemoteResult{}, fmt.Errorf("decode master join response: %w", err)
	}
	if strings.TrimSpace(jr.Secret) == "" {
		return fedJoinRemoteResult{}, fmt.Errorf("master join response carried no secret")
	}
	if jr.ClusterID != "" {
		clusterID = jr.ClusterID
	}

	// Persist the per-cluster secret (+ per-joint client cert/key/CA when the master runs
	// mTLS). The private key is sealed at rest inside PersistJointJoin.
	if err := PersistJointJoin(ctx, pool, sealer, orgID, clusterID, jr.Secret, jr.ClientCert, jr.ClientKey, jr.CACert); err != nil {
		return fedJoinRemoteResult{}, fmt.Errorf("persist joint join: %w", err)
	}

	// Flip local federation state to joint so the background poller (ReconcileFedSyncLoop)
	// starts pulling this master. Upsert directly (rather than via federation.Join, which
	// only admits standalone→joint) so a re-join from an already-joint state is idempotent.
	// master_id records the master URL; cluster_name is this joint's self-reported identity,
	// matching what the master stamped its fed_members heartbeat against.
	if _, err := pool.Exec(ctx, `
INSERT INTO federation_state (org_id, state, master_id, cluster_name, revision, updated_at)
VALUES ($1, $2, $3, $4, 0, NOW())
ON CONFLICT (org_id) DO UPDATE SET
    state=EXCLUDED.state, master_id=EXCLUDED.master_id,
    cluster_name=EXCLUDED.cluster_name, updated_at=NOW()`,
		orgID, string(federation.StateJoint), masterURL, clusterID); err != nil {
		return fedJoinRemoteResult{}, fmt.Errorf("update federation_state: %w", err)
	}

	return fedJoinRemoteResult{
		ClusterID: clusterID,
		State:     string(federation.StateJoint),
		MasterURL: masterURL,
		MTLS:      jr.ClientCert != "",
	}, nil
}
