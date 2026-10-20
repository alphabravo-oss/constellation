package compliance

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

type complianceWriteScope struct {
	orgID     uuid.UUID
	clusterID *uuid.UUID
	actorID   *uuid.UUID
	agentID   *uuid.UUID
}

func complianceWriteQuery(r *http.Request) (url.Values, *uuid.UUID, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, nil, errors.New("invalid query")
	}
	for _, name := range []string{"cluster_id", "profile", "benchmark", "node"} {
		if len(values[name]) > 1 {
			return nil, nil, errors.New("query selectors must occur once")
		}
	}
	raw := strings.TrimSpace(values.Get("cluster_id"))
	if raw == "" {
		return values, nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return nil, nil, errors.New("invalid cluster_id")
	}
	return values, &id, nil
}

func (c *Compliance) userWriteScope(w http.ResponseWriter, r *http.Request) (complianceWriteScope, bool) {
	subject, ok := authctx.SubjectFrom(r.Context())
	if !ok || subject.OrgID == uuid.Nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusUnauthorized, "subject required")
		return complianceWriteScope{}, false
	}
	_, cluster, err := complianceWriteQuery(r)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, err.Error())
		return complianceWriteScope{}, false
	}
	if cluster != nil {
		var owned bool
		if err := c.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, cluster, subject.OrgID).Scan(&owned); err != nil {
			apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "cluster unavailable")
			return complianceWriteScope{}, false
		}
		if !owned {
			apiutil.WriteStatus(r.Context(), w, http.StatusNotFound, "cluster not found")
			return complianceWriteScope{}, false
		}
	}
	scope := complianceWriteScope{orgID: subject.OrgID, clusterID: cluster}
	if subject.UserID != uuid.Nil {
		scope.actorID = &subject.UserID
	}
	return scope, true
}

func (c *Compliance) agentWriteScope(w http.ResponseWriter, r *http.Request) (complianceWriteScope, bool) {
	token, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok || token == nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusUnauthorized, "runtime-agent token required")
		return complianceWriteScope{}, false
	}
	_, requested, err := complianceWriteQuery(r)
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusBadRequest, err.Error())
		return complianceWriteScope{}, false
	}
	cluster, err := handler.ResolveAgentClusterID(r.Context(), c.db, token)
	if errors.Is(err, handler.ErrAgentClusterScope) || err == nil && (cluster == nil || requested != nil && *requested != *cluster) {
		apiutil.WriteStatus(r.Context(), w, http.StatusForbidden, "agent token cluster scope mismatch")
		return complianceWriteScope{}, false
	}
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "cluster unavailable")
		return complianceWriteScope{}, false
	}
	return complianceWriteScope{orgID: token.OrgID, clusterID: cluster, agentID: &token.ID}, true
}

// AgentIngest is separate from user JWT/PAT authoring. The caller cannot choose
// another cluster or fall back to unscoped evidence when binding is ambiguous.
func (c *Compliance) AgentIngest(w http.ResponseWriter, r *http.Request) {
	scope, ok := c.agentWriteScope(w, r)
	if ok {
		c.ingest(w, r, scope)
	}
}
func (c *Compliance) AgentClaimBenchRun(w http.ResponseWriter, r *http.Request) {
	scope, ok := c.agentWriteScope(w, r)
	if ok {
		c.claimBenchRun(w, r, scope)
	}
}

// Hold ownership stable through evidence/request writes and their audit record.
// FOR SHARE also fences non-key org_id updates, unlike FOR KEY SHARE.
func (scope complianceWriteScope) lockCluster(w http.ResponseWriter, r *http.Request, tx pgx.Tx) bool {
	if scope.clusterID == nil {
		return true
	}
	var id uuid.UUID
	err := tx.QueryRow(r.Context(), `SELECT id FROM clusters WHERE id=$1 AND org_id=$2 FOR SHARE`, scope.clusterID, scope.orgID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		status, message := http.StatusNotFound, "cluster not found"
		if scope.agentID != nil {
			status, message = http.StatusForbidden, "agent token cluster scope mismatch"
		}
		apiutil.WriteStatus(r.Context(), w, status, message)
		return false
	}
	if err != nil {
		apiutil.WriteStatus(r.Context(), w, http.StatusInternalServerError, "cluster unavailable")
		return false
	}
	return true
}
