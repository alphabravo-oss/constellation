package compliance

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
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
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return complianceWriteScope{}, false
	}
	_, cluster, err := complianceWriteQuery(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return complianceWriteScope{}, false
	}
	if cluster != nil {
		var owned bool
		if err := c.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, cluster, subject.OrgID).Scan(&owned); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "cluster unavailable"})
			return complianceWriteScope{}, false
		}
		if !owned {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "cluster not found"})
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
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "runtime-agent token required"})
		return complianceWriteScope{}, false
	}
	_, requested, err := complianceWriteQuery(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return complianceWriteScope{}, false
	}
	cluster, err := handler.ResolveAgentClusterID(r.Context(), c.db, token)
	if errors.Is(err, handler.ErrAgentClusterScope) || err == nil && (cluster == nil || requested != nil && *requested != *cluster) {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "agent token cluster scope mismatch"})
		return complianceWriteScope{}, false
	}
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "cluster unavailable"})
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
