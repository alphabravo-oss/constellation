// Git connector config API + store (roadmap B5).
//
// Stores a per-org GitHub / Azure DevOps connector that config-as-code export is pushed
// to. The PAT is AES-GCM-sealed with the registry KEK (pkg/registry/secrets) and is
// write-only over the API (never returned; the DTO exposes only has_pat).
//
// Endpoints (all gated by manage-org, same as /config/export — the connector holds a
// credential and controls where the full org config is published):
//
//	GET  /api/v1/config/git-connector        read the connector (PAT redacted)
//	PUT  /api/v1/config/git-connector        upsert the connector (optional pat)
//	POST /api/v1/config/git-connector/push   export the org config and push it now
//
// SAFETY: the connector is opt-in (enabled defaults false) and only ever writes to an
// operator-configured external repo. It touches no cluster/dataplane state.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/gitops"
	regsecrets "github.com/alphabravocompany/constellation/pkg/registry/secrets"
)

// GitConnector is the HTTP handler for /api/v1/config/git-connector.
type GitConnector struct {
	db    *db.DB
	audit *audit.Logger
}

// NewGitConnector constructs the handler.
func NewGitConnector(d *db.DB, a *audit.Logger) *GitConnector {
	return &GitConnector{db: d, audit: a}
}

// gitConnectorDTO is the wire shape. PAT is write-only: on read it is never populated,
// and has_pat reports whether one is stored.
type gitConnectorDTO struct {
	Provider       string     `json:"provider"`
	GitHubOwner    string     `json:"github_owner,omitempty"`
	GitHubRepo     string     `json:"github_repo,omitempty"`
	AzureOrg       string     `json:"azure_org,omitempty"`
	AzureProject   string     `json:"azure_project,omitempty"`
	AzureRepo      string     `json:"azure_repo,omitempty"`
	Branch         string     `json:"branch"`
	FilePath       string     `json:"file_path"`
	CommitterName  string     `json:"committer_name"`
	CommitterEmail string     `json:"committer_email"`
	Enabled        bool       `json:"enabled"`
	PAT            string     `json:"pat,omitempty"` // write-only
	HasPAT         bool       `json:"has_pat"`       // read-only
	LastPushAt     *time.Time `json:"last_push_at,omitempty"`
	LastStatus     string     `json:"last_status,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
}

// Get returns the org's connector (PAT redacted). Returns provider defaults when unset.
func (h *GitConnector) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var dto gitConnectorDTO
	var patLen int
	var lastPush *time.Time
	var lastStatus, lastError string
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT provider, COALESCE(github_owner,''), COALESCE(github_repo,''),
       COALESCE(azure_org,''), COALESCE(azure_project,''), COALESCE(azure_repo,''),
       branch, default_file_path, committer_name, committer_email, enabled,
       COALESCE(octet_length(pat_sealed),0), last_push_at, COALESCE(last_status,''), COALESCE(last_error,'')
  FROM git_connectors WHERE org_id=$1`, subj.OrgID).Scan(
		&dto.Provider, &dto.GitHubOwner, &dto.GitHubRepo,
		&dto.AzureOrg, &dto.AzureProject, &dto.AzureRepo,
		&dto.Branch, &dto.FilePath, &dto.CommitterName, &dto.CommitterEmail, &dto.Enabled,
		&patLen, &lastPush, &lastStatus, &lastError)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, 200, gitConnectorDTO{Provider: "github", Branch: "main",
				FilePath: "constellation/config.yaml", CommitterName: "constellation-bot",
				CommitterEmail: "bot@constellation.local", Enabled: false})
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dto.HasPAT = patLen > 0
	dto.LastPushAt = lastPush
	dto.LastStatus = lastStatus
	dto.LastError = lastError
	writeJSON(w, 200, dto)
}

// Put upserts the connector. A non-empty pat is sealed and stored; an empty pat leaves
// the existing sealed PAT untouched (so operators can edit config without re-entering it).
func (h *GitConnector) Put(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	var dto gitConnectorDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		jsonError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	dto.Provider = strings.TrimSpace(dto.Provider)
	if dto.Provider == "" {
		dto.Provider = "github"
	}
	if dto.Provider != "github" && dto.Provider != "azure_devops" {
		jsonError(w, http.StatusBadRequest, "provider must be 'github' or 'azure_devops'")
		return
	}
	if strings.TrimSpace(dto.Branch) == "" {
		dto.Branch = "main"
	}
	if strings.TrimSpace(dto.FilePath) == "" {
		dto.FilePath = "constellation/config.yaml"
	}
	if strings.TrimSpace(dto.CommitterName) == "" {
		dto.CommitterName = "constellation-bot"
	}
	if strings.TrimSpace(dto.CommitterEmail) == "" {
		dto.CommitterEmail = "bot@constellation.local"
	}

	var sealed []byte
	if strings.TrimSpace(dto.PAT) != "" {
		cipher, err := regsecrets.Default(r.Context(), h.db.Pool(), slog.Default())
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "cipher: "+err.Error())
			return
		}
		sealed, err = cipher.Seal([]byte(dto.PAT))
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "seal: "+err.Error())
			return
		}
	}

	// COALESCE keeps the existing PAT when sealed is NULL (no new PAT supplied).
	if _, err := h.db.Pool().Exec(r.Context(), `
INSERT INTO git_connectors
    (org_id, provider, github_owner, github_repo, azure_org, azure_project, azure_repo,
     branch, default_file_path, committer_name, committer_email, enabled, pat_sealed)
VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),
        $8,$9,$10,$11,$12,$13)
ON CONFLICT (org_id) DO UPDATE SET
    provider=EXCLUDED.provider,
    github_owner=EXCLUDED.github_owner, github_repo=EXCLUDED.github_repo,
    azure_org=EXCLUDED.azure_org, azure_project=EXCLUDED.azure_project, azure_repo=EXCLUDED.azure_repo,
    branch=EXCLUDED.branch, default_file_path=EXCLUDED.default_file_path,
    committer_name=EXCLUDED.committer_name, committer_email=EXCLUDED.committer_email,
    enabled=EXCLUDED.enabled,
    pat_sealed=COALESCE(EXCLUDED.pat_sealed, git_connectors.pat_sealed),
    updated_at=NOW()`,
		subj.OrgID, dto.Provider, dto.GitHubOwner, dto.GitHubRepo, dto.AzureOrg, dto.AzureProject, dto.AzureRepo,
		dto.Branch, dto.FilePath, dto.CommitterName, dto.CommitterEmail, dto.Enabled, sealed); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "config.git_connector.update",
		TargetKind: "git-connector",
		TargetID:   subj.OrgID.String(),
		After:      map[string]any{"provider": dto.Provider, "enabled": dto.Enabled, "branch": dto.Branch},
	})
	dto.PAT = ""
	dto.HasPAT = len(sealed) > 0
	writeJSON(w, 200, dto)
}

// Push exports the org config and pushes it to the configured repo immediately.
func (h *GitConnector) Push(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	err := PushConfigToGit(r.Context(), h.db.Pool(), subj.OrgID.String(), subj.Email,
		"constellation: config export by "+subj.Email)
	if err != nil {
		if errors.Is(err, gitops.ErrConnectorDisabled) {
			jsonError(w, http.StatusConflict, "git connector is disabled or not configured")
			return
		}
		jsonError(w, http.StatusBadGateway, "push: "+err.Error())
		return
	}
	_, _, _ = h.audit.Log(r.Context(), audit.Event{
		OrgID:      &subj.OrgID,
		ActorID:    &subj.UserID,
		Action:     "config.git_connector.push",
		TargetKind: "git-connector",
		TargetID:   subj.OrgID.String(),
	})
	writeJSON(w, 200, map[string]string{"status": "pushed"})
}

// loadGitConnector reads and unseals the org's connector into a ready-to-use
// gitops.ConnectorConfig. Returns (config, enabled, err). A missing row yields
// (zero, false, nil) so callers can no-op cleanly.
func loadGitConnector(ctx context.Context, pool *pgxpool.Pool, orgID string) (gitops.ConnectorConfig, bool, error) {
	var (
		cfg     gitops.ConnectorConfig
		enabled bool
		sealed  []byte
		prov    string
	)
	err := pool.QueryRow(ctx, `
SELECT provider, COALESCE(github_owner,''), COALESCE(github_repo,''),
       COALESCE(azure_org,''), COALESCE(azure_project,''), COALESCE(azure_repo,''),
       branch, default_file_path, committer_name, committer_email, enabled, pat_sealed
  FROM git_connectors WHERE org_id=$1`, orgID).Scan(
		&prov, &cfg.GitHubOwner, &cfg.GitHubRepo, &cfg.AzureOrg, &cfg.AzureProject, &cfg.AzureRepo,
		&cfg.Branch, &cfg.FilePath, &cfg.CommitterName, &cfg.CommitterEmail, &enabled, &sealed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return gitops.ConnectorConfig{}, false, nil
		}
		return gitops.ConnectorConfig{}, false, err
	}
	cfg.Provider = gitops.Provider(prov)
	if len(sealed) > 0 {
		cipher, cerr := regsecrets.Default(ctx, pool, slog.Default())
		if cerr != nil {
			return cfg, enabled, cerr
		}
		pt, oerr := cipher.Open(sealed)
		if oerr != nil {
			return cfg, enabled, oerr
		}
		cfg.PAT = string(pt)
	}
	return cfg, enabled, nil
}

// recordGitPushResult stamps the connector's last_push_* columns.
func recordGitPushResult(ctx context.Context, pool *pgxpool.Pool, orgID, status, errMsg string) {
	_, _ = pool.Exec(ctx, `
UPDATE git_connectors SET last_push_at=NOW(), last_status=$2, last_error=NULLIF($3,''), updated_at=NOW()
 WHERE org_id=$1`, orgID, status, errMsg)
}
