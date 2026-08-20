package findings

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/vulnprofile"
)

// GitOps YAML portability for vulnerability profiles (NV parity). Only the authored config
// travels: name/description/active/entries/domain_scope. entries + domain_scope round-trip
// through `any` so the YAML is readable and re-validates on import via vulnprofile.Profile.

type portableVulnProfile struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Active      bool   `yaml:"active" json:"active"`
	Entries     any    `yaml:"entries" json:"entries"`
	DomainScope any    `yaml:"domain_scope,omitempty" json:"domain_scope,omitempty"`
}

type vulnProfileBundle struct {
	APIVersion string                `yaml:"apiVersion" json:"apiVersion"`
	Kind       string                `yaml:"kind" json:"kind"`
	Profiles   []portableVulnProfile `yaml:"profiles" json:"profiles"`
}

// Export serializes the org's vuln profiles to a YAML bundle. GET /api/v1/vuln-profiles:export
func (h *VulnProfiles) Export(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT name, description, active, entries, domain_scope
  FROM vuln_profiles
 WHERE org_id=$1 AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
 ORDER BY name`, subj.OrgID, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	bundle := vulnProfileBundle{APIVersion: "constellation/v1", Kind: "VulnProfileBundle", Profiles: []portableVulnProfile{}}
	for rows.Next() {
		var pp portableVulnProfile
		var entriesRaw, domainRaw []byte
		if err := rows.Scan(&pp.Name, &pp.Description, &pp.Active, &entriesRaw, &domainRaw); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_ = json.Unmarshal(entriesRaw, &pp.Entries)
		if len(domainRaw) > 0 && string(domainRaw) != "null" {
			_ = json.Unmarshal(domainRaw, &pp.DomainScope)
		}
		bundle.Profiles = append(bundle.Profiles, pp)
	}
	out, err := yaml.Marshal(bundle)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="constellation-vuln-profiles.yaml"`)
	_, _ = w.Write(out)
}

// Import upserts vuln profiles from a YAML bundle, keyed by name. POST /api/v1/vuln-profiles:import
func (h *VulnProfiles) Import(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	var bundle vulnProfileBundle
	if err := yaml.Unmarshal(raw, &bundle); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid bundle: " + err.Error()})
		return
	}
	if len(bundle.Profiles) == 0 {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bundle contains no profiles"})
		return
	}
	type result struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(bundle.Profiles))
	created, updated := 0, 0
	for _, pp := range bundle.Profiles {
		res := result{Name: pp.Name}
		// Round-trip entries/domain_scope through JSON so they land as the typed structs
		// the validator + storage expect.
		entriesJSON, _ := json.Marshal(pp.Entries)
		domainJSON, _ := json.Marshal(pp.DomainScope)
		var entries []vulnprofile.Entry
		var domain vulnprofile.DomainScope
		// Surface type-mismatch errors instead of swallowing them — otherwise a structurally
		// valid but type-wrong bundle would pass validation as "empty" and overwrite a good
		// profile with the raw, unvalidated blob.
		if err := json.Unmarshal(entriesJSON, &entries); err != nil {
			res.Status, res.Error = "error", "invalid entries: "+err.Error()
			results = append(results, res)
			continue
		}
		if len(domainJSON) > 0 && string(domainJSON) != "null" {
			if err := json.Unmarshal(domainJSON, &domain); err != nil {
				res.Status, res.Error = "error", "invalid domain_scope: "+err.Error()
				results = append(results, res)
				continue
			}
		}
		p := &vulnprofile.Profile{Name: strings.TrimSpace(pp.Name), Description: pp.Description, Active: pp.Active, Entries: entries, DomainScope: domain}
		if err := p.Validate(); err != nil {
			res.Status, res.Error = "error", err.Error()
			results = append(results, res)
			continue
		}
		// Persist exactly what was validated (the typed structs), not the raw YAML blob.
		storedEntries, _ := json.Marshal(p.Entries)
		storedDomain, _ := json.Marshal(p.DomainScope)
		var wasInsert bool
		if err := h.db.Pool().QueryRow(r.Context(), `
INSERT INTO vuln_profiles (org_id, cluster_id, name, description, active, entries, domain_scope, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (org_id, name) DO UPDATE SET
  description=EXCLUDED.description, active=EXCLUDED.active, entries=EXCLUDED.entries,
  domain_scope=EXCLUDED.domain_scope, updated_at=NOW()
RETURNING (xmax = 0)`,
			subj.OrgID, clusterArg, p.Name, p.Description, p.Active, storedEntries, storedDomain, subj.UserID).Scan(&wasInsert); err != nil {
			res.Status, res.Error = "error", err.Error()
			results = append(results, res)
			continue
		}
		if wasInsert {
			res.Status = "created"
			created++
		} else {
			res.Status = "updated"
			updated++
		}
		results = append(results, res)
	}
	if h.auditLog != nil {
		oid, uid := subj.OrgID, subj.UserID
		_, _, _ = h.auditLog.Log(r.Context(), audit.Event{OrgID: &oid, ActorID: &uid,
			Action: "vuln_profile.import", TargetKind: "vuln-profile", TargetID: "",
			After: map[string]any{"created": created, "updated": updated, "total": len(bundle.Profiles)}})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"created": created, "updated": updated, "results": results})
}
