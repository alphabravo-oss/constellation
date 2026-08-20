package policy

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
)

// AdmissionRules surfaces the org's admission policies as a structured NV-style rule table:
// name, mode, enabled, action, and a human criteria summary derived from each rule's YAML
// spec. NeuVector shows admission as an ordered rules table (type/criteria/mode/enabled);
// Constellation stored the same rules only as raw YAML on the generic Policies page. The
// Admission page renders this list; enable/disable/delete reuse the existing /policies/{id}
// PATCH/DELETE endpoints. GET /policies/admission/rules
type admissionRuleRowDTO struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Mode     string   `json:"mode"`
	Action   string   `json:"action"`
	Category string   `json:"category"`
	Criteria []string `json:"criteria"`
}

func (p *Policies) AdmissionRules(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows, err := p.db.Pool().Query(r.Context(), `
SELECT id, name, COALESCE(category,''), enabled, mode, COALESCE(spec_yaml,'')
  FROM policies
 WHERE org_id = $1
   AND engine = 'constellation-admission'
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)
 ORDER BY enabled DESC, name`, subj.OrgID, clusterArg)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []admissionRuleRowDTO{}
	for rows.Next() {
		var id uuid.UUID
		var d admissionRuleRowDTO
		var specYAML string
		if err := rows.Scan(&id, &d.Name, &d.Category, &d.Enabled, &d.Mode, &specYAML); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		d.ID = id.String()
		d.Action, d.Criteria = summarizeAdmissionSpec(specYAML)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rules": out, "total": len(out)})
}

// summarizeAdmissionSpec turns a rule's YAML spec into a short, human criteria list so the
// table reads like NeuVector's without the operator opening the YAML. Best-effort: an
// unparseable spec yields an empty summary rather than an error.
func summarizeAdmissionSpec(specYAML string) (action string, criteria []string) {
	action = "deny"
	criteria = []string{}
	if strings.TrimSpace(specYAML) == "" {
		return action, criteria
	}
	var doc struct {
		Spec struct {
			Action string `yaml:"action"`
			Match  struct {
				Namespaces []string `yaml:"namespaces"`
			} `yaml:"match"`
			Images struct {
				DisallowLatestTag bool     `yaml:"disallowLatestTag"`
				RequireDigest     bool     `yaml:"requireDigest"`
				AllowedRegistries []string `yaml:"allowedRegistries"`
			} `yaml:"images"`
			Containers struct {
				RequireNonRoot                bool `yaml:"requireNonRoot"`
				RequireReadOnlyRootFilesystem bool `yaml:"requireReadOnlyRootFilesystem"`
			} `yaml:"containers"`
			Vulnerability struct {
				MaxAllowedSeverity  string   `yaml:"maxAllowedSeverity"`
				MaxCriticalCount    *int     `yaml:"maxCriticalCount"`
				MaxHighCount        *int     `yaml:"maxHighCount"`
				MaxCveScoreCount    *int     `yaml:"maxCveScoreCount"`
				CveScore            float64  `yaml:"cveScore"`
				DeniedCVEs          []string `yaml:"deniedCVEs"`
				RequireFixAvailable bool     `yaml:"requireFixAvailable"`
			} `yaml:"vulnerability"`
			PodSecurityStandard struct {
				Level string `yaml:"level"`
			} `yaml:"podSecurityStandard"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(specYAML), &doc); err != nil {
		return action, criteria
	}
	s := doc.Spec
	if strings.TrimSpace(s.Action) != "" {
		action = strings.ToLower(s.Action)
	}
	if len(s.Match.Namespaces) > 0 {
		criteria = append(criteria, "namespace in "+strings.Join(s.Match.Namespaces, ", "))
	}
	if len(s.Images.AllowedRegistries) > 0 {
		criteria = append(criteria, "registry in "+strings.Join(s.Images.AllowedRegistries, ", "))
	}
	if s.Images.DisallowLatestTag {
		criteria = append(criteria, "disallow :latest")
	}
	if s.Images.RequireDigest {
		criteria = append(criteria, "require digest")
	}
	if s.Containers.RequireNonRoot {
		criteria = append(criteria, "deny run-as-root")
	}
	if s.Containers.RequireReadOnlyRootFilesystem {
		criteria = append(criteria, "require read-only rootfs")
	}
	if s.Vulnerability.MaxCriticalCount != nil {
		criteria = append(criteria, fmt.Sprintf("max %d critical CVEs", *s.Vulnerability.MaxCriticalCount))
	}
	if s.Vulnerability.MaxHighCount != nil {
		criteria = append(criteria, fmt.Sprintf("max %d high CVEs", *s.Vulnerability.MaxHighCount))
	}
	if s.Vulnerability.MaxCveScoreCount != nil {
		criteria = append(criteria, fmt.Sprintf("max %d CVEs at CVSS ≥ %.1f", *s.Vulnerability.MaxCveScoreCount, s.Vulnerability.CveScore))
	}
	if len(s.Vulnerability.DeniedCVEs) > 0 {
		criteria = append(criteria, "denied CVEs: "+strings.Join(s.Vulnerability.DeniedCVEs, ", "))
	}
	if strings.TrimSpace(s.Vulnerability.MaxAllowedSeverity) != "" {
		criteria = append(criteria, "max severity "+strings.ToLower(s.Vulnerability.MaxAllowedSeverity))
	}
	if s.Vulnerability.RequireFixAvailable {
		criteria = append(criteria, "require fix available")
	}
	if strings.TrimSpace(s.PodSecurityStandard.Level) != "" {
		criteria = append(criteria, "PSS "+strings.ToLower(s.PodSecurityStandard.Level))
	}
	sort.Strings(criteria)
	return action, criteria
}
