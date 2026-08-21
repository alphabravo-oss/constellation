package policy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/admission"
	"github.com/alphabravocompany/constellation/pkg/audit"
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

// createAdmissionRuleBody is the builder payload: a name, a mode, and a list of criteria
// rows the UI assembled from the options catalog. The server translates the criteria into
// an admissionRuleSpec (so the YAML always matches the engine schema) rather than trusting
// the client to hand-write YAML.
type createAdmissionRuleBody struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"` // monitor | enforce
	Criteria []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"criteria"`
}

// CreateAdmissionRule builds an admission policy from structured criteria, validates the
// generated YAML against the engine parser, and stores it. POST /policies/admission/rules
func (p *Policies) CreateAdmissionRule(w http.ResponseWriter, r *http.Request) {
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
	var body createAdmissionRuleBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		jsonError(w, http.StatusBadRequest, "name is required")
		return
	}
	if body.Mode != "enforce" {
		body.Mode = "monitor"
	}
	if len(body.Criteria) == 0 {
		jsonError(w, http.StatusBadRequest, "at least one criterion is required")
		return
	}
	specYAML, err := buildAdmissionSpecYAML(body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Validate against the real engine parser so an unsupported/typo'd rule is a clean 400,
	// never a silently-ignored no-op rule.
	if _, supported, verr := admission.RuleFromYAML(body.Name, body.Name, "", body.Mode, specYAML); verr != nil {
		jsonError(w, http.StatusBadRequest, "rule did not compile: "+verr.Error())
		return
	} else if !supported {
		jsonError(w, http.StatusBadRequest, "rule uses criteria the engine cannot enforce")
		return
	}
	var id uuid.UUID
	if err := p.db.Pool().QueryRow(r.Context(), `
INSERT INTO policies (org_id, cluster_id, name, description, engine, category, spec_yaml, enabled, mode)
VALUES ($1, $2, $3, '', 'constellation-admission', 'admission', $4, TRUE, $5) RETURNING id`,
		subj.OrgID, clusterArg, body.Name, specYAML, body.Mode).Scan(&id); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p.auditLog != nil {
		uid, oid := subj.UserID, subj.OrgID
		_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "admission.rule.create",
			TargetKind: "admission-rule", TargetID: id.String(),
			After: map[string]any{"name": body.Name, "mode": body.Mode},
		})
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id.String(), "spec_yaml": specYAML})
}

// buildAdmissionSpecYAML translates the builder's criteria rows into the engine's YAML
// document. Only the keys in the options catalog are recognised; an unknown key is a 400.
func buildAdmissionSpecYAML(body createAdmissionRuleBody) (string, error) {
	spec := map[string]any{"action": "deny"}
	match := map[string]any{}
	images := map[string]any{}
	containers := map[string]any{}
	vuln := map[string]any{}
	pod := map[string]any{}
	var conditions []map[string]any

	csv := func(v string) []string {
		out := []string{}
		for _, part := range strings.Split(v, ",") {
			if t := strings.TrimSpace(part); t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	cond := func(field string) { conditions = append(conditions, map[string]any{"field": field, "equals": true}) }

	for _, c := range body.Criteria {
		switch c.Key {
		case "namespace":
			if ns := csv(c.Value); len(ns) > 0 {
				match["namespaces"] = ns
			}
		case "allowed_registries":
			if reg := csv(c.Value); len(reg) > 0 {
				images["allowedRegistries"] = reg
			}
		case "disallow_latest_tag":
			images["disallowLatestTag"] = true
		case "require_digest":
			images["requireDigest"] = true
		case "run_as_privileged":
			cond("spec.containers[*].securityContext.privileged")
		case "run_as_root":
			containers["requireNonRoot"] = true
		case "read_only_rootfs":
			containers["requireReadOnlyRootFilesystem"] = true
		case "host_network":
			cond("spec.hostNetwork")
		case "host_pid":
			cond("spec.hostPID")
		case "max_critical_cves":
			n, err := strconv.Atoi(strings.TrimSpace(c.Value))
			if err != nil || n < 0 {
				return "", fmt.Errorf("max_critical_cves must be a non-negative integer")
			}
			vuln["maxCriticalCount"] = n
		case "max_high_cves":
			n, err := strconv.Atoi(strings.TrimSpace(c.Value))
			if err != nil || n < 0 {
				return "", fmt.Errorf("max_high_cves must be a non-negative integer")
			}
			vuln["maxHighCount"] = n
		case "deny_cvss_at_score":
			f, err := strconv.ParseFloat(strings.TrimSpace(c.Value), 64)
			if err != nil || f < 0 || f > 10 {
				return "", fmt.Errorf("deny_cvss_at_score must be a CVSS score 0–10")
			}
			vuln["maxCveScoreCount"] = 0
			vuln["cveScore"] = f
		case "denied_cves":
			if cves := csv(c.Value); len(cves) > 0 {
				vuln["deniedCVEs"] = cves
			}
		case "max_allowed_severity":
			sev := strings.ToLower(strings.TrimSpace(c.Value))
			switch sev {
			case "low", "medium", "high", "critical":
				vuln["maxAllowedSeverity"] = sev
			default:
				return "", fmt.Errorf("max_allowed_severity must be low, medium, high, or critical")
			}
		case "require_fix_available":
			vuln["requireFixAvailable"] = true
		case "max_medium_cves":
			n, err := strconv.Atoi(strings.TrimSpace(c.Value))
			if err != nil || n < 0 {
				return "", fmt.Errorf("max_medium_cves must be a non-negative integer")
			}
			vuln["maxMediumCount"] = n
		case "max_critical_with_fix_cves":
			n, err := strconv.Atoi(strings.TrimSpace(c.Value))
			if err != nil || n < 0 {
				return "", fmt.Errorf("max_critical_with_fix_cves must be a non-negative integer")
			}
			vuln["maxCriticalWithFixCount"] = n
		case "max_high_with_fix_cves":
			n, err := strconv.Atoi(strings.TrimSpace(c.Value))
			if err != nil || n < 0 {
				return "", fmt.Errorf("max_high_with_fix_cves must be a non-negative integer")
			}
			vuln["maxHighWithFixCount"] = n
		case "host_ipc":
			cond("spec.hostIPC")
		case "allow_privilege_escalation":
			cond("spec.containers[*].securityContext.allowPrivilegeEscalation")
		case "image_no_os":
			cond("spec.imageNoOS")
		case "require_resource_limits":
			pod["resourceLimit"] = map[string]any{
				"requireCpuRequest":    true,
				"requireCpuLimit":      true,
				"requireMemoryRequest": true,
				"requireMemoryLimit":   true,
			}
		case "pss_level":
			lvl := strings.ToLower(strings.TrimSpace(c.Value))
			if lvl != "baseline" && lvl != "restricted" {
				return "", fmt.Errorf("pss_level must be baseline or restricted")
			}
			spec["podSecurityStandard"] = map[string]any{"level": lvl}
		default:
			return "", fmt.Errorf("unknown criterion %q", c.Key)
		}
	}

	if len(match) > 0 {
		spec["match"] = match
	}
	if len(images) > 0 {
		spec["images"] = images
	}
	if len(containers) > 0 {
		spec["containers"] = containers
	}
	if len(vuln) > 0 {
		spec["vulnerability"] = vuln
	}
	if len(pod) > 0 {
		spec["pod"] = pod
	}
	if len(conditions) > 0 {
		spec["conditions"] = map[string]any{"any": conditions}
	}
	doc := map[string]any{
		"apiVersion": "constellation/v1",
		"kind":       "AdmissionRule",
		"metadata":   map[string]any{"name": body.Name},
		"spec":       spec,
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(out), nil
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
				MaxAllowedSeverity      string   `yaml:"maxAllowedSeverity"`
				MaxCriticalCount        *int     `yaml:"maxCriticalCount"`
				MaxHighCount            *int     `yaml:"maxHighCount"`
				MaxMediumCount          *int     `yaml:"maxMediumCount"`
				MaxCriticalWithFixCount *int     `yaml:"maxCriticalWithFixCount"`
				MaxHighWithFixCount     *int     `yaml:"maxHighWithFixCount"`
				MaxCveScoreCount        *int     `yaml:"maxCveScoreCount"`
				CveScore                float64  `yaml:"cveScore"`
				DeniedCVEs              []string `yaml:"deniedCVEs"`
				RequireFixAvailable     bool     `yaml:"requireFixAvailable"`
			} `yaml:"vulnerability"`
			Pod struct {
				ResourceLimit struct {
					RequireCPURequest    bool `yaml:"requireCpuRequest"`
					RequireCPULimit      bool `yaml:"requireCpuLimit"`
					RequireMemoryRequest bool `yaml:"requireMemoryRequest"`
					RequireMemoryLimit   bool `yaml:"requireMemoryLimit"`
				} `yaml:"resourceLimit"`
			} `yaml:"pod"`
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
	if s.Vulnerability.MaxMediumCount != nil {
		criteria = append(criteria, fmt.Sprintf("max %d medium CVEs", *s.Vulnerability.MaxMediumCount))
	}
	if s.Vulnerability.MaxCriticalWithFixCount != nil {
		criteria = append(criteria, fmt.Sprintf("max %d fixable critical CVEs", *s.Vulnerability.MaxCriticalWithFixCount))
	}
	if s.Vulnerability.MaxHighWithFixCount != nil {
		criteria = append(criteria, fmt.Sprintf("max %d fixable high CVEs", *s.Vulnerability.MaxHighWithFixCount))
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
	if rl := s.Pod.ResourceLimit; rl.RequireCPURequest || rl.RequireCPULimit || rl.RequireMemoryRequest || rl.RequireMemoryLimit {
		criteria = append(criteria, "require resource limits")
	}
	if strings.TrimSpace(s.PodSecurityStandard.Level) != "" {
		criteria = append(criteria, "PSS "+strings.ToLower(s.PodSecurityStandard.Level))
	}
	sort.Strings(criteria)
	return action, criteria
}
