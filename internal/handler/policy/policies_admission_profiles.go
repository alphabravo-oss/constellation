package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"

	"github.com/alphabravocompany/constellation/pkg/admission"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
)

type admissionProfileImportRequest struct {
	ProfileID string                            `json:"profile_id,omitempty"`
	Bundle    *admission.AdmissionProfileBundle `json:"bundle,omitempty"`
	Mode      string                            `json:"mode,omitempty"`
	Enabled   *bool                             `json:"enabled,omitempty"`
	DryRun    bool                              `json:"dry_run,omitempty"`
}

type admissionProfilePolicyPreview struct {
	PolicyName  string `json:"policy_name"`
	RuleName    string `json:"rule_name"`
	Description string `json:"description"`
	Engine      string `json:"engine"`
	Category    string `json:"category"`
	Mode        string `json:"mode"`
	Enabled     bool   `json:"enabled"`
	SpecYAML    string `json:"spec_yaml"`
}

type admissionProfileImportResponse struct {
	ProfileID string                          `json:"profile_id"`
	DryRun    bool                            `json:"dry_run"`
	Imported  int                             `json:"imported"`
	IDs       []string                        `json:"ids,omitempty"`
	Policies  []admissionProfilePolicyPreview `json:"policies"`
}

func (p *Policies) AdmissionProfiles(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"profiles": admission.BuiltInAdmissionProfiles(),
	})
}

func (p *Policies) ExportAdmissionProfile(w http.ResponseWriter, r *http.Request) {
	profileID := chi.URLParam(r, "profile")
	profile, ok := admission.BuiltInAdmissionProfile(profileID)
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "admission profile not found"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, admission.AdmissionProfileBundleFor(profile))
}

func (p *Policies) ImportAdmissionProfile(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	req, err := decodeAdmissionProfileImportRequest(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	bundle, err := resolveAdmissionProfileImportBundle(req)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	policies, err := admissionProfilePolicyPreviews(bundle.Profile, req.Mode, req.Enabled)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DryRun {
		httpx.WriteJSON(w, http.StatusOK, admissionProfileImportResponse{
			ProfileID: bundle.Profile.ID,
			DryRun:    true,
			Policies:  policies,
		})
		return
	}
	if p.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "policy storage unavailable")
		return
	}

	tx, err := p.db.Pool().Begin(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	ids := make([]string, 0, len(policies))
	fedRevs := make([]handler.FedSyncPayload, 0, len(policies))
	fedIDs := make([]string, 0, len(policies))
	for _, policy := range policies {
		var id string
		err := tx.QueryRow(r.Context(), `
INSERT INTO policies (
  org_id, name, description, engine, category, spec_yaml, enabled, mode,
  source, lifecycle_stages, enforcement_actions
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8,
  'declarative', ARRAY['DEPLOY'], ARRAY[$9::text]
)
ON CONFLICT (org_id, name, version) DO UPDATE SET
  description = EXCLUDED.description,
  engine = EXCLUDED.engine,
  category = EXCLUDED.category,
  spec_yaml = EXCLUDED.spec_yaml,
  enabled = EXCLUDED.enabled,
  mode = EXCLUDED.mode,
  source = 'declarative',
  lifecycle_stages = ARRAY['DEPLOY'],
  enforcement_actions = ARRAY[$9::text],
  updated_at = NOW()
RETURNING id::text`,
			subj.OrgID, policy.PolicyName, policy.Description, policy.Engine, policy.Category,
			policy.SpecYAML, policy.Enabled, policy.Mode, policyAction(policy.Mode),
		).Scan(&id)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ids = append(ids, id)
		fedIDs = append(fedIDs, id)
		fedRevs = append(fedRevs, handler.FedSyncPayload{
			OrgID: subj.OrgID, Name: policy.PolicyName, Description: policy.Description,
			Engine: policy.Engine, Category: policy.Category, SpecYAML: policy.SpecYAML,
			Mode: policy.Mode, Enabled: policy.Enabled})
	}
	if err := tx.Commit(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	uid, oid := subj.UserID, subj.OrgID
	// G3a / ENT-2: replicate each imported admission-deny policy to joints (master
	// only, best-effort). Recorded under the dedicated admission_policy kind so the
	// fed log mirrors NeuVector's separate FedAdmCtrlDenyRulesType; joints upsert it
	// into the policies table just like a plain policy revision.
	for i, rev := range fedRevs {
		handler.LogFedRevision(r.Context(), p.db.Pool(), oid, "admission_policy", fedIDs[i], rev)
	}
	if p.auditLog != nil {
		_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid,
			Action: "policy.admission_profile.import", TargetKind: "admission-profile", TargetID: bundle.Profile.ID,
			After: map[string]any{"policy_ids": ids, "policy_count": len(ids)},
		})
	}
	if p.dispatcher != nil {
		_, _ = p.dispatcher.Dispatch(r.Context(), notify.Event{
			Kind: "policy.admission_profile.import", OrgID: oid, Severity: "info",
			Title:   "Admission profile imported: " + bundle.Profile.Name,
			Labels:  map[string]string{"profile": bundle.Profile.ID},
			Payload: map[string]any{"policy_ids": ids, "policy_count": len(ids)},
			URL:     "/policies",
		})
	}
	httpx.WriteJSON(w, http.StatusOK, admissionProfileImportResponse{
		ProfileID: bundle.Profile.ID,
		DryRun:    false,
		Imported:  len(ids),
		IDs:       ids,
		Policies:  policies,
	})
}

func decodeAdmissionProfileImportRequest(body io.Reader) (admissionProfileImportRequest, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return admissionProfileImportRequest{}, err
	}
	if len(raw) == 0 {
		return admissionProfileImportRequest{}, errors.New("request body required")
	}
	var req admissionProfileImportRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return admissionProfileImportRequest{}, err
	}
	if req.ProfileID == "" && req.Bundle == nil {
		var bundle admission.AdmissionProfileBundle
		if err := json.Unmarshal(raw, &bundle); err == nil && bundle.Kind != "" {
			req.Bundle = &bundle
		}
	}
	return req, nil
}

func resolveAdmissionProfileImportBundle(req admissionProfileImportRequest) (admission.AdmissionProfileBundle, error) {
	if req.ProfileID != "" && req.Bundle != nil {
		return admission.AdmissionProfileBundle{}, errors.New("provide either profile_id or bundle, not both")
	}
	if req.Bundle != nil {
		if err := validateAdmissionProfileBundle(*req.Bundle); err != nil {
			return admission.AdmissionProfileBundle{}, err
		}
		return *req.Bundle, nil
	}
	if req.ProfileID == "" {
		return admission.AdmissionProfileBundle{}, errors.New("profile_id or bundle required")
	}
	profile, ok := admission.BuiltInAdmissionProfile(req.ProfileID)
	if !ok {
		return admission.AdmissionProfileBundle{}, fmt.Errorf("unknown admission profile %q", req.ProfileID)
	}
	return admission.AdmissionProfileBundleFor(profile), nil
}

func validateAdmissionProfileBundle(bundle admission.AdmissionProfileBundle) error {
	if bundle.APIVersion != admission.AdmissionProfileAPIVersion {
		return fmt.Errorf("unsupported admission profile api_version %q", bundle.APIVersion)
	}
	if bundle.Kind != admission.AdmissionProfileKind {
		return fmt.Errorf("unsupported admission profile kind %q", bundle.Kind)
	}
	if bundle.Profile.ID == "" || bundle.Profile.Name == "" {
		return errors.New("bundle profile must include id and name")
	}
	if len(bundle.Profile.Rules) == 0 {
		return errors.New("bundle profile must include at least one rule")
	}
	if len(bundle.Profile.Rules) > 200 {
		return errors.New("bundle profile must include no more than 200 rules")
	}
	for _, rule := range bundle.Profile.Rules {
		if rule.Name == "" || rule.Engine == "" || rule.Category == "" || rule.SpecYAML == "" {
			return fmt.Errorf("bundle profile rule %q is incomplete", rule.Name)
		}
		if rule.Mode != "monitor" && rule.Mode != "enforce" {
			return fmt.Errorf("bundle profile rule %q has invalid mode %q", rule.Name, rule.Mode)
		}
	}
	return nil
}

func admissionProfilePolicyPreviews(profile admission.AdmissionProfile, modeOverride string, enabledOverride *bool) ([]admissionProfilePolicyPreview, error) {
	if modeOverride != "" && modeOverride != "monitor" && modeOverride != "enforce" {
		return nil, fmt.Errorf("invalid mode override %q", modeOverride)
	}
	out := make([]admissionProfilePolicyPreview, 0, len(profile.Rules))
	for _, rule := range profile.Rules {
		mode := rule.Mode
		if modeOverride != "" {
			mode = modeOverride
		}
		enabled := rule.Enabled
		if enabledOverride != nil {
			enabled = *enabledOverride
		}
		out = append(out, admissionProfilePolicyPreview{
			PolicyName:  profile.ID + "/" + rule.Name,
			RuleName:    rule.Name,
			Description: rule.Description,
			Engine:      rule.Engine,
			Category:    rule.Category,
			Mode:        mode,
			Enabled:     enabled,
			SpecYAML:    rule.SpecYAML,
		})
	}
	return out, nil
}

func policyAction(mode string) string {
	if mode == "enforce" {
		return "deny"
	}
	return "warn"
}
