// GitOps export: turn stored policy rows back into the declarative CR documents the operator
// reconciles. This is the inverse of the controllers' mapAdmissionRule / mapResponseRule, and it
// must round-trip: AdmissionCR(row) re-applied upserts the identical row, ResponseCR(rule)
// re-applied upserts the identical rule (see the round-trip test in the controllers package).
//
// `constellationctl policy export-crds` calls List*+*CR to emit kubectl-applyable multi-doc YAML,
// closing the audit's GitOps gap (policy that today lives only in Postgres becomes committable CRs).
package policydb

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cv1alpha1 "github.com/alphabravocompany/constellation/deploy/operator/api/v1alpha1"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// APIVersion is the group/version stamped on every exported CR (kubectl-applyable).
const APIVersion = "constellation.alphabravo.io/v1alpha1"

// Exported CR kinds.
const (
	KindAdmissionRule = "ConstellationAdmissionRule"
	KindResponseRule  = "ConstellationResponseRule"
	KindGroup         = "ConstellationGroup"
	KindNetworkRule   = "ConstellationNetworkRule"
)

// AdmissionCR renders a stored admission policy row as a ConstellationAdmissionRule CR. The row's
// (org_id, name) becomes the CR's Spec.OrgID + metadata.name (its reconcile identity); every mutable
// column is carried explicitly so re-applying the CR reproduces the row exactly (the engine/mode the
// controller would otherwise default are emitted verbatim). TypeMeta is set so the document is
// kubectl-applyable as-is.
func AdmissionCR(row AdmissionRuleRow) *cv1alpha1.ConstellationAdmissionRule {
	return &cv1alpha1.ConstellationAdmissionRule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: APIVersion,
			Kind:       KindAdmissionRule,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: row.Name,
		},
		Spec: cv1alpha1.ConstellationAdmissionRuleSpec{
			OrgID:       row.OrgID.String(),
			Description: row.Description,
			Engine:      row.Engine,
			Mode:        row.Mode,
			Enabled:     row.Enabled,
			SpecYAML:    row.SpecYAML,
		},
	}
}

// ResponseCR renders a stored response rule as a ConstellationResponseRule CR. The rule's
// (org_id, name) becomes the CR's Spec.OrgID + metadata.name; conditions and actions are carried
// verbatim so re-applying the CR reproduces the rule exactly. TypeMeta is set so the document is
// kubectl-applyable as-is. The DB-assigned ID is intentionally dropped — CR identity is (org, name).
func ResponseCR(rule responserule.ResponseRule) *cv1alpha1.ConstellationResponseRule {
	conds := make([]cv1alpha1.ResponseRuleCondition, 0, len(rule.Conditions))
	for _, c := range rule.Conditions {
		conds = append(conds, cv1alpha1.ResponseRuleCondition{
			Field: c.Field,
			Op:    string(c.Op),
			Value: c.Value,
		})
	}
	acts := make([]cv1alpha1.ResponseRuleAction, 0, len(rule.Actions))
	for _, a := range rule.Actions {
		acts = append(acts, cv1alpha1.ResponseRuleAction{
			Type:   string(a.Type),
			Params: a.Params,
		})
	}
	return &cv1alpha1.ConstellationResponseRule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: APIVersion,
			Kind:       KindResponseRule,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: rule.Name,
		},
		Spec: cv1alpha1.ConstellationResponseRuleSpec{
			OrgID:      rule.OrgID.String(),
			Enabled:    rule.Enabled,
			Priority:   rule.Priority,
			EventType:  string(rule.EventType),
			Conditions: conds,
			Actions:    acts,
		},
	}
}

// GroupCR renders a stored group row (GroupRow) as a ConstellationGroup CR. The row's
// (org_id, name) becomes the CR's Spec.OrgID + metadata.name (its reconcile identity); criteria
// and modes are carried verbatim so re-applying the CR reproduces the row exactly (members are
// server-computed and intentionally not exported). TypeMeta is set so the document is
// kubectl-applyable as-is.
func GroupCR(row GroupRow) *cv1alpha1.ConstellationGroup {
	crit := make([]cv1alpha1.GroupCriterion, 0, len(row.Criteria))
	for _, c := range row.Criteria {
		crit = append(crit, cv1alpha1.GroupCriterion{
			Key:   c.Key,
			Value: c.Value,
			Op:    string(c.Op),
		})
	}
	return &cv1alpha1.ConstellationGroup{
		TypeMeta: metav1.TypeMeta{
			APIVersion: APIVersion,
			Kind:       KindGroup,
		},
		ObjectMeta: metav1.ObjectMeta{
			// Name verbatim (like AdmissionCR/ResponseCR) so (org, name) round-trips exactly.
			Name: row.Name,
		},
		Spec: cv1alpha1.ConstellationGroupSpec{
			OrgID:       row.OrgID.String(),
			Kind:        row.Kind,
			Comment:     row.Comment,
			Criteria:    crit,
			PolicyMode:  row.PolicyMode,
			ProfileMode: row.ProfileMode,
		},
	}
}

// NetworkRuleCR renders a stored group→group edge (NetworkRuleRow) as a ConstellationNetworkRule
// CR. The edge's natural key is (org_id, cluster_id, from_group, to_group), so metadata.name is a
// deterministic handle synthesised from that key (edges carry no name column); the reconcile
// identity is the spec fields, not the name. Ports and mode are carried verbatim so re-applying the
// CR reproduces the row exactly. TypeMeta is set so the document is kubectl-applyable as-is.
func NetworkRuleCR(row NetworkRuleRow) *cv1alpha1.ConstellationNetworkRule {
	ports := make([]cv1alpha1.NetworkRulePort, 0, len(row.Ports))
	for _, p := range row.Ports {
		ports = append(ports, cv1alpha1.NetworkRulePort{
			Protocol: p.Protocol,
			Port:     p.Port,
		})
	}
	// A deterministic, DNS-safe name unique within the export: cluster prefix disambiguates the
	// same from/to pair across clusters (the natural key includes cluster_id).
	name := fmt.Sprintf("edge-%s-%s-to-%s",
		shortID(row.ClusterID.String()), sanitizeDNSName(row.FromGroup), sanitizeDNSName(row.ToGroup))
	return &cv1alpha1.ConstellationNetworkRule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: APIVersion,
			Kind:       KindNetworkRule,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: cv1alpha1.ConstellationNetworkRuleSpec{
			OrgID:     row.OrgID.String(),
			ClusterID: row.ClusterID.String(),
			FromGroup: row.FromGroup,
			ToGroup:   row.ToGroup,
			Ports:     ports,
			Mode:      row.Mode,
			Comment:   row.Comment,
		},
	}
}

// sanitizeDNSName lowercases s and replaces every character that is not [a-z0-9-] with '-', so a
// group name becomes a valid RFC1123 metadata.name segment. It is used only to build the CR's
// k8s object handle — the reconcile identity is the spec, so a lossy name is harmless.
func sanitizeDNSName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "unnamed"
	}
	return out
}

// shortID returns the first DNS label of a UUID string (up to the first '-'), a compact cluster
// disambiguator for synthesised edge names.
func shortID(id string) string {
	if i := strings.IndexByte(id, '-'); i > 0 {
		return id[:i]
	}
	return id
}
