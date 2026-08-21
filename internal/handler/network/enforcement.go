package network

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
)

// Phase 1 network enforcement. Direct, CNI-enforced block/isolate actions taken
// from the network map — the Tier-1 datapath that needs no dp inline mode:
//   isolate  -> native NetworkPolicy default-deny over the target workload's pods
//   block_ip -> CiliumNetworkPolicy egressDeny/ingressDeny toCIDR scoped to one workload
// Rows land in network_enforcement_actions; the network-policy-applier reconciles
// them to the cluster (apply active, delete lifting). Live-connection kill stays a
// separate immediate action (KillSession / dp ctrl_clear_session).

type enforcementDTO struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Target      string `json:"target"`
	Namespace   string `json:"namespace"`
	Workload    string `json:"workload,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Flavor      string `json:"flavor"`
	ResourceRef string `json:"resource_ref"`
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
	CreatedBy   string `json:"created_by,omitempty"`
	LastStatus  string `json:"last_status,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// EnforcementList — GET /network/enforcement?cluster_id=&state=
func (h *Network) EnforcementList(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterID, err := h.resolveNetworkCluster(r, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, kind, target, namespace, workload, direction, manifest_flavor, resource_ref,
       state, reason, created_by, last_status, last_error, created_at
  FROM network_enforcement_actions
 WHERE org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2)
   AND ($3 = '' OR state = $3)
   AND state <> 'removed'
 ORDER BY created_at DESC
 LIMIT 500`, subj.OrgID, clusterID, state)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []enforcementDTO{}
	for rows.Next() {
		var d enforcementDTO
		var created time.Time
		if err := rows.Scan(&d.ID, &d.Kind, &d.Target, &d.Namespace, &d.Workload, &d.Direction,
			&d.Flavor, &d.ResourceRef, &d.State, &d.Reason, &d.CreatedBy, &d.LastStatus, &d.LastError, &created); err != nil {
			continue
		}
		d.CreatedAt = created.UTC().Format(time.RFC3339)
		out = append(out, d)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"actions": out})
}

// EnforcementCreate — POST /network/enforcement
//
//	{ "kind": "isolate", "target": "ns/name", "reason": "..." }
//	{ "kind": "block_ip", "workload": "ns/name", "target": "1.2.3.4", "direction": "egress", "reason": "..." }
func (h *Network) EnforcementCreate(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	var req struct {
		Kind      string `json:"kind"`
		Target    string `json:"target"`
		Workload  string `json:"workload"`
		Direction string `json:"direction"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	req.Kind = strings.TrimSpace(req.Kind)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "reason is required"})
		return
	}
	clusterID, err := h.resolveNetworkCluster(r, subj.OrgID)
	if err != nil || clusterID == nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "a specific cluster is required for enforcement"})
		return
	}

	var (
		ns, name, flavor, manifest, ref, workload, direction, target string
	)
	switch req.Kind {
	case "isolate":
		ns, name = splitWorkload(strings.TrimSpace(req.Target))
		if ns == "" || name == "" {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "target must be 'namespace/name'"})
			return
		}
		labels := h.workloadLabels(r, subj.OrgID, clusterID, ns, name)
		flavor = "native"
		manifest, ref = isolateManifest(ns, name, labels)
		target = req.Target

	case "block_ip":
		ip := strings.TrimSpace(req.Target)
		if net.ParseIP(ip) == nil {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "target must be a valid IP address"})
			return
		}
		// A single-IP block ("allow all except this IP") is only expressible in a
		// deny-capable CNI (Cilium/Calico). Native NetworkPolicy (flannel/k3s) is
		// allow-list only — reject with a clear alternative rather than applying a
		// CRD the cluster can't enforce.
		if cni := h.clusterCNI(r, subj.OrgID, clusterID); !denyCapableCNI(cni) {
			httpx.WriteJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": fmt.Sprintf("this cluster's CNI (%s) can't block a single IP — that needs a deny-capable CNI (Cilium/Calico). Isolate the workload, or kill the live session, instead.", cniLabel(cni)),
			})
			return
		}
		ns, name = splitWorkload(strings.TrimSpace(req.Workload))
		if ns == "" || name == "" {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "workload ('namespace/name') is required to scope an IP block"})
			return
		}
		direction = normalizeDirection(req.Direction)
		labels := h.workloadLabels(r, subj.OrgID, clusterID, ns, name)
		flavor = "cilium" // per-IP deny needs a deny-capable policy; native NetworkPolicy is allow-list only
		workload = req.Workload
		target = ip
		manifest, ref = blockIPManifest(ns, name, ip, direction, labels)

	default:
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "kind must be 'isolate' or 'block_ip'"})
		return
	}

	var id string
	err = h.db.Pool().QueryRow(r.Context(), `
INSERT INTO network_enforcement_actions
    (org_id, cluster_id, kind, target, namespace, workload, direction, manifest_flavor, manifest, resource_ref, reason, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING id::text`,
		subj.OrgID, clusterID, req.Kind, target, ns, workload, direction, flavor, manifest, ref, req.Reason, subj.Email).
		Scan(&id)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, enforcementDTO{
		ID: id, Kind: req.Kind, Target: target, Namespace: ns, Workload: workload,
		Direction: direction, Flavor: flavor, ResourceRef: ref, State: "active",
		Reason: req.Reason, CreatedBy: subj.Email,
	})
}

// EnforcementLift — DELETE /network/enforcement/{id}. Marks the action for removal;
// the applier deletes the policy from the cluster on its next pass.
func (h *Network) EnforcementLift(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	tag, err := h.db.Pool().Exec(r.Context(), `
UPDATE network_enforcement_actions
   SET state = 'lifting', updated_at = NOW()
 WHERE id = $1 AND org_id = $2 AND state = 'active'`, id, subj.OrgID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tag.RowsAffected() == 0 {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "no active enforcement action with that id"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "lifting"})
}

// workloadLabels resolves a workload's pod-selector labels from the deployments
// inventory, falling back to {"app": name} — the same seed the netpolicy candidate
// generator uses, so isolate selects the same pods a learned policy would.
func (h *Network) workloadLabels(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID, ns, name string) map[string]string {
	labels := map[string]string{"app": name}
	var raw []byte
	err := h.db.Pool().QueryRow(r.Context(), `
SELECT labels FROM deployments
 WHERE org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2) AND namespace = $3 AND name = $4
 LIMIT 1`, orgID, clusterID, ns, name).Scan(&raw)
	if err == nil && len(raw) > 0 {
		var parsed map[string]string
		if json.Unmarshal(raw, &parsed) == nil && len(parsed) > 0 {
			labels = parsed
		}
	}
	return labels
}

// clusterCNI returns the most-recently observed CNI name for the cluster (from
// host_facts), or "" when unknown.
func (h *Network) clusterCNI(r *http.Request, orgID uuid.UUID, clusterID *uuid.UUID) string {
	var cni string
	_ = h.db.Pool().QueryRow(r.Context(), `
SELECT COALESCE(cni_name,'') FROM host_facts
 WHERE org_id = $1 AND ($2::uuid IS NULL OR cluster_id = $2) AND COALESCE(cni_name,'') <> ''
 ORDER BY observed_at DESC LIMIT 1`, orgID, clusterID).Scan(&cni)
	return cni
}

// denyCapableCNI reports whether the CNI can enforce a per-IP deny policy.
func denyCapableCNI(cni string) bool {
	c := strings.ToLower(cni)
	return strings.Contains(c, "cilium") || strings.Contains(c, "calico")
}

func cniLabel(cni string) string {
	if strings.TrimSpace(cni) == "" {
		return "unknown / native NetworkPolicy"
	}
	return cni
}

// --- manifest generators (rendered as JSON, which is valid YAML for the applier) ---

// isolateManifest renders a native NetworkPolicy that selects the workload's pods
// and declares both policy types with no allow rules → default-deny all ingress+egress.
func isolateManifest(ns, name string, labels map[string]string) (string, string) {
	polName := k8sName("constellation-isolate-" + name)
	obj := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name":      polName,
			"namespace": ns,
			"labels":    managedLabels("isolate"),
		},
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": labels},
			"policyTypes": []string{"Ingress", "Egress"},
		},
	}
	b, _ := json.Marshal(obj)
	return string(b), "networking.k8s.io/v1/NetworkPolicy:" + ns + "/" + polName
}

// blockIPManifest renders a CiliumNetworkPolicy that denies the workload's traffic
// to/from a single IP (via egressDeny/ingressDeny toCIDR). Deny rules are additive
// and don't disturb the workload's other traffic — precise "block this line".
func blockIPManifest(ns, name, ip, direction string, labels map[string]string) (string, string) {
	polName := k8sName(fmt.Sprintf("constellation-block-%s-%s", name, ipSlug(ip)))
	cidr := ip + "/32"
	if strings.Contains(ip, ":") {
		cidr = ip + "/128"
	}
	spec := map[string]any{
		"endpointSelector": map[string]any{"matchLabels": labels},
	}
	if direction == "egress" || direction == "both" {
		spec["egressDeny"] = []any{map[string]any{"toCIDR": []string{cidr}}}
	}
	if direction == "ingress" || direction == "both" {
		spec["ingressDeny"] = []any{map[string]any{"fromCIDR": []string{cidr}}}
	}
	obj := map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name":      polName,
			"namespace": ns,
			"labels":    managedLabels("block-ip"),
		},
		"spec": spec,
	}
	b, _ := json.Marshal(obj)
	return string(b), "cilium.io/v2/CiliumNetworkPolicy:" + ns + "/" + polName
}

func managedLabels(kind string) map[string]any {
	return map[string]any{
		"app.kubernetes.io/managed-by": "constellation",
		"constellation.dev/enforcement": kind,
	}
}

func normalizeDirection(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "egress":
		return "egress"
	case "ingress":
		return "ingress"
	default:
		return "both"
	}
}

var nonName = regexp.MustCompile(`[^a-z0-9-]+`)

// k8sName lower-cases, strips illegal chars, and caps to the 253-char DNS-subdomain limit.
func k8sName(s string) string {
	s = strings.ToLower(s)
	s = nonName.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 253 {
		s = strings.Trim(s[:253], "-")
	}
	if s == "" {
		s = "constellation-enforce"
	}
	return s
}

// ipSlug makes an IP safe for a k8s name (dots/colons → dashes).
func ipSlug(ip string) string {
	return strings.NewReplacer(".", "-", ":", "-").Replace(ip)
}
