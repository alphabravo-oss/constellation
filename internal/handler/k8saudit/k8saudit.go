// Package k8saudit ingests and alerts on Kubernetes API-server audit events —
// the C1 "Kubernetes-audit / control-plane monitoring" slice of the NeuVector
// feature matrix.
//
//	POST /api/v1/k8s-audit:bulk   — apiserver audit-webhook receiver
//	                                (auth: runtime-agent / cluster token)
//	GET  /api/v1/k8s-audit        — console read path (user JWT, verb=read-findings)
//
// The simplest viable collector is the Kubernetes *audit webhook*: the API
// server is configured with an audit policy + a webhook backend that POSTs
// batches of audit.k8s.io/v1 Events to our ingest endpoint. This needs no
// cluster-privileged watch — the control plane pushes to us. See the
// apiserver-config TODO on Ingest.Bulk for the flags/policy required.
//
// Each incoming event is persisted into k8s_audit_events, and the high-signal
// subset — exec into a pod, secret reads, RBAC mutations, privileged pod
// creates — is fanned out to the notify dispatcher + audit log + response-rule
// engine, reusing the exact runtime-events fan-out pattern
// (internal/handler/runtime/runtime_threats_alert.go). A short in-memory dedup
// collapses repeated identical events (e.g. a controller re-listing secrets in a
// hot loop) into one alert per window.
//
// SAFETY: this path is observe-first. The notify/audit legs are pure
// observation; the response-rule legs reuse the existing engines whose seeded
// rules ship in MONITOR mode and whose enforcing actions are operator-authored
// opt-in — nothing here blocks a live control-plane request. (The apiserver
// audit webhook is inherently out-of-band: even a "deny" here cannot retro-
// actively block a request the apiserver already served.)
package k8saudit

import (
	"encoding/json"
	"strings"
	"time"
)

// AuditEvent is the subset of an audit.k8s.io/v1 Event we consume. Field names
// match the apiserver's JSON exactly. Unknown fields are ignored by the decoder;
// the full event is preserved verbatim in the k8s_audit_events.raw column.
type AuditEvent struct {
	Kind    string `json:"kind"`    // "Event"
	AuditID string `json:"auditID"` // apiserver-assigned request id
	Stage   string `json:"stage"`   // ResponseComplete | ResponseStarted | ...
	Verb    string `json:"verb"`    // get|list|create|update|patch|delete|watch|deletecollection
	User    struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`
	ObjectRef struct {
		Resource    string `json:"resource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		APIGroup    string `json:"apiGroup"`
		APIVersion  string `json:"apiVersion"`
		Subresource string `json:"subresource"`
	} `json:"objectRef"`
	ResponseStatus struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	Annotations              map[string]string `json:"annotations"`
	RequestReceivedTimestamp time.Time         `json:"requestReceivedTimestamp"`

	// RequestObject is present only when the apiserver audit policy captures at
	// Request / RequestResponse level. When present for a pod create it carries
	// the pod spec, which we inspect to confirm a privileged create.
	RequestObject json.RawMessage `json:"requestObject,omitempty"`
}

// EventList is the audit-webhook batch envelope the apiserver POSTs
// (apiVersion: audit.k8s.io/v1, kind: EventList).
type EventList struct {
	Kind  string          `json:"kind"`
	Items json.RawMessage `json:"items"`
}

// decision extracts the authorizer verdict the apiserver records as the
// "authorization.k8s.io/decision" annotation ("allow" | "forbid"). Empty when
// the annotation is absent.
func (e *AuditEvent) decision() string {
	if e.Annotations == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(e.Annotations["authorization.k8s.io/decision"]))
}

// sourceIP returns the first client IP the apiserver recorded, if any.
func (e *AuditEvent) sourceIP() string {
	if len(e.SourceIPs) == 0 {
		return ""
	}
	return strings.TrimSpace(e.SourceIPs[0])
}

// --- high-signal classification (pure logic; unit-tested) ------------------

// Signal tags for the high-signal control-plane events C1 alerts on.
const (
	SignalPodExec          = "pod_exec"          // kubectl exec/attach into a pod
	SignalSecretAccess     = "secret_access"     // read of a Secret (get/list/watch)
	SignalRBACChange       = "rbac_change"       // create/update/patch/delete on rbac.authorization.k8s.io
	SignalPrivilegedCreate = "privileged_create" // create of a privileged / host-namespace pod
)

// classify inspects an audit event and, if it is one of the high-signal
// control-plane actions, returns its signal tag + severity. highSignal is false
// for the (vast) majority of routine audit traffic, which is persisted for the
// console but never paged on.
//
// A "forbid" decision keeps the same signal but is not down-graded: a *denied*
// exec/secret-read/RBAC-write is often the more interesting security event (an
// attacker probing what they can reach), so it still alerts.
//
// TODO(matrix): extend to detect more NeuVector control-plane signals —
// serviceaccount/token creation, impersonation (users != user.username via the
// impersonate verb), certificatesigningrequests approval, and namespace/CRD
// deletion. Add them as new Signal* tags + cases here.
func classify(ev *AuditEvent) (signal, severity string, highSignal bool) {
	resource := strings.ToLower(strings.TrimSpace(ev.ObjectRef.Resource))
	sub := strings.ToLower(strings.TrimSpace(ev.ObjectRef.Subresource))
	group := strings.ToLower(strings.TrimSpace(ev.ObjectRef.APIGroup))
	verb := strings.ToLower(strings.TrimSpace(ev.Verb))

	switch {
	case resource == "pods" && (sub == "exec" || sub == "attach"):
		// kubectl exec / attach — remote code execution into a running pod.
		return SignalPodExec, "high", true

	case resource == "secrets" && isReadVerb(verb):
		// Reading Secret material. Bulk list/watch of all secrets is the classic
		// credential-harvesting tell.
		return SignalSecretAccess, "high", true

	case group == "rbac.authorization.k8s.io" && isWriteVerb(verb):
		// roles/rolebindings/clusterroles/clusterrolebindings mutation —
		// privilege-grant / persistence.
		return SignalRBACChange, "high", true

	case resource == "pods" && sub == "" && (verb == "create" || verb == "update" || verb == "patch"):
		// A privileged / host-namespace pod is a container-breakout vector. We
		// can only confirm from the captured pod spec (Request-level audit); a
		// plain pod create without the spec is too noisy to alert on, so it is
		// persisted but not paged.
		//
		// TODO(matrix): to classify these reliably the apiserver audit policy
		// must capture pods create/update at level "RequestResponse" (or at
		// least "Request"). Without RequestObject we conservatively skip.
		if podRequestIsPrivileged(ev.RequestObject) {
			return SignalPrivilegedCreate, "high", true
		}
	}
	return "", "info", false
}

// isReadVerb reports whether verb reads object contents (and thus Secret data).
func isReadVerb(verb string) bool {
	switch verb {
	case "get", "list", "watch":
		return true
	}
	return false
}

// isWriteVerb reports whether verb mutates the object.
func isWriteVerb(verb string) bool {
	switch verb {
	case "create", "update", "patch", "delete", "deletecollection":
		return true
	}
	return false
}

// podRequestIsPrivileged best-effort inspects a captured pod spec (the
// RequestObject of a pods create/update) for a container-breakout posture:
// any container running privileged, or the pod sharing a host namespace. Absent
// or unparseable spec => false (we never guess privileged).
func podRequestIsPrivileged(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var pod struct {
		Spec struct {
			HostNetwork bool `json:"hostNetwork"`
			HostPID     bool `json:"hostPID"`
			HostIPC     bool `json:"hostIPC"`
			Containers  []struct {
				SecurityContext struct {
					Privileged *bool `json:"privileged"`
				} `json:"securityContext"`
			} `json:"containers"`
			InitContainers []struct {
				SecurityContext struct {
					Privileged *bool `json:"privileged"`
				} `json:"securityContext"`
			} `json:"initContainers"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &pod); err != nil {
		return false
	}
	if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
		return true
	}
	for _, c := range pod.Spec.Containers {
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return true
		}
	}
	for _, c := range pod.Spec.InitContainers {
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return true
		}
	}
	return false
}
