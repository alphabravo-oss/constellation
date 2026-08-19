package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"text/template"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
)

// ClusterImport serves the one-command cluster-join manifest (Rancher's
// /v3/import/<token>.yaml equivalent). The URL token IS the runtime-agent token —
// the join credential — so the endpoint is UNAUTHENTICATED (whoever holds the URL
// can join, exactly like Rancher). It resolves token -> cluster, then renders a
// self-contained agent manifest with this control plane's FQDN + the token baked
// in, so `kubectl apply -f <url>` installs an agent that connects back and enrolls.
type ClusterImport struct {
	db *db.DB
}

func NewClusterImport(d *db.DB) *ClusterImport {
	return &ClusterImport{db: d}
}

// defaultAgentImage is the published runtime-agent image the rendered DaemonSet
// pulls (overridable via CONSTELLATION_AGENT_IMAGE). Must be reachable from the
// TARGET cluster — a local dev tag won't pull remotely.
func agentImage() string {
	if v := strings.TrimSpace(os.Getenv("CONSTELLATION_AGENT_IMAGE")); v != "" {
		return v
	}
	return "ghcr.io/alphabravocompany/constellation/runtime-agent:latest"
}

// Manifest handles GET /api/v1/import/{filename}. filename is "<token>.yaml".
func (h *ClusterImport) Manifest(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")
	token := strings.TrimSuffix(filename, ".yaml")
	if token == "" || len(token) < 16 {
		http.Error(w, "# invalid import token", http.StatusBadRequest)
		return
	}
	clusterID, clusterName, ok := h.resolve(r.Context(), token)
	if !ok {
		http.Error(w, "# import token not found, expired, or revoked", http.StatusNotFound)
		return
	}
	manifest, err := renderImportManifest(importParams{
		ControlPlaneURL: deriveServerURL(r),
		Token:           token,
		ClusterID:       clusterID.String(),
		ClusterName:     clusterName,
		AgentImage:      agentImage(),
	})
	if err != nil {
		http.Error(w, "# render error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write([]byte(manifest))
}

// resolve maps a raw runtime-agent token to its (active, unexpired, unrevoked)
// cluster via the init-bundle that minted it.
func (h *ClusterImport) resolve(ctx context.Context, token string) (uuid.UUID, string, bool) {
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	var tokenID uuid.UUID
	err := h.db.Pool().QueryRow(ctx, `
SELECT id FROM runtime_agent_tokens
 WHERE token_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())`, hash).Scan(&tokenID)
	if err != nil {
		return uuid.Nil, "", false
	}
	var clusterID uuid.UUID
	var name string
	err = h.db.Pool().QueryRow(ctx, `
SELECT cluster_id, name FROM cluster_init_bundles
 WHERE runtime_agent_token_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
 ORDER BY created_at DESC LIMIT 1`, tokenID).Scan(&clusterID, &name)
	if err != nil {
		return uuid.Nil, "", false
	}
	return clusterID, name, true
}

type importParams struct {
	ControlPlaneURL string
	Token           string
	ClusterID       string
	ClusterName     string
	AgentImage      string
}

// renderImportManifest builds a self-contained agent DaemonSet manifest. It's the
// minimal set for the cluster to enroll and run runtime detection: namespace, SA +
// cluster-read RBAC, the token Secret, and the runtime-agent DaemonSet pointed at
// the control-plane FQDN. (The full feature set — scanner, admission, etc. — is
// installed later via helm in consumer mode; this is the register-and-observe core,
// mirroring Rancher's cattle-cluster-agent bootstrap.)
func renderImportManifest(p importParams) (string, error) {
	t, err := template.New("import").Parse(importManifestTmpl)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := t.Execute(&sb, p); err != nil {
		return "", err
	}
	return sb.String(), nil
}

const importManifestTmpl = `# Constellation cluster registration — apply on the target cluster:
#   kubectl apply -f <this-url>
# Registers "{{.ClusterName}}" ({{.ClusterID}}) and connects the agent back to
# {{.ControlPlaneURL}}. The cluster appears under Clusters once the agent checks in.
apiVersion: v1
kind: Namespace
metadata:
  name: constellation-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: constellation-runtime-agent
  namespace: constellation-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: constellation-runtime-agent
rules:
  - apiGroups: [""]
    resources: ["pods", "nodes", "namespaces", "services", "endpoints"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["daemonsets", "deployments", "replicasets", "statefulsets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: constellation-runtime-agent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: constellation-runtime-agent
subjects:
  - kind: ServiceAccount
    name: constellation-runtime-agent
    namespace: constellation-system
---
apiVersion: v1
kind: Secret
metadata:
  name: constellation-runtime-agent-token
  namespace: constellation-system
type: Opaque
stringData:
  token: "{{.Token}}"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: constellation-runtime-agent
  namespace: constellation-system
  labels: { app.kubernetes.io/name: constellation, app.kubernetes.io/component: runtime-agent }
spec:
  selector:
    matchLabels: { app.kubernetes.io/name: constellation, app.kubernetes.io/component: runtime-agent }
  template:
    metadata:
      labels: { app.kubernetes.io/name: constellation, app.kubernetes.io/component: runtime-agent }
    spec:
      serviceAccountName: constellation-runtime-agent
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      tolerations:
        - operator: Exists
      containers:
        - name: agent
          image: {{.AgentImage}}
          imagePullPolicy: IfNotPresent
          securityContext:
            privileged: true
          env:
            - name: CONSTELLATION_CONTROL_PLANE_URL
              value: "{{.ControlPlaneURL}}"
            - name: CONSTELLATION_API_URL
              value: "{{.ControlPlaneURL}}"
            - name: CONSTELLATION_CLUSTER_ID
              value: "{{.ClusterID}}"
            - name: CONSTELLATION_CLUSTER_NAME
              value: "{{.ClusterName}}"
            - name: CONSTELLATION_NODE_NAME
              valueFrom: { fieldRef: { fieldPath: spec.nodeName } }
            - name: NODE_NAME
              valueFrom: { fieldRef: { fieldPath: spec.nodeName } }
            - name: CONSTELLATION_POD_NAMESPACE
              valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
            - name: RUNTIME_AGENT_TOKEN
              valueFrom: { secretKeyRef: { name: constellation-runtime-agent-token, key: token } }
            - name: CONSTELLATION_HOSTSCAN_ROOT
              value: "/host"
            - name: CONSTELLATION_HEALTH_ADDR
              value: ":9404"
          volumeMounts:
            - { name: proc, mountPath: /host/proc, readOnly: true }
            - { name: sys, mountPath: /sys, readOnly: true }
            - { name: bpf-fs, mountPath: /sys/fs/bpf }
            - { name: btf, mountPath: /sys/kernel/btf, readOnly: true }
            - { name: host-root, mountPath: /host, readOnly: true }
            - { name: lib-modules, mountPath: /lib/modules, readOnly: true }
      volumes:
        - { name: proc, hostPath: { path: /proc, type: Directory } }
        - { name: sys, hostPath: { path: /sys, type: Directory } }
        - { name: bpf-fs, hostPath: { path: /sys/fs/bpf, type: DirectoryOrCreate } }
        - { name: btf, hostPath: { path: /sys/kernel/btf, type: DirectoryOrCreate } }
        - { name: host-root, hostPath: { path: /, type: Directory } }
        - { name: lib-modules, hostPath: { path: /lib/modules, type: DirectoryOrCreate } }
`
