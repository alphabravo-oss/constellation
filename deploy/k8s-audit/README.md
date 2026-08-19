# Kubernetes audit-webhook → Constellation (C1)

Wires the Kubernetes API server's **audit webhook** to Constellation so
control-plane events (exec into a pod, secret reads, RBAC mutations, privileged
pod creates) are ingested, persisted, and alerted on.

The API server pushes to us — no cluster-privileged watch needed. Two files in
this directory configure it:

| File | API-server flag | Purpose |
|------|-----------------|---------|
| [`audit-policy.yaml`](./audit-policy.yaml) | `--audit-policy-file` | What to audit (high-signal events only). |
| [`audit-webhook-kubeconfig.yaml`](./audit-webhook-kubeconfig.yaml) | `--audit-webhook-config-file` | Where to send it + the bearer token. |

## Ingest endpoint (verified against the code)

- **Path:** `POST /api/v1/k8s-audit:bulk`
  (registered in `internal/server/server.go`; handled by
  `internal/handler/k8saudit` `Ingest.Bulk`).
- **Auth:** runtime-agent / cluster **bearer token** — the route is mounted under
  `RuntimeAgentTokenMiddleware`, which reads `Authorization: Bearer <token>` and
  validates it against `runtime_agent_tokens`. The audit webhook sends the
  kubeconfig's `user.token` as exactly that header, so the two match.
- **Body:** an `audit.k8s.io/v1` `EventList` (the batch envelope) or a bare JSON
  array of Events. Batch delivery is expected (`--audit-webhook-mode=batch`).
- **Read side (console):** `GET /api/v1/k8s-audit` (user JWT, `read-findings`).

The `server:` URL in the kubeconfig template already ends in the exact path
`/api/v1/k8s-audit:bulk` — only change the host/scheme, never the path.

## API-server flags (kubeadm / static-pod control planes)

Add to the `kube-apiserver` manifest / flags:

```
--audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
--audit-webhook-config-file=/etc/kubernetes/audit/audit-webhook-kubeconfig.yaml
--audit-webhook-mode=batch
--audit-webhook-batch-max-size=400
```

Both files must be mounted into the API-server pod (for a kubeadm static pod, drop
them under a host path such as `/etc/kubernetes/audit/` and add the corresponding
`volumes` / `volumeMounts` to `/etc/kubernetes/manifests/kube-apiserver.yaml`).

## k3s

k3s runs the API server embedded, so you don't edit a static-pod manifest — you
pass API-server args through the k3s **server config** and let k3s restart the
apiserver.

1. Copy both files onto the server node, e.g.:

   ```
   /var/lib/rancher/k3s/server/audit/audit-policy.yaml
   /var/lib/rancher/k3s/server/audit/audit-webhook-kubeconfig.yaml
   ```

2. Add `kube-apiserver-arg` entries to `/etc/rancher/k3s/config.yaml`:

   ```yaml
   kube-apiserver-arg:
     - "audit-policy-file=/var/lib/rancher/k3s/server/audit/audit-policy.yaml"
     - "audit-webhook-config-file=/var/lib/rancher/k3s/server/audit/audit-webhook-kubeconfig.yaml"
     - "audit-webhook-mode=batch"
     - "audit-webhook-batch-max-size=400"
   ```

   (Note: `kube-apiserver-arg` values omit the leading `--`.)

3. Restart k3s so the embedded apiserver picks up the args:

   ```
   systemctl restart k3s
   ```

## Reaching the API from the control plane

`kube-apiserver` typically runs in the **host network namespace** on the
control-plane node and often **cannot resolve cluster Service DNS** (CoreDNS/kube-proxy
may not apply to it). The kubeconfig template points at the in-cluster Service
FQDN for convenience; if the apiserver can't reach it, use one of:

- **ClusterIP directly:** `kubectl -n <ns> get svc <release>-api -o jsonpath='{.spec.clusterIP}'`
  and set `server: http://<clusterIP>:8080/api/v1/k8s-audit:bulk` (routable on
  most CNIs from the host).
- **NodePort / LoadBalancer:** expose the API Service and point at the node/LB
  address.
- **Ingress hostname (TLS):** point at your external Constellation URL with
  `https://…/api/v1/k8s-audit:bulk` and supply `certificate-authority-data`.
- **hostAliases / /etc/hosts:** pin the Service name to the ClusterIP on the
  control-plane node.

## Token

`user.token` in the kubeconfig must be a runtime-agent / cluster token (the same
credential class the Constellation DaemonSet agent uses; issue/rotate it via a
cluster init-bundle). Replace `REPLACE_WITH_RUNTIME_AGENT_TOKEN` before applying.
`cluster_id` is resolved server-side from the token's org (the org's primary
connected cluster).

## What is captured

`audit-policy.yaml` keeps only the high-signal set and drops the rest:

| Signal | Rule |
|--------|------|
| `pod_exec` | `pods/exec`, `pods/attach` create — **Metadata** |
| `secret_access` | `secrets` get/list/watch — **Metadata** (never the secret body) |
| `rbac_change` | roles/rolebindings/clusterroles/clusterrolebindings create/update/patch/delete — **Metadata** |
| `privileged_create` | `pods` create/update/patch — **Request** (pod spec needed to detect privileged / hostNetwork/PID/IPC) |
| everything else | dropped (`level: None`) |
