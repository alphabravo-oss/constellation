# Scenario 04 — Admission TLS plumbing

**Engine:** `cmd/constellation-admission` over HTTPS, fronted by a
`ValidatingWebhookConfiguration` that the apiserver actually invokes.

**Result:** PASS — Wave E left the webhook running with `--insecure`; this
scenario closes that gap end-to-end (cert mint → Secret → Deployment TLS →
VWC with caBundle → apiserver-driven deny).

## What got built

1. **CA + server cert** under `captures/tls/`:
   - `ca.crt`, `ca.key` — self-signed CA (CN=`constellation-admission-ca`).
   - `tls.crt`, `tls.key` — server cert with SANs:
     `e2e-admission{,.constellation-system{,.svc{,.cluster.local}}}`.
2. **Secret**: `secret/e2e-admission-tls` in `constellation-system`, type
   `kubernetes.io/tls`. Manifest in `captures/secret.yaml`.
3. **ValidatingWebhookConfiguration** `constellation-admission` with:
   - `clientConfig.service.{name,namespace,path,port}` →
     `e2e-admission/constellation-system/validate/443`.
   - `clientConfig.caBundle` = base64(ca.crt).
   - `rules` = CREATE/UPDATE on Pods, `scope: Namespaced`.
   - `namespaceSelector` exempts `kube-system`, `constellation-system`,
     `kube-public`, `kube-node-lease`.
   - `failurePolicy: Ignore` so a webhook outage cannot DoS the apiserver.
   - YAML in `captures/validatingwebhookconfig.yaml`; live state in
     `captures/vwc-current.yaml`; describe output in `captures/vwc-describe.txt`.
4. **Deployment patch** removes the `--insecure` flag and mounts the Secret at
   `/etc/webhook/certs`. The Constellation operator is scaled to 0 while this
   patch is in effect (it would otherwise reconcile the args back to
   `["--insecure"]`). Live spec in `captures/deployment-current.yaml`.

## Proof the apiserver invoked the webhook over TLS

```
$ kubectl apply -f /tmp/priv-pod-tls.yaml
Error from server: error when creating "/tmp/priv-pod-tls.yaml":
admission webhook "validate.constellation.alphabravo.io" denied the request:
denied by constellation policy "block-privileged": container "c" is privileged
```

This output (captured at `captures/kubectl-apply-output.txt`) is decisive: the
apiserver only quotes a webhook by name when the TLS handshake against
`caBundle` succeeded and the webhook returned `allowed: false`. The admission
pod log (`captures/admission-tls-logs.txt`) shows it listening **with TLS** (no
`--insecure` warning) on `:8443`.

## Follow-up

This scenario deliberately scales the operator to 0. For a permanent fix the
operator should learn to consume a `tlsSecretRef` field on
`ConstellationCluster.spec` and stop hard-coding `--insecure`. Tracked outside
Wave H3.

## Reproduce

```
./run.sh
```

To restore the cluster to its operator-managed state:

```
kubectl scale -n constellation-system deployment/constellation-operator --replicas=1
kubectl delete validatingwebhookconfiguration constellation-admission
```
