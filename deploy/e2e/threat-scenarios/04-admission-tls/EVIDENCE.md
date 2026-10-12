# Scenario 04 — Admission TLS plumbing

**Engine:** `cmd/constellation-admission` over HTTPS, fronted by a
`ValidatingWebhookConfiguration` that the apiserver actually invokes.

**Result:** PASS — Wave E left the webhook running with `--insecure`; this
scenario closes that gap end-to-end (cert mint → Secret → Deployment TLS →
VWC with caBundle → apiserver-driven deny).

## What got built

1. **Public CA + server certificates** under `captures/tls/`:
   - `ca.crt` — self-signed CA (CN=`constellation-admission-ca`).
   - `tls.crt` — server cert with SANs:
     `e2e-admission{,.constellation-system{,.svc{,.cluster.local}}}`.
2. **Secret**: `secret/e2e-admission-tls` in `constellation-system`, type
   `kubernetes.io/tls`. The historical Secret capture was removed because it
   contained a private key. Current runs stream the Secret directly to kubectl;
   private keys live in a mode-0700 temporary directory and are deleted on exit.
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

## October 12 credential remediation

The old TLS Secret remains exposed in Git history. Removing the capture does
not revoke that key or make the full-history scanner pass. The current default
cluster has no `constellation-system/e2e-admission-tls` Secret. The owner is unsure
whether this fixture was used outside local development. A read-only October 12
inventory compared the historical leaf and CA certificate DER SHA-256 fingerprints
against public certificates in every `kubernetes.io/tls` Secret and all validating
and mutating admission webhook CA bundles in the two accessible environments:

| Environment | TLS certificates checked | Webhook CA bundles checked | Matches |
| --- | ---: | ---: | ---: |
| Main local cluster | 2 | 4 | 0 |
| Isolated CNPG test cluster | 14 | 11 | 0 |

The inventory did not read private keys. Its non-secret result is retained locally
at `/tmp/constellation-historical-tls-inventory.json`. This check does not cover
Opaque Secrets, external trust stores or other clusters and does not establish
global revocation. The historical certificate is valid
until May 9, 2036; treat any deployment using it as compromised, replace the key
and certificate, and remove obsolete CA trust. That deployment inventory and
revocation evidence remain release blockers.

New runs generate fresh one-day test certificates even when historical public
captures exist. They retain only public certificates, never a serialized Secret
or private key. `CONSTELLATION_E2E_CAPTURE_DIR` can redirect captures and
`KUBECONFIG` selects the test cluster. Do not point this disruptive scenario at
production: it scales the operator down and changes the admission configuration.

## Reproduce

```
./run.sh
```

To restore the cluster to its operator-managed state:

```
kubectl scale -n constellation-system deployment/constellation-operator --replicas=1
kubectl delete validatingwebhookconfiguration constellation-admission
```
