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
whether this fixture was used outside local development.

A wider all-local-refs scan also found **both the CA and server private keys** in
commit `4333d28b2d92be35c8c4b198d6b73f6d6d3945c0`. Public-key comparison confirms
that they match the historical certificates. That commit is reachable from local
branches, but no current `origin` ref contains it and GitHub's commit lookup
reported no commit found. Its publication status is **unconfirmed**; this is not
proof that no copy was shared. The server key is also in the known published
Secret capture. Any environment using these keys needs a fresh CA and server key,
replacement certificates, and removal of old CA trust after the replacement
webhook works. Reissuing a leaf certificate under the old CA is insufficient.

The read-only `scripts/audit-admission-tls-trust.py` compares both certificate
DER and public-key SPKI SHA-256 fingerprints. Public-key matching also detects
reissued certificates that reuse either exposed key. The October 12 run checked
named certificate fields (`ca.crt`, `tls.crt`, `ca-bundle.crt`, `root-cert.pem`,
`cert.pem`) in Secrets of **all types** and ConfigMaps, plus every validating and
mutating admission webhook CA bundle in the two accessible environments:

| Environment | Secret fields / certificates | ConfigMap fields / certificates | Webhook bundles / certificates | Certificate or key matches | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| Main local cluster | 6 / 9 | 7 / 7 | 4 / 4 | 0 | 0 |
| Isolated CNPG test cluster | 24 / 25 | 9 / 9 | 11 / 11 | 0 | 0 |

Counts include repeated certificates in chains or multiple resources. No private
key values are emitted or persisted: kubectl emits only the selected certificate
fields. Its API client necessarily receives the selected Kubernetes resources.
The non-secret reports are retained locally at
`/tmp/constellation-admission-trust-{main,cnpg}-expanded.json`.

Reproduce for each cluster that could have used the scenario:

```sh
python3 -B scripts/audit-admission-tls-trust.py --context CLUSTER_CONTEXT --label CLUSTER_NAME
```

Exit 0 means no match in the stated scope, 1 means a historical certificate or
public key matched, and 2 means at least one inventory or certificate could not
be verified. Errors never mean a clean result. Resource/field identifiers and
public fingerprints identify matches without disclosing key material.

Other certificate field names, mounted files, external trust stores, APIService
and CRD conversion trust, and inaccessible clusters remain outside this check.
The historical certificates are valid until May 9, 2036. Zero scoped matches do
not establish global revocation; deployment inventory and replacement evidence
remain release blockers. The audit itself makes no cluster changes.

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
