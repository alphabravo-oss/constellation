#!/usr/bin/env bash
# Scenario 04: provision TLS for the admission webhook + register a
# ValidatingWebhookConfiguration that the apiserver actually invokes.
#
# Steps:
#   1. Mint a self-signed CA + server cert with SANs for the in-cluster Service DNS names.
#   2. kubectl create secret tls e2e-admission-tls with the cert + key.
#   3. Apply a ValidatingWebhookConfiguration whose clientConfig.caBundle is the CA.
#   4. Scale the operator to 0 (it would otherwise revert our patch) and patch the
#      Deployment to drop --insecure + mount the TLS Secret.
#   5. Apply a privileged Pod via `kubectl apply` and capture the apiserver's
#      "admission webhook denied" output — proof the apiserver itself trusted
#      the CA and forwarded the AdmissionReview over TLS.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
TLS="$CAP/tls"
mkdir -p "$TLS"
KCFG=/tmp/kubeconfig-constellation.yaml

echo "==> [1/5] mint TLS material"
if [ ! -s "$TLS/tls.crt" ]; then
  openssl genrsa -out "$TLS/ca.key" 2048 2>/dev/null
  openssl req -x509 -new -key "$TLS/ca.key" -days 3650 \
    -subj '/CN=constellation-admission-ca' -out "$TLS/ca.crt" 2>/dev/null
  openssl genrsa -out "$TLS/tls.key" 2048 2>/dev/null
  cat > "$TLS/csr.cnf" <<'EOF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no
[req_dn]
CN = e2e-admission.constellation-system.svc
[v3_req]
subjectAltName = @alt
[alt]
DNS.1 = e2e-admission
DNS.2 = e2e-admission.constellation-system
DNS.3 = e2e-admission.constellation-system.svc
DNS.4 = e2e-admission.constellation-system.svc.cluster.local
EOF
  openssl req -new -key "$TLS/tls.key" -out "$TLS/tls.csr" -config "$TLS/csr.cnf" 2>/dev/null
  openssl x509 -req -in "$TLS/tls.csr" -CA "$TLS/ca.crt" -CAkey "$TLS/ca.key" -CAcreateserial \
    -out "$TLS/tls.crt" -days 3650 -extensions v3_req -extfile "$TLS/csr.cnf" 2>/dev/null
fi
ls -la "$TLS"/

echo "==> [2/5] kubectl create secret tls"
KUBECONFIG=$KCFG kubectl create secret tls e2e-admission-tls \
  -n constellation-system --cert="$TLS/tls.crt" --key="$TLS/tls.key" \
  --dry-run=client -o yaml > "$CAP/secret.yaml"
KUBECONFIG=$KCFG kubectl apply -f "$CAP/secret.yaml"

echo "==> [3/5] register ValidatingWebhookConfiguration"
CA_B64=$(base64 -w0 < "$TLS/ca.crt")
cat > "$CAP/validatingwebhookconfig.yaml" <<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: constellation-admission
  labels:
    constellation.alphabravo.io/cluster: e2e
webhooks:
  - name: validate.constellation.alphabravo.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Ignore
    timeoutSeconds: 5
    namespaceSelector:
      matchExpressions:
        - {key: "kubernetes.io/metadata.name", operator: NotIn, values: ["kube-system","constellation-system","kube-public","kube-node-lease"]}
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        operations: ["CREATE","UPDATE"]
        scope: Namespaced
    clientConfig:
      service:
        name: e2e-admission
        namespace: constellation-system
        path: /validate
        port: 443
      caBundle: ${CA_B64}
EOF
KUBECONFIG=$KCFG kubectl apply -f "$CAP/validatingwebhookconfig.yaml"
KUBECONFIG=$KCFG kubectl describe validatingwebhookconfiguration constellation-admission > "$CAP/vwc-describe.txt"

echo "==> [4/5] scale operator, patch Deployment to drop --insecure + mount Secret"
KUBECONFIG=$KCFG kubectl scale -n constellation-system deployment/constellation-operator --replicas=0
sleep 3
KUBECONFIG=$KCFG kubectl patch deployment -n constellation-system e2e-admission --type=json -p '[
  {"op":"replace","path":"/spec/template/spec/containers/0/args","value":[]},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts","value":[{"name":"tls","mountPath":"/etc/webhook/certs","readOnly":true}]},
  {"op":"add","path":"/spec/template/spec/volumes","value":[{"name":"tls","secret":{"secretName":"e2e-admission-tls"}}]}
]'
KUBECONFIG=$KCFG kubectl rollout status -n constellation-system deployment/e2e-admission --timeout=60s
KUBECONFIG=$KCFG kubectl get pods -n constellation-system -l app.kubernetes.io/component=admission

echo "==> [5/5] kubectl apply privileged pod — apiserver should deny via VWC"
cat > /tmp/priv-pod-tls.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: tls-priv-test, namespace: default }
spec:
  containers:
    - name: c
      image: alpine:3.18
      command: ["sleep","3600"]
      securityContext: { privileged: true }
EOF
( KUBECONFIG=$KCFG kubectl apply -f /tmp/priv-pod-tls.yaml 2>&1 || true ) \
  | tee "$CAP/kubectl-apply-output.txt"

echo "==> snapshot artefacts"
KUBECONFIG=$KCFG kubectl get validatingwebhookconfiguration constellation-admission -o yaml > "$CAP/vwc-current.yaml"
KUBECONFIG=$KCFG kubectl get deploy -n constellation-system e2e-admission -o yaml > "$CAP/deployment-current.yaml"

POD=$(KUBECONFIG=$KCFG kubectl get pods -n constellation-system -l app.kubernetes.io/component=admission -o jsonpath='{.items[0].metadata.name}')
KUBECONFIG=$KCFG kubectl logs -n constellation-system "$POD" > "$CAP/admission-tls-logs.txt"

echo "==> done. Evidence in $CAP/."
echo "NB: this scenario leaves the operator scaled to 0. Re-enable with:"
echo "    kubectl scale -n constellation-system deployment/constellation-operator --replicas=1"
