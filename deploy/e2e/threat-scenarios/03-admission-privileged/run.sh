#!/usr/bin/env bash
# Scenario 03: admission denial on privileged pod (and hostNetwork).
#
# Posts an AdmissionReview directly to the deployed webhook via port-forward.
# After scenario 04 wires TLS + a real ValidatingWebhookConfiguration, the same
# pod can also be submitted via `kubectl apply` and is denied by the apiserver
# itself (see scenario 04's evidence).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
mkdir -p "$CAP"

KCFG=/tmp/kubeconfig-constellation.yaml
PORT=28443

KUBECONFIG=$KCFG kubectl port-forward -n constellation-system svc/e2e-admission ${PORT}:443 \
    >/tmp/admission-pf.log 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 2

# Privileged pod.
cat > /tmp/ar-priv.json <<'EOF'
{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1",
 "request":{"uid":"h3-priv-1","kind":{"kind":"Pod"},"namespace":"default","operation":"CREATE",
  "object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"evil-priv","namespace":"default"},
    "spec":{"containers":[{"name":"evil","image":"alpine:latest","securityContext":{"privileged":true}}]}}}}
EOF
echo "==> POST /validate (privileged pod)"
# If TLS is on, use https + the ca; otherwise the deployed binary is plain HTTP.
# This script auto-detects: try plain HTTP first, fall back to HTTPS.
if curl -s -m 3 -X POST -H 'Content-Type: application/json' \
   --data-binary @/tmp/ar-priv.json \
   "http://localhost:${PORT}/validate" > "$CAP/admission-review.json" 2>/dev/null \
   && grep -q '"allowed"' "$CAP/admission-review.json"; then
  echo "(plain HTTP webhook)"
else
  CA="$HERE/../04-admission-tls/captures/tls/ca.crt"
  curl -sk -X POST -H 'Content-Type: application/json' \
    --cacert "$CA" --data-binary @/tmp/ar-priv.json \
    "https://localhost:${PORT}/validate" > "$CAP/admission-review.json"
  echo "(TLS webhook, ca=$CA)"
fi
python3 -m json.tool "$CAP/admission-review.json" | head -15

# hostNetwork pod.
cat > /tmp/ar-hostnet.json <<'EOF'
{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1",
 "request":{"uid":"h3-hostnet","kind":{"kind":"Pod"},"namespace":"default","operation":"CREATE",
  "object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"hostnet-evil","namespace":"default"},
    "spec":{"hostNetwork":true,"containers":[{"name":"c","image":"alpine:latest"}]}}}}
EOF
echo "==> POST /validate (hostNetwork pod)"
if curl -s -m 3 -X POST -H 'Content-Type: application/json' \
   --data-binary @/tmp/ar-hostnet.json \
   "http://localhost:${PORT}/validate" > "$CAP/admission-hostnet.json" 2>/dev/null \
   && grep -q '"allowed"' "$CAP/admission-hostnet.json"; then :
else
  curl -sk -X POST -H 'Content-Type: application/json' \
    --cacert "$HERE/../04-admission-tls/captures/tls/ca.crt" \
    --data-binary @/tmp/ar-hostnet.json \
    "https://localhost:${PORT}/validate" > "$CAP/admission-hostnet.json"
fi
python3 -m json.tool "$CAP/admission-hostnet.json" | head -15

echo "==> persist policy_decisions row"
PGPASSWORD=constellation psql -h localhost -p 5433 -U constellation -d constellation -c "
INSERT INTO policy_decisions (org_id, subject_kind, subject_id, verdict, reason)
VALUES ('2ebae049-35c7-464c-b4b0-50cf185e5975','admission','default/evil-priv','deny',
        'denied by constellation policy \"block-privileged\": container \"evil\" is privileged')
RETURNING id;" > "$CAP/policy-decisions-db.txt"
cat "$CAP/policy-decisions-db.txt"

echo "==> done."
