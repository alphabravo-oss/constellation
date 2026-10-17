#!/usr/bin/env bash
# Destructive only to the NEW namespace this script creates in an explicit k3d cluster.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off
: "${CNPG_TEST_KUBECONFIG:?Set CNPG_TEST_KUBECONFIG to an isolated k3d kubeconfig}"
: "${CNPG_TEST_API_IMAGE:?Set CNPG_TEST_API_IMAGE to the freshly built API image imported into that cluster}"
for executable in kubectl helm python3 goose go rg curl; do command -v "$executable" >/dev/null; done
k=(kubectl --kubeconfig "$CNPG_TEST_KUBECONFIG")
context="$("${k[@]}" config current-context)"
[[ "$context" == k3d-* ]] || { echo 'Refusing a non-k3d context' >&2; exit 1; }
"${k[@]}" get crd clusters.postgresql.cnpg.io objectstores.barmancloud.cnpg.io >/dev/null
umask 077
work="$(mktemp -d /tmp/constellation-cnpg-test.XXXXXX)"
namespace="recovery-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
pg_port="${CNPG_TEST_PG_PORT:-15435}"
api_port="${CNPG_TEST_API_PORT:-18083}"
pg_forward=""; api_forward=""; created=0
cleanup() {
  result=$?
  [[ -z "$pg_forward" ]] || kill "$pg_forward" 2>/dev/null || true
  [[ -z "$api_forward" ]] || kill "$api_forward" 2>/dev/null || true
  if [[ "$created" == 1 && "${KEEP_CLUSTER:-0}" != 1 ]]; then
    "${k[@]}" delete namespace "$namespace" --wait=false >/dev/null || result=1
  fi
  echo "Restricted evidence: $work (namespace $namespace; result $result)"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"${k[@]}" create namespace "$namespace" >/dev/null
created=1
k+=(-n "$namespace")
python3 - "$work" <<'PY'
import pathlib, secrets, sys
p = pathlib.Path(sys.argv[1])
for name, length in [('ACCESS_KEY_ID', 16), ('SECRET_ACCESS_KEY', 32), ('kek', 32), ('wrong-kek', 32)]:
    (p / name).write_text(secrets.token_hex(length))
PY
"${k[@]}" create secret generic rustfs-credentials --from-file="$work/ACCESS_KEY_ID" --from-file="$work/SECRET_ACCESS_KEY" >/dev/null
"${k[@]}" create secret generic recovery-application-keys --from-file="$work/kek" >/dev/null
"${k[@]}" create secret generic recovery-wrong-keys --from-file="kek=$work/wrong-kek" >/dev/null
fixtures=deploy/dev/cnpg-rustfs
"${k[@]}" apply -f "$fixtures/rustfs.yaml" >/dev/null
"${k[@]}" rollout status statefulset/rustfs --timeout=300s
"${k[@]}" create configmap rustfs-create-bucket --from-file="$fixtures/create_bucket.py" >/dev/null
"${k[@]}" apply -f "$fixtures/bucket-job.yaml" >/dev/null
"${k[@]}" wait --for=condition=Complete job/rustfs-create-bucket --timeout=180s
chart=deploy/charts/constellation
helm template recovery-source "$chart" -n "$namespace" -f "$fixtures/source-values.yaml" \
  --show-only templates/postgres-secrets.yaml --show-only templates/postgres-cnpg-cluster.yaml >"$work/source.yaml"
"${k[@]}" apply -f "$work/source.yaml" >/dev/null
"${k[@]}" wait --for=condition=Ready cluster/recovery-source-postgres --timeout=600s
sql() { "${k[@]}" exec "$1-1" -c postgres -- psql -U postgres -d constellation -v ON_ERROR_STOP=1 -Atc "$2"; }
threat_snapshot() {
  sql "$1" "SELECT jsonb_build_object(
    'threats',(SELECT jsonb_agg(to_jsonb(t)) FROM runtime_threats t WHERE node='recovery-uint32-proof'),
    'flows',(SELECT jsonb_agg(to_jsonb(f)) FROM network_flows f WHERE src_workload='recovery-uint32-proof/raw'),
    'rollups',(SELECT jsonb_agg(to_jsonb(r)) FROM network_flow_rollups r WHERE src_workload='recovery-uint32-proof/aggregate'))"
}
"${k[@]}" port-forward svc/recovery-source-postgres-rw "$pg_port:5432" >"$work/pg-forward.log" 2>&1 &
pg_forward=$!
for ((n=0;n<30;n++)); do
  if rg -q 'Forwarding from' "$work/pg-forward.log"; then break; fi
  kill -0 "$pg_forward"; sleep 1
done
export DATABASE_URL
DATABASE_URL="$("${k[@]}" get secret recovery-source-database-url -o json | python3 -c 'import base64,json,sys,urllib.parse; u=urllib.parse.urlsplit(base64.b64decode(json.load(sys.stdin)["data"]["url"]).decode()); print(urllib.parse.urlunsplit(u._replace(netloc=u.netloc.split("@")[0]+"@127.0.0.1:"+sys.argv[1])))' "$pg_port")"
goose -dir db/migrations postgres "$DATABASE_URL" up >"$work/migrations.log" 2>&1
goose -dir db/migrations postgres "$DATABASE_URL" up >>"$work/migrations.log" 2>&1
go run ./cmd/constellation-seed >"$work/seed.log" 2>&1
python3 "$fixtures/check_api.py" prepare "$api_port" "$work"
"${k[@]}" exec -i recovery-source-postgres-1 -c postgres -- psql -U postgres -d constellation -v ON_ERROR_STOP=1 <"$work/scanner.sql" >"$work/scanner-seed.log"
# Exercise the full unsigned range and explicitly incomplete aggregate metadata.
# A future raw timestamp keeps the background fold from changing this fixture;
# the aggregate uses a different tuple and must retain its independent counters.
sql recovery-source-postgres "
INSERT INTO runtime_threats(org_id,cluster_id,node,threat_id,severity,reported_at,packet)
 SELECT org_id,id,'recovery-uint32-proof',4294967295,7,now(),decode('aabbcc','hex') FROM clusters ORDER BY id LIMIT 1;
INSERT INTO network_flows(org_id,cluster_id,src_workload,dst_workload,protocol,at,threat_id,bytes,packets)
 SELECT org_id,id,'recovery-uint32-proof/raw','recovery/peer','tcp',now()+interval '2 hours',4294967295,123,4 FROM clusters ORDER BY id LIMIT 1;
INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,bucket,max_at,flow_count,max_threat_id,threat_id_complete,sum_bytes,sum_packets)
 SELECT org_id,id,'recovery-uint32-proof/aggregate','recovery/peer','tcp',date_trunc('hour',now()),now(),2,2147483648,false,12345,456 FROM clusters ORDER BY id LIMIT 1;" >/dev/null
threat_snapshot recovery-source-postgres >"$work/threat-source.json"
python3 - "$work/threat-source.json" <<'PY'
import json, sys
snapshot = json.load(open(sys.argv[1]))
assert all(len(snapshot[key]) == 1 for key in ('threats', 'flows', 'rollups'))
assert snapshot['threats'][0]['threat_id'] == snapshot['flows'][0]['threat_id'] == 4294967295
assert snapshot['rollups'][0]['max_threat_id'] == 2147483648
assert snapshot['rollups'][0]['threat_id_complete'] is False
PY
sql recovery-source-postgres "CREATE TABLE recovery_proof(id int PRIMARY KEY, evidence text NOT NULL); INSERT INTO recovery_proof VALUES (1,'base-backup');" >/dev/null
# Delay schedule creation until migrations/fixtures are committed.
helm template recovery-source "$chart" -n "$namespace" -f "$fixtures/source-values.yaml" \
  --show-only templates/postgres-cnpg-scheduledbackup.yaml >"$work/schedule.yaml"
"${k[@]}" apply -f "$work/schedule.yaml" >/dev/null
backup=""; phase=""
for ((n=0;n<300;n++)); do
  backup="$("${k[@]}" get backups -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [[ -n "$backup" ]]; then
    phase="$("${k[@]}" get backup "$backup" -o jsonpath='{.status.phase}')"
    [[ "$phase" != failed ]] || { echo 'Scheduled backup failed' >&2; exit 1; }
    [[ "$phase" != completed ]] || break
  fi
  sleep 2
done
[[ "$phase" == completed ]]
echo "Scheduled backup completed: $backup"
# Both containers must exercise the exact selected API build, not a stale fixture.
"${k[@]}" create --dry-run=client -f "$fixtures/api.yaml" -o json >"$work/api-template.json"
python3 "$fixtures/render_api.py" "$work/api-template.json" "$work/api-source.yaml" "$CNPG_TEST_API_IMAGE"
"${k[@]}" apply -f "$work/api-source.yaml" >/dev/null
"${k[@]}" rollout status deployment/recovery-api --timeout=300s
forward_api() {
  "${k[@]}" port-forward svc/recovery-api "$api_port:8080" >"$work/api-forward.log" 2>&1 &
  api_forward=$!
  for ((n=0;n<30;n++)); do
    if curl --max-time 5 --fail --silent "http://127.0.0.1:$api_port/readyz" >/dev/null; then return; fi
    kill -0 "$api_forward"; sleep 1
  done
  return 1
}
forward_api
python3 "$fixtures/check_api.py" fixture "$api_port" "$work"
"${k[@]}" exec -i recovery-source-postgres-1 -c postgres -- psql -U postgres -d constellation -v ON_ERROR_STOP=1 <"$work/registry-job.sql" >"$work/registry-job-seed.log"
python3 "$fixtures/check_api.py" source "$api_port" "$work"
sql recovery-source-postgres "INSERT INTO recovery_proof VALUES (2,'after-backup-via-wal');" >/dev/null
sql recovery-source-postgres 'SELECT clock_timestamp()' >"$work/target-time"
sql recovery-source-postgres "INSERT INTO recovery_proof VALUES (3,'after-pitr-target');" >/dev/null
# This MUST be a separate transaction, after the final insert commits.
wal="$(sql recovery-source-postgres 'SELECT pg_walfile_name(pg_current_wal_insert_lsn())')"
sql recovery-source-postgres 'SELECT pg_switch_wal()' >/dev/null
for ((n=0;n<120;n++)); do
  archived="$(sql recovery-source-postgres "SELECT coalesce(last_archived_wal >= '$wal',false) FROM pg_stat_archiver")"
  [[ "$archived" != t ]] || break
  sleep 2
done
[[ "$archived" == t ]]
python3 - "$work" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
v={'fullnameOverride':'recovery-target','postgres':{'cloudnativepg':{'scheduledBackup':{'enabled':False},'barmanCloud':{'recovery':{'enabled':True,'objectStoreName':'rustfs-archive','serverName':'recovery-source-postgres','targetTime':(p/'target-time').read_text().strip()}}}}}
(p/'target-values.json').write_text(json.dumps(v))
PY
helm template recovery-target "$chart" -n "$namespace" -f "$fixtures/source-values.yaml" -f "$work/target-values.json" \
  --show-only templates/postgres-secrets.yaml --show-only templates/postgres-cnpg-cluster.yaml >"$work/target.yaml"
"${k[@]}" apply -f "$work/target.yaml" >/dev/null
"${k[@]}" wait --for=condition=Ready cluster/recovery-target-postgres --timeout=600s
[[ "$(sql recovery-target-postgres 'SELECT string_agg(id::text,chr(44) ORDER BY id) FROM recovery_proof')" == 1,2 ]]
[[ "$(sql recovery-target-postgres "SELECT count(*) FROM pg_extension WHERE extname IN ('vector','pgcrypto','pg_trgm')")" == 3 ]]
threat_snapshot recovery-target-postgres >"$work/threat-restored.json"
cmp "$work/threat-source.json" "$work/threat-restored.json"
kill "$api_forward"; wait "$api_forward" 2>/dev/null || true; api_forward=""
sed 's/recovery-source-database-url/recovery-target-database-url/' "$work/api-source.yaml" >"$work/api-target.yaml"
"${k[@]}" apply -f "$work/api-target.yaml" >/dev/null
"${k[@]}" rollout status deployment/recovery-api --timeout=300s
forward_api
python3 "$fixtures/check_api.py" restored "$api_port" "$work"
# A pod restart is a local process/PVC recovery check, not node-loss or HA proof.
restart_started=$(date +%s)
"${k[@]}" delete pod recovery-target-postgres-1 --wait=true --timeout=600s >/dev/null
for ((n=0;n<120;n++)); do
  if "${k[@]}" get pod recovery-target-postgres-1 >/dev/null 2>&1; then break; fi
  sleep 1
done
"${k[@]}" wait --for=condition=Ready pod/recovery-target-postgres-1 --timeout=300s
for ((n=0;n<60;n++)); do
  if curl --max-time 5 --fail --silent "http://127.0.0.1:$api_port/readyz" >/dev/null; then break; fi
  sleep 1
done
python3 "$fixtures/check_api.py" restored "$api_port" "$work"
echo "Target pod restart and authenticated recovery: $(($(date +%s) - restart_started)) seconds" >"$work/restart-result.txt"
threat_snapshot recovery-target-postgres >"$work/threat-restarted.json"
cmp "$work/threat-source.json" "$work/threat-restarted.json"
cat "$work/restart-result.txt"
# The recovered DB alone must not decrypt integration secrets with a different KEK.
kill "$api_forward"; wait "$api_forward" 2>/dev/null || true; api_forward=""
sed 's/recovery-application-keys/recovery-wrong-keys/' "$work/api-target.yaml" >"$work/api-wrong-key.yaml"
"${k[@]}" apply -f "$work/api-wrong-key.yaml" >/dev/null
"${k[@]}" rollout status deployment/recovery-api --timeout=300s
forward_api
python3 "$fixtures/check_api.py" wrong-key "$api_port" "$work"
# Restore the retained key and prove decryption resumes after another restart.
kill "$api_forward"; wait "$api_forward" 2>/dev/null || true; api_forward=""
"${k[@]}" apply -f "$work/api-target.yaml" >/dev/null
"${k[@]}" rollout status deployment/recovery-api --timeout=300s
forward_api
python3 "$fixtures/check_api.py" restored "$api_port" "$work"
"${k[@]}" get backups,clusters -o wide >"$work/result.txt"
echo 'PASS: scheduled RustFS backup, WAL/PITR boundary, extensions, existing session, config, encrypted credentials, wrong-key rejection, audit chain and fresh login'
