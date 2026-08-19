#!/usr/bin/env bash
# Scenario 10: end-to-end audit chain integrity (clean → tamper → broken → restore).
#
# Uses a stand-alone verifier (./verify-driver) that calls pkg/audit.VerifyChain
# directly so we don't need to bounce the running API process. The DB triggers
# audit_events_no_{update,delete} are disabled while we manually corrupt one
# row, then re-enabled and the row restored at the end.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
mkdir -p "$CAP"

if [ ! -x /tmp/audit-verifier ]; then
  (cd "$HERE/../../../.." && go build -tags e2etools -o /tmp/audit-verifier \
       ./deploy/e2e/threat-scenarios/10-audit-chain/verify-driver)
fi

export DATABASE_URL="postgres://constellation:constellation@localhost:5433/constellation?sslmode=disable"
export PGPASSWORD=constellation
PSQL=(psql -h localhost -p 5433 -U constellation -d constellation -tA)
PSQLV=(psql -h localhost -p 5433 -U constellation -d constellation)

echo "==> [1/5] clean verify"
/tmp/audit-verifier | tee "$CAP/audit-verify-clean.json"

echo "==> [2/5] H3 events by action"
"${PSQLV[@]}" -c "SELECT action, COUNT(*) FROM audit_events GROUP BY action ORDER BY action;" \
  | tee "$CAP/events-by-action.txt"

echo "==> [3/5] choose a row to tamper"
TARGET_ID=$("${PSQL[@]}" -c "SELECT id FROM audit_events WHERE action='gitops.drift.detected' ORDER BY id LIMIT 1;")
ORIG=$("${PSQL[@]}" -c "SELECT after::text FROM audit_events WHERE id = $TARGET_ID;")
echo "target_id=$TARGET_ID"
printf '%s\n' "$ORIG" > "$CAP/original-after.txt"

echo "==> [4/5] tamper: disable trigger, set after=NULL, re-verify"
"${PSQLV[@]}" -c "ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update;"
"${PSQLV[@]}" -c "UPDATE audit_events SET after = NULL WHERE id = $TARGET_ID;"
( /tmp/audit-verifier || true ) | tee "$CAP/audit-verify-broken.json"

echo "==> [5/5] restore + re-verify"
# Use a server-side parameter so we don't have to fight psql's quote escaping.
"${PSQLV[@]}" <<SQL
ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update;
UPDATE audit_events SET after = \$\$$ORIG\$\$::jsonb WHERE id = $TARGET_ID;
ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update;
SQL
/tmp/audit-verifier | tee "$CAP/audit-verify-restored.json"

echo "==> done. Evidence in $CAP/."
