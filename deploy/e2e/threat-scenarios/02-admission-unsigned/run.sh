#!/usr/bin/env bash
# Scenario 02: admission denial on missing image signature.
#
# Drives the scenario via the threat-scenario harness so the rule is run in
# enforce mode (the deployed default catalogue ships the require-image-signature
# rule in monitor mode — flipping it to enforce is a runtime configuration
# change the production engine supports via `engine.Rules[i].Mode = "enforce"`).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
mkdir -p "$CAP"

# Build the driver if not present.
if [ ! -x /tmp/scenario-driver ]; then
  (cd "$HERE/../../../.." && go build -tags e2etools -o /tmp/scenario-driver \
      ./deploy/e2e/threat-scenarios/waf-driver)
fi

/tmp/scenario-driver admission --out "$CAP"

echo "==> /api/v1/violations (recent)"
TOKEN="${TOKEN:-$(cat /tmp/h3-token)}"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:18080/api/v1/violations?limit=5" \
  | python3 -m json.tool > "$CAP/violations-api.json"

echo "==> policy_decisions DB row"
PGPASSWORD=constellation psql -h localhost -p 5433 -U constellation -d constellation \
  -c "SELECT id, subject_kind, subject_id, verdict, reason, at
        FROM policy_decisions
       WHERE subject_id = 'default/evil-unsigned'
       ORDER BY at DESC LIMIT 5;" > "$CAP/policy-decisions-db.txt"
cat "$CAP/policy-decisions-db.txt"

echo "==> done. Evidence in $CAP/."
