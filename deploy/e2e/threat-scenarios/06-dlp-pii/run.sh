#!/usr/bin/env bash
# Scenario 06: DLP catches PII exfil (Luhn-valid credit-card number).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
mkdir -p "$CAP"

if [ ! -x /tmp/scenario-driver ]; then
  (cd "$HERE/../../../.." && go build -tags e2etools -o /tmp/scenario-driver \
      ./deploy/e2e/threat-scenarios/waf-driver)
fi

/tmp/scenario-driver dlp-pii --out "$CAP"
echo "==> Evidence in $CAP/."
