#!/usr/bin/env bash
# Scenario 05: WAF blocks SQL injection.
#
# Drives the in-process WAF engine (internal/runtime/waf) with a synthetic
# L7Event modelling an attacker probing /api/v1/orders with the classic
# ?id=1 OR 1=1-- payload (and a sqlmap User-Agent). Asserts rule 942110 fires
# with severity=critical and verdict=block, then appends a hash-chained
# runtime.alert.waf audit event to the live DB.
#
# This is path (b) from the H3 brief — we drive the engine directly rather
# than attach NFQUEUE on a node. The driver is provider-agnostic; the same
# Verdict shape is emitted by the cluster runtime-agent when NFQUEUE is wired.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
mkdir -p "$CAP"

if [ ! -x /tmp/scenario-driver ]; then
  (cd "$HERE/../../../.." && go build -tags e2etools -o /tmp/scenario-driver \
      ./deploy/e2e/threat-scenarios/waf-driver)
fi

/tmp/scenario-driver waf-sqli --out "$CAP"
echo "==> Evidence in $CAP/."
