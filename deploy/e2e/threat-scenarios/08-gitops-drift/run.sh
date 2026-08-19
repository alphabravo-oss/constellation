#!/usr/bin/env bash
# Scenario 08: GitOps drift detection.
#
# Loads the declared and (intentionally drifted) live RoleBinding YAMLs into
# pkg/gitops.DetectDrift, captures the resulting DriftFinding JSON, then
# appends a gitops.drift.detected audit event tied to the (declared,observed)
# SHA pair.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
ROOT="$HERE/../../../.."
mkdir -p "$CAP"

echo "==> [1/2] run drift detector"
go run -C "$ROOT" -tags e2etools deploy/e2e/cluster-integration/drift_driver.go \
    deploy/e2e/gitops/declared-rolebinding.yaml \
    deploy/e2e/gitops/live-rolebinding.yaml \
    | tee "$CAP/drift-detection.json"

echo "==> [2/2] persist hash-chained audit event"
DATABASE_URL="postgres://constellation:constellation@localhost:5433/constellation?sslmode=disable" \
go run -tags e2etools "$HERE/audit-driver" 2>&1 | tee "$CAP/audit-event.txt"

echo "==> done."
