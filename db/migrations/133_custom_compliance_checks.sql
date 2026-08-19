-- +goose Up
-- +goose StatementBegin
-- P0-03: user-supplied custom compliance checks. Parity with NeuVector's per-group custom
-- check scripts (neuvector/controller/rest/bench.go handlerCustomCheckConfig). Each row is a
-- CEL expression evaluated by the k8s-compliance collector over a collected Kubernetes object
-- of target_kind; the result is persisted into compliance_checks under the "Custom" framework.
CREATE TABLE IF NOT EXISTS custom_compliance_checks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'medium',
    target_kind TEXT NOT NULL,                     -- Namespace|ClusterRole|Deployment|StatefulSet|DaemonSet
    expression  TEXT NOT NULL,                     -- CEL bool expression; true = compliant
    remediation TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_custom_compliance_checks_org ON custom_compliance_checks(org_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS custom_compliance_checks;
-- +goose StatementEnd
