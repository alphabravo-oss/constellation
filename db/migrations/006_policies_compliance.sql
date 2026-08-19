-- +goose Up
-- +goose StatementBegin
CREATE TABLE policies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID REFERENCES clusters(id) ON DELETE CASCADE,
    project_id    UUID REFERENCES projects(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    description   TEXT,
    engine        TEXT NOT NULL,                  -- "kyverno" | "opa-rego" | "k8s-cel" | "internal-waf" | "internal-dlp" | "internal-license"
    category      TEXT NOT NULL,                  -- "admission" | "runtime-waf" | "runtime-dlp" | "license" | "iac" | "signature-verification"
    spec_yaml     TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    mode          TEXT NOT NULL DEFAULT 'monitor', -- "learn" | "monitor" | "enforce"
    version       INTEGER NOT NULL DEFAULT 1,
    embedding     vector(1536),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name, version)
);

CREATE INDEX idx_policies_category ON policies(org_id, category, enabled);

CREATE TABLE policy_decisions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID REFERENCES clusters(id) ON DELETE CASCADE,
    policy_id     UUID REFERENCES policies(id) ON DELETE SET NULL,
    subject_kind  TEXT NOT NULL,                  -- "admission" | "finding" | "runtime-event"
    subject_id    TEXT NOT NULL,
    verdict       TEXT NOT NULL,                  -- "allow" | "deny" | "warn"
    reason        TEXT,
    at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_decisions_org_at ON policy_decisions(org_id, at DESC);

CREATE TABLE compliance_checks (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id     UUID REFERENCES clusters(id) ON DELETE CASCADE,
    asset_id       UUID REFERENCES assets(id) ON DELETE CASCADE,
    framework      TEXT NOT NULL,                 -- "cis-k8s-1.9" | "nist-800-53-rev5" | "pci-dss-4.0" | ...
    control_id     TEXT NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT,
    status         TEXT NOT NULL,                 -- "pass" | "fail" | "manual" | "not_applicable"
    severity       TEXT NOT NULL,
    evidence       TEXT,
    evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_framework ON compliance_checks(org_id, framework, status);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS compliance_checks;
DROP TABLE IF EXISTS policy_decisions;
DROP TABLE IF EXISTS policies;
-- +goose StatementEnd
