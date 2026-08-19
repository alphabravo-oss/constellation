-- +goose Up
-- +goose StatementBegin
-- Deployments table — StackRox-parity. We persist per-deployment risk + findings counts
-- so the risk-ranked dashboard renders in one query instead of joining findings on every
-- page load. The risk-prioritized deployment view is StackRox's marquee feature.
CREATE TABLE IF NOT EXISTS deployments (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id       UUID REFERENCES clusters(id) ON DELETE CASCADE,
    namespace        TEXT NOT NULL,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL, -- Deployment | StatefulSet | DaemonSet | Job | CronJob
    labels           JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_score       INT  NOT NULL DEFAULT 0,
    risk_factors     JSONB NOT NULL DEFAULT '{}'::jsonb, -- {"cvss":35,"epss":12,"kev":20,"privileged":15,"net_exposure":10}
    finding_count    INT  NOT NULL DEFAULT 0,
    critical_count   INT  NOT NULL DEFAULT 0,
    high_count       INT  NOT NULL DEFAULT 0,
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, namespace, name, kind)
);

CREATE INDEX IF NOT EXISTS idx_deployments_org_risk ON deployments(org_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_deployments_org_cluster_ns ON deployments(org_id, cluster_id, namespace);

-- Violation events: append-only per-deployment timeline. Distinct from `events` (the
-- runtime telemetry table) because violations are policy + finding lifecycle events the
-- UI renders as a per-deployment timeline.
CREATE TABLE IF NOT EXISTS violations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    deployment_id   UUID REFERENCES deployments(id) ON DELETE CASCADE,
    policy_name     TEXT,
    finding_id      UUID,
    severity        TEXT NOT NULL,
    kind            TEXT NOT NULL, -- admission | finding | drift | runtime
    message         TEXT,
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_violations_org_at        ON violations(org_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_violations_deployment_at ON violations(deployment_id, at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS violations;
DROP TABLE IF EXISTS deployments;
-- +goose StatementEnd
