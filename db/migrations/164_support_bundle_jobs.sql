-- +goose Up
-- +goose StatementBegin
CREATE TABLE support_bundle_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'ready', 'failed', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    bundle_id UUID,
    error TEXT,
    payload JSONB,
    audit_event_id BIGINT,
    audit_pending TEXT CHECK (audit_pending IN ('ready', 'failed')),
    CONSTRAINT support_bundle_jobs_ready_payload CHECK (status <> 'ready' OR (payload IS NOT NULL AND bundle_id IS NOT NULL AND expires_at IS NOT NULL)),
    CONSTRAINT support_bundle_jobs_expired_payload CHECK (status <> 'expired' OR payload IS NULL)
);
CREATE INDEX support_bundle_jobs_claim_idx ON support_bundle_jobs (created_at, id)
    WHERE status IN ('queued', 'running');
CREATE INDEX support_bundle_jobs_org_list_idx ON support_bundle_jobs (org_id, created_at DESC, id DESC);
CREATE INDEX support_bundle_jobs_expiry_idx ON support_bundle_jobs (expires_at)
    WHERE status IN ('ready', 'failed');
CREATE INDEX support_bundle_jobs_audit_pending_idx ON support_bundle_jobs (created_at, id)
    WHERE audit_pending IS NOT NULL;
CREATE INDEX support_bundle_job_audit_idx ON audit_events (org_id, target_id, id DESC)
    WHERE target_kind = 'support_bundle_job';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX support_bundle_job_audit_idx;
DROP TABLE support_bundle_jobs;
-- +goose StatementEnd
