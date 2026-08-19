-- +goose Up
-- +goose StatementBegin
-- Audit log: append-only, hash-chained. Triggers below prevent UPDATE / DELETE outside controlled archival.
CREATE TABLE audit_events (
    id            BIGSERIAL PRIMARY KEY,
    org_id        UUID,                                   -- nullable for system-level events
    actor_id      UUID,
    actor_ip      INET,
    action        TEXT NOT NULL,                          -- e.g., "finding.suppress", "policy.update"
    target_kind   TEXT,
    target_id     TEXT,
    before        JSONB,
    after         JSONB,
    prev_hash     TEXT NOT NULL,                          -- hex sha256 of previous row
    chain_hash    TEXT NOT NULL UNIQUE,                   -- hex sha256 of this row
    request_id    TEXT,
    at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_org_at ON audit_events(org_id, at DESC);
CREATE INDEX idx_audit_action ON audit_events(action, at DESC);

-- Tamper-evidence: forbid UPDATE / DELETE on audit_events.
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_events_no_modify() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only; UPDATE/DELETE forbidden';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_no_modify();
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_no_modify();
-- +goose StatementEnd

-- +goose StatementBegin
-- CVE records ingested by constellation-vulndb pipeline.
CREATE TABLE cve_records (
    cve_id           TEXT PRIMARY KEY,                    -- CVE-YYYY-NNNN, GHSA-..., OSV-...
    title            TEXT,
    description      TEXT,
    cvss_base        DOUBLE PRECISION,
    cvss_vector      TEXT,
    kev_listed       BOOLEAN NOT NULL DEFAULT FALSE,
    kev_added        TIMESTAMPTZ,
    epss_probability DOUBLE PRECISION,
    epss_updated_at  TIMESTAMPTZ,
    aliases          TEXT[] NOT NULL DEFAULT '{}',
    affected         JSONB NOT NULL DEFAULT '[]'::jsonb,
    "references"     TEXT[] NOT NULL DEFAULT '{}',
    sources          TEXT[] NOT NULL DEFAULT '{}',
    reachability_hint JSONB NOT NULL DEFAULT '{}'::jsonb,
    embedding        vector(1536),
    published_at     TIMESTAMPTZ,
    modified_at      TIMESTAMPTZ
);

CREATE INDEX idx_cve_kev   ON cve_records(kev_listed) WHERE kev_listed = TRUE;
CREATE INDEX idx_cve_epss  ON cve_records(epss_probability DESC) WHERE epss_probability IS NOT NULL;
CREATE INDEX idx_cve_id_trgm ON cve_records USING GIN (cve_id gin_trgm_ops);
CREATE INDEX idx_cve_aliases ON cve_records USING GIN (aliases);
CREATE INDEX idx_cve_affected ON cve_records USING GIN (affected jsonb_path_ops);

-- Bundle metadata recorded by `vulndb-importer` so the UI can show "last refreshed".
CREATE TABLE cve_bundles (
    id             BIGSERIAL PRIMARY KEY,
    version        TEXT NOT NULL UNIQUE,
    oci_ref        TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    record_count   BIGINT NOT NULL,
    signed         BOOLEAN NOT NULL DEFAULT FALSE,
    signer_identity TEXT,
    imported_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at   TIMESTAMPTZ
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cve_bundles;
DROP TABLE IF EXISTS cve_records;
DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
DROP FUNCTION IF EXISTS audit_events_no_modify();
DROP TABLE IF EXISTS audit_events;
-- +goose StatementEnd
