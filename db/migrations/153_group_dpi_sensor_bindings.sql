-- +goose Up
-- +goose StatementBegin
-- NET-42: allow user-authored WAF rules to live in runtime_dlp_rules alongside
-- DLP + signature rules. The agent's dlp_sync worker routes category='waf' rows
-- onto dp's WAF path (RESET) instead of the DLP path (DROP). Relax the CHECK
-- constraint 046 added (auto-named runtime_dlp_rules_category_check) to include
-- the new value; the default and every existing row stay 'dlp'.
ALTER TABLE runtime_dlp_rules
    DROP CONSTRAINT IF EXISTS runtime_dlp_rules_category_check;
ALTER TABLE runtime_dlp_rules
    ADD CONSTRAINT runtime_dlp_rules_category_check
        CHECK (category IN ('dlp', 'signature', 'waf'));

-- NET-43: bind a DLP or WAF sensor (rule set) to a GROUP, mirroring NeuVector's
-- per-group waf_group/dlp_group model. Today DPI opt-in is per-pod-label only
-- (dpi.constellation.alphabravo.io/waf|dlp); this adds an additional path so an
-- operator can attach a sensor to a group and have every current + future member
-- workload inherit it. Membership → member workloads → their MACs is resolved
-- server-side (see internal/handler/runtime/waf_dlp.go resolveSensorMACs); the
-- label opt-in keeps working unchanged.
--
-- sensor_id references dlp_sensors(id) when sensor_kind='dlp' and waf_groups(id)
-- when sensor_kind='waf' (026_waf_dlp.sql). It is not a hard FK because the two
-- referents differ by kind; the resolver validates the referent exists.
CREATE TABLE IF NOT EXISTS group_dpi_sensor_bindings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    group_id        UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    sensor_kind     TEXT NOT NULL CHECK (sensor_kind IN ('dlp', 'waf')),
    sensor_id       UUID NOT NULL,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, sensor_kind, sensor_id)
);

CREATE INDEX IF NOT EXISTS idx_group_dpi_bindings_org
    ON group_dpi_sensor_bindings(org_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS group_dpi_sensor_bindings;
ALTER TABLE runtime_dlp_rules
    DROP CONSTRAINT IF EXISTS runtime_dlp_rules_category_check;
ALTER TABLE runtime_dlp_rules
    ADD CONSTRAINT runtime_dlp_rules_category_check
        CHECK (category IN ('dlp', 'signature'));
-- +goose StatementEnd
