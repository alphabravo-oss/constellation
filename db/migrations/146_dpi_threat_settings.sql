-- Per-cluster DPI signature toggles. Currently just the weak-TLS version detections
-- (SSLv3/TLS1.0/1.1), which are off by default (noisy false positives in tap mode) and can
-- be turned on from the console when genuine legacy-TLS detection is wanted. The runtime-agent
-- reads this on its session-snapshot upload and applies it live via dp ctrl_set_threat.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS dpi_threat_settings (
    org_id           UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id       UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    weak_tls_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dpi_threat_settings;
-- +goose StatementEnd
