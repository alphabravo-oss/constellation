-- +goose Up
-- +goose StatementBegin
-- Runtime events. Partitioned monthly because they're high-volume (eBPF + L7 DPI + WAF/DLP/Falco).
CREATE TABLE events (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL,
    cluster_id    UUID NOT NULL,
    node_id       TEXT NOT NULL,
    workload_id   TEXT NOT NULL,
    container_id  TEXT,
    source        TEXT NOT NULL,        -- "ebpf" | "l7-dpi" | "waf" | "dlp" | "falco"
    kind          TEXT NOT NULL,
    severity      TEXT NOT NULL,
    verdict       TEXT NOT NULL,        -- "observed" | "alert" | "block" | "quarantine"
    attack_techniques TEXT[] NOT NULL DEFAULT '{}',
    payload       JSONB NOT NULL DEFAULT '{}'::jsonb,  -- PII redacted at write time
    at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, at)
) PARTITION BY RANGE (at);

CREATE TABLE events_p_default PARTITION OF events DEFAULT;

CREATE INDEX idx_events_workload ON events(org_id, workload_id, at DESC);
CREATE INDEX idx_events_severity ON events(org_id, severity, at DESC);
CREATE INDEX idx_events_attack   ON events USING GIN (attack_techniques);

-- Network flows for the Traffic Map + auto-policy generation.
CREATE TABLE network_flows (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL,
    cluster_id    UUID NOT NULL,
    src_workload  TEXT NOT NULL,
    dst_workload  TEXT NOT NULL,
    src_addr      TEXT,
    dst_addr      TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      TEXT NOT NULL,        -- "tcp" | "udp" | "icmp"
    l7_protocol   TEXT,                  -- "http" | "grpc" | "dns" | "mysql" | "postgres" | "kafka" | "redis"
    bytes         BIGINT NOT NULL DEFAULT 0,
    packets       BIGINT NOT NULL DEFAULT 0,
    verdict       TEXT NOT NULL DEFAULT 'allow',
    at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, at)
) PARTITION BY RANGE (at);

CREATE TABLE network_flows_p_default PARTITION OF network_flows DEFAULT;

CREATE INDEX idx_flows_src ON network_flows(org_id, src_workload, at DESC);
CREATE INDEX idx_flows_dst ON network_flows(org_id, dst_workload, at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS network_flows CASCADE;
DROP TABLE IF EXISTS events CASCADE;
-- +goose StatementEnd
