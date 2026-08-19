-- Network-map perf (Tier 2): a rolling pre-aggregate of network_flows.
--
-- /network/map and /network/conversations aggregate a full day of raw flow
-- rows (millions) with a GROUP BY on every page load — the dominant cost even
-- after the (org_id,cluster_id,at) index (114). NeuVector stays instant because
-- it renders from a continuously-maintained in-memory conversation graph, not a
-- query-time GROUP BY over raw observations.
--
-- network_flow_rollups is the durable equivalent: raw flows are folded into
-- per-hour buckets keyed by the same conversation tuple the map groups on, by an
-- incremental refresher (internal/handler/network/rollup.go) that advances a
-- watermark. Reads then aggregate ~(distinct conversations x hours) rows instead
-- of millions. Raw flows remain for drill-down / recent-flow lists.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS network_flow_rollups (
    org_id           uuid        NOT NULL,
    cluster_id       uuid        NOT NULL,
    src_workload     text        NOT NULL,
    dst_workload     text        NOT NULL,
    protocol         text        NOT NULL,
    l7_protocol      text        NOT NULL DEFAULT '',
    dst_port         int         NOT NULL DEFAULT 0,
    verdict          text        NOT NULL DEFAULT '',
    bucket           timestamptz NOT NULL,           -- date_trunc('hour', at)
    sum_bytes        bigint      NOT NULL DEFAULT 0,
    sum_packets      bigint      NOT NULL DEFAULT 0,
    flow_count       bigint      NOT NULL DEFAULT 0,
    max_at           timestamptz NOT NULL,
    min_src_addr     text        NOT NULL DEFAULT '',
    min_dst_addr     text        NOT NULL DEFAULT '',
    min_src_port     int         NOT NULL DEFAULT 0,
    has_dp           boolean     NOT NULL DEFAULT false,
    has_hubble       boolean     NOT NULL DEFAULT false,
    has_bpf          boolean     NOT NULL DEFAULT false,
    min_source       text        NOT NULL DEFAULT '',
    sum_client_bytes bigint      NOT NULL DEFAULT 0,
    sum_server_bytes bigint      NOT NULL DEFAULT 0,
    sum_sessions     bigint      NOT NULL DEFAULT 0,
    max_threat_id    int,
    max_severity     smallint,
    max_application  int,
    PRIMARY KEY (org_id, cluster_id, src_workload, dst_workload, protocol, l7_protocol, dst_port, verdict, bucket)
);
-- Read path filters (org_id, cluster_id, bucket-window); PK leads with the same
-- prefix but a dedicated bucket-ordered index keeps the window scan tight.
CREATE INDEX IF NOT EXISTS idx_flow_rollups_org_cluster_bucket
    ON network_flow_rollups (org_id, cluster_id, bucket DESC);

-- Singleton watermark: the max(at) already folded into the rollup.
CREATE TABLE IF NOT EXISTS network_flow_rollup_state (
    id        boolean     PRIMARY KEY DEFAULT true CHECK (id),
    watermark timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z'
);
INSERT INTO network_flow_rollup_state (id) VALUES (true) ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS network_flow_rollups;
DROP TABLE IF EXISTS network_flow_rollup_state;
-- +goose StatementEnd
