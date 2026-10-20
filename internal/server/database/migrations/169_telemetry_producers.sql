-- +goose Up
-- One cursor per persistent producer/stream, not one receipt per event. Keep
-- cursors for the cluster lifetime: expiring them would allow old replay.
CREATE TABLE telemetry_producers (
    org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    stream text NOT NULL CHECK (stream IN ('events', 'flows')),
    producer_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    payload_hash bytea NOT NULL,
    response jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, cluster_id, stream, producer_id)
);
CREATE INDEX telemetry_producers_cluster ON telemetry_producers(cluster_id);
