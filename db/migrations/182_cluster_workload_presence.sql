-- +goose Up
CREATE TABLE cluster_workload_presence (
 org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
 observed_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 workloads jsonb NOT NULL CHECK(jsonb_typeof(workloads)='object'),
 PRIMARY KEY(org_id,cluster_id),
 CHECK(expires_at>observed_at)
);
-- Controller presence is separate from pod presence: a zero-replica controller
-- still exists. Missing/stale snapshots cannot establish workload absence.
-- +goose Down
DROP TABLE cluster_workload_presence;
