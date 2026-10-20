-- +goose Up
CREATE TABLE cluster_inventory_presence (
 org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
 observed_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 pods jsonb NOT NULL CHECK(jsonb_typeof(pods)='object'),
 image_digests jsonb NOT NULL CHECK(jsonb_typeof(image_digests)='object'),
 PRIMARY KEY(org_id,cluster_id),
 CHECK(expires_at>observed_at)
);
-- Findings remain immutable evidence of an observation. Presence is a separate
-- classification, never a claim that a retired asset's vulnerability was fixed.
