-- Store the full generated Kubernetes policy artifact bundle for lifecycle
-- approvals, applies, and rollback refs. `preview_yaml` remains the legacy
-- default Cilium manifest for old clients.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE network_policy_rollback_refs
    ADD COLUMN IF NOT EXISTS preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE network_policy_lifecycle_states
   SET preview_manifests = jsonb_build_object('cilium', preview_yaml)
 WHERE preview_yaml <> ''
   AND preview_manifests = '{}'::jsonb;

UPDATE network_policy_lifecycle_actions
   SET preview_manifests = jsonb_build_object('cilium', preview_yaml)
 WHERE preview_yaml <> ''
   AND preview_manifests = '{}'::jsonb;

UPDATE network_policy_rollback_refs
   SET preview_manifests = jsonb_build_object('cilium', preview_yaml)
 WHERE preview_yaml <> ''
   AND preview_manifests = '{}'::jsonb;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE network_policy_rollback_refs
    DROP COLUMN IF EXISTS preview_manifests;

ALTER TABLE network_policy_lifecycle_actions
    DROP COLUMN IF EXISTS preview_manifests;

ALTER TABLE network_policy_lifecycle_states
    DROP COLUMN IF EXISTS preview_manifests;
-- +goose StatementEnd
