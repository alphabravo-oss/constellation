-- +goose Up
-- Stash the container image refs each deployment uses so the discoverer's risk
-- rollup can match them to the corresponding image-asset findings emitted by
-- the scanner. Without this, deployment.risk_score is always zero because
-- findings live on assets of kind='image' (one per image-ref) while
-- deployments only had a paired asset of kind='deployment'.
ALTER TABLE deployments ADD COLUMN image_refs TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX idx_deployments_image_refs ON deployments USING GIN (image_refs);

-- +goose Down
DROP INDEX IF EXISTS idx_deployments_image_refs;
ALTER TABLE deployments DROP COLUMN IF EXISTS image_refs;
