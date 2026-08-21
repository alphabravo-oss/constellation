-- RT-MATCH-16: full-path + hash + parent matching for process baselines.
--
-- Process matching was basename-only, so a renamed/relocated binary running under
-- an allowed name (e.g. `cp /tmp/evil /bin/nginx` or `/tmp/nginx`) bypassed the
-- baseline. NeuVector's CLUSProcessProfileEntry keys on full path + optional sha256
-- + parent name; the agent-side rich matcher (processProfileEntry) already supports
-- this, but the authored per-process rule table (process_profile_rules, mig 139)
-- could only key on name+path. This adds the two missing key columns so authored
-- allow/deny rules — and the bundle shipped to the agent enforcer — can pin a
-- process to a content hash and/or a parent process, not just its basename.
--
-- `path` already exists (mig 139); only `sha256` and `parent_name` are added.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE process_profile_rules
    ADD COLUMN IF NOT EXISTS sha256      TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS parent_name TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE process_profile_rules
    DROP COLUMN IF EXISTS parent_name,
    DROP COLUMN IF EXISTS sha256;
-- +goose StatementEnd
