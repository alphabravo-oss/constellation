-- +goose Up
-- +goose StatementBegin
-- G3a race fix: recordFedRevision assigns revision = max(existing)+1, which two
-- concurrent master mutations can compute identically, silently collapsing two
-- distinct rule changes onto one revision (a joint would replicate only one).
-- A UNIQUE(org_id, revision) constraint makes the colliding INSERT fail so the
-- handler can retry with a freshly recomputed revision.
--
-- Pre-dedup (mirrors migration 061): a deployment that already hit the very race
-- this migration fixes will hold duplicate (org_id, revision) rows, and ADD
-- CONSTRAINT would then fail and block the deploy. Each duplicate is a distinct
-- rule change that must be preserved (not deleted), so renumber the colliding
-- rows instead: keep the earliest write at its original revision and reassign
-- the later collisions to fresh revisions above the org's current max — exactly
-- the freshly-recomputed-revision outcome the handler retry now produces at
-- write time. This is idempotent: on already-clean data no row has rn>1 so the
-- UPDATE is a no-op, and the new revisions (> max) can never collide with the
-- kept ones (<= max) nor with each other (seq is unique per org).
WITH maxrev AS (
    SELECT org_id, MAX(revision) AS max_rev
      FROM fed_rule_revisions
     GROUP BY org_id
),
ranked AS (
    SELECT id, org_id,
           row_number() OVER (
               PARTITION BY org_id, revision
               ORDER BY updated_at ASC, id ASC
           ) AS rn
      FROM fed_rule_revisions
),
renumber AS (
    SELECT id, org_id,
           row_number() OVER (PARTITION BY org_id ORDER BY id) AS seq
      FROM ranked
     WHERE rn > 1
)
UPDATE fed_rule_revisions f
   SET revision = m.max_rev + r.seq
  FROM renumber r
  JOIN maxrev m ON m.org_id = r.org_id
 WHERE f.id = r.id;

ALTER TABLE fed_rule_revisions
    ADD CONSTRAINT fed_rule_revisions_org_revision_key UNIQUE (org_id, revision);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE fed_rule_revisions
    DROP CONSTRAINT IF EXISTS fed_rule_revisions_org_revision_key;
-- +goose StatementEnd
