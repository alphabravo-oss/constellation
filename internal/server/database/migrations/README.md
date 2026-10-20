# Migrations

Goose SQL migrations, applied in file order. **Forward-only** (ADR 0006):

- Every file carries a `-- +goose Up` section only. `-- +goose Down` sections were
  deleted on 2026-10-20; `goose down` is not a supported operation and
  `scripts/dev.sh migrate-down` refuses to run.
- To undo a schema change, write a new forward migration. Pre-production data can be
  dropped: recreate the database (`docker volume rm constellation-dev_pgdata` for the
  dev loop) instead of rolling back.
- Numbering is sequential (`NNN_slug.sql`). Take the next number; never renumber.
- The set is embedded (`//go:embed`) by `internal/server/database`, which runs it with the
  goose provider under a PostgreSQL session advisory lock. `constellation-api` applies
  pending migrations on every boot before it listens; replicas serialise on the lock.
  `make migrate` (`constellation-api --migrate-only`) applies them without starting the API.
- `internal/testutil/pgtest` feeds the same runner to pgtestdb, so integration tests run on
  exactly the production schema path.
- Bump `internal/db.RequiredSchemaVersion` in the same commit as a new migration
  (`TestLatestVersionMatchesRequiredSchema` enforces it).
