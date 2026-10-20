# Migrations

Goose SQL migrations, applied in file order. **Forward-only** (ADR 0006):

- Every file carries a `-- +goose Up` section only. `-- +goose Down` sections were
  deleted on 2026-10-20; `goose down` is not a supported operation and
  `scripts/dev.sh migrate-down` refuses to run.
- To undo a schema change, write a new forward migration. Pre-production data can be
  dropped: recreate the database (`docker volume rm constellation-dev_pgdata` for the
  dev loop) instead of rolling back.
- Numbering is sequential (`NNN_slug.sql`). Take the next number; never renumber.
- `make migrate` applies pending migrations to `$DATABASE_URL`; `make test-integration`
  runs `goose up` against a disposable Postgres as the migration smoke test.
- The API refuses to start until the schema is at `internal/db.RequiredSchemaVersion`;
  bump that constant in the same commit as a new migration.

Phase 1 of the re-alignment moves the runner in-process (`//go:embed` + goose provider
with a Postgres session lock) and deletes the pre-install migrate Job.
