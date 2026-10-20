---
status: "accepted"
date: 2026-10-20
deciders: ["AlphaBravoCompany"]
title: "Forward-only database migrations"
tags: [data]
---

# Forward-only database migrations

## Context

The repository carried 184 goose migrations with `Down` sections that were never
exercised: `goose down-to 0` failed at migration 167 (re-adding a unique constraint over
duplicated rows), and no CI job ran the down path. Pre-production data can be dropped;
no customer database exists.

## Decision Drivers

- Guide ch.08 §7: no backward-compatibility burden before production.
- A migration path that is tested is the only one that is supported.

## Considered Options

- Fix and test the down path for all 184 migrations.
- Forward-only: delete `Down` sections; undo by writing a new forward migration.

## Decision Outcome

Chosen option: "forward-only", because the down path had no consumer and no test, and
maintaining it costs every schema change. `scripts/dev.sh migrate-down` refuses to run and
points at recreating the dev database. `make test-integration` runs `goose up` against a
disposable Postgres as the migration smoke test. Phase 1 embeds the runner in the API
binary with a Postgres session lock.

### Positive Consequences

- Half the migration code is gone; no untested path can bit-rot.

### Negative Consequences

- Rolling back a bad migration in production (when there is one) requires a forward fix
  or a restore from backup; the backup/PITR runbook must be in place before GA.

## Links

- `db/migrations/README.md`.
