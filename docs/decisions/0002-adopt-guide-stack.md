---
status: "accepted"
date: 2026-10-20
deciders: ["AlphaBravoCompany"]
title: "Adopt the Technology Selection Guide stack; supersedes ADR 0001"
tags: [architecture, frontend, data, rpc, logging]
---

# Adopt the Technology Selection Guide stack; supersedes ADR 0001

## Context

ADR 0001 (2026-10-12) chose TanStack Router + TanStack Form and a hand-written REST/axios
client to match the Astronomer console. The owner has since directed every AlphaBravo
product at the Technology Selection Guide (snapshot 2026-05-08), whose MUSTs for this
codebase are: domain packages with `handler → service → store` layering (ch.01),
`sqlc`-generated queries with no hand-written SQL in handlers (ch.02), Connect-RPC
services on chi with generated Connect-Web clients (ch.03/10), zerolog structured
logging (ch.05), react-hook-form + Zod forms (ch.10).

The 2026-10-20 gap analysis measured the distance: 90,989 LOC in `internal/handler`
with 1,311 inline SQL call sites and 443 REST paths; `log/slog` in 162 files; no proto,
no sqlc. Phase 0 (this re-alignment series) is mechanical; this ADR records the
direction the bounded (Phase 1) and architectural (Phase 2) work follows.

## Decision Drivers

- One stack across AlphaBravo products so engineers and agents move between repos.
- Greenfield rules (ch.08 §7): no backward-compatibility shims; delete and rewrite.
- Every phase must land with an end-to-end proof, not a big-bang rewrite.
- Astronomer (the product family's console) already uses TanStack Router.

## Considered Options

- Keep ADR 0001 (REST + axios + TanStack everything) and record the guide as nonconformant.
- Adopt the guide literally, including react-router v8 Data Mode.
- Adopt the guide stack domain-by-domain, keeping TanStack Router as the recorded
  routing alternative for product-family consistency.

## Decision Outcome

Chosen option: "adopt domain-by-domain, keep TanStack Router", because it closes the
guide's MUSTs on the backend (layers, sqlc, Connect-RPC, zerolog) and the form/validation
stack on the frontend while not re-platforming 212 pages away from the router the sibling
product uses. The guide explicitly allows TanStack Router v1 as the alternative when an
ADR records it (ch.10 §routing); this ADR is that record.

Concretely:

1. **Phase 1 (bounded)**: embedded goose runner with a session lock; testcontainers +
   pgtestdb fixtures; composite `otelpgx` + metrics tracer on the pool; zerolog through
   an `internal/logging` wrapper with an `slog.Handler` bridge so untouched files keep
   compiling; `internal/api/apiutil` (sentinel errors, `WriteError`, cursor pagination,
   `routePolicy` table); `age` column encryption via `internal/crypto`; react-hook-form +
   `zodResolver` for every form.
2. **Phase 2 (architectural)**: for each domain, extract `internal/<domain>/{handler,
   service,store}` with `queries.sql` → sqlc, define `proto/constellation/v1/<domain>.proto`,
   mount the generated Connect handler on the same chi router under `/rpc/`, switch the
   frontend consumer to the generated Connect-Web client, then delete the REST routes for
   that domain. Order: auth/rbac → clusters/assets → findings → scanning → policy/admission
   → runtime/network → compliance/backup/federation. Machine ingest paths convert last and
   may use Connect streaming.
3. **Routing**: TanStack Router stays. `App.tsx` owns provider composition; loaders handle
   auth redirects centrally. react-router is not adopted.
4. **Lint**: `internal/handler` and `internal/server` are held at the golangci STANDARD
   preset until each domain is extracted (`.golangci.yml` exclusion rules); complexity
   linters apply to every new or extracted package at the golden thresholds.

### Positive Consequences

- Each domain ships with its own e2e proof (Playwright + integration + k3s).
- The REST surface shrinks monotonically; no parallel long-lived API.
- Product-family UX consistency (routing, navigation) is preserved.

### Negative Consequences

- During Phase 2 the repo carries REST and Connect side by side.
- TanStack Router remains a recorded deviation from the guide's canonical router.

## Consequences

New backend code MUST follow the layered layout and MUST NOT add hand-written SQL to
handlers. New frontend forms MUST use react-hook-form + Zod. The owner reviews this ADR
at the end of each Phase 2 domain cut.

## Pros and Cons of the Options

### Keep ADR 0001

- Good, because zero migration cost.
- Bad, because every guide MUST on data/surface/logging stays open.

### Adopt the guide literally (react-router v8)

- Good, because full conformance.
- Bad, because a 212-page router migration with no product benefit and a split from Astronomer.

### Adopt domain-by-domain, keep TanStack Router (chosen)

- Good, because backend conformance lands incrementally with proofs.
- Good, because the guide's explicit routing alternative is honoured with an ADR.
- Bad, because REST and Connect coexist for the duration of Phase 2.

## Links

- Supersedes `0001-astronomer-console-stack.md`.
- Guide chapters 01, 02, 03, 05, 08, 10.
