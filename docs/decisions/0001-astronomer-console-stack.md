# ADR 0001: Astronomer-aligned console stack

Recorded: 2026-10-12. Status: accepted product direction; implementation remains
subject to the parity acceptance gates. Approval source: the user's explicit
instruction, “Converge on Astronomer’s stack, including Router and Form,” followed
by approval to implement the plan. Accountable review roles: frontend/API
maintainers. Next review: 2027-01-12, or earlier for a security advisory, major
upgrade or changed product requirements.

The reference checkout is Astronomer commit `3b378ef1`, as recorded in the
[canonical parity plan](../NEUVECTOR-PARITY-PLAN.md). Its stack guides shared
patterns and contracts; copying unrelated services or dependency versions is
not an acceptance criterion.

Use TanStack Router as the single console router, TanStack Query for remote
state, and the shared TanStack Form layer with Zod validation. Retain React,
Vite, Tailwind v4, Radix primitives and TanStack Table. Generate REST/OpenAPI
contracts and introduce sqlc domain accessors through the approved incremental
plan. Adding react-router, react-hook-form or a second competing form stack
requires revisiting this decision.

This explicitly departs from the Technology Selection Guide's canonical
React Router/react-hook-form/Connect examples. It does not establish literal
conformance to those requirements. The guide allows TanStack Router with an ADR;
that alternative now applies. Generated REST contracts and sqlc remain work in
progress, and this decision does not treat hand-written DTOs/SQL as generated.

The rationale is consistency with the selected reference product, one owner for
routing and one shared form API, and preservation of the existing REST/CLI/agent
surface during incremental migration. Risks include route/search typing gaps,
form behavior changes, stale saves and incomplete client-contract coverage.
Controls are shared field/submit components, schema validation, server-enforced
configuration revision preconditions, secret-safe error handling, unsaved-edit
protection, and component plus production-serving browser tests. New tables must
have matching server pagination/count/export semantics; a TanStack dependency
alone does not provide that behavior.

Current evidence: Router owns all route consumers and React Router is removed.
Data Retention and NVD configuration use the shared Form/Zod layer. The local
production browser suite passed 193 tests before the subsequent conditional-edit
addition, and hosted run 38190053858 passed the browser and FIPS jobs. The updated
forms pass 143 component/unit tests; exact subsequent browser evidence belongs
in the canonical plan. Remaining editors, generated route/search/API contracts,
full table behaviors and deployed acceptance remain open.

For security guidance that differs across chapters, use the stronger rule:
browser access/refresh tokens are not persisted in localStorage. Browser sessions
use HttpOnly cookies and CSRF defenses; automation retains the documented bearer
contract. This ADR does not approve unrelated departures in bearer precedence,
cryptographic custody, logging/telemetry, native/privileged images, architecture
support or migration orchestration. Track those individually in the
[control matrix](../technology-guide-control-matrix.md).

Version tables in the guide are dated evidence, not an instruction to downgrade
or adopt a predicted release. Review the checked-in runtime pins and lockfiles,
upstream support/security notices and actual build/browser/migration results at
the next review. Retain the repository's current Helm contract until a separately
qualified upgrade proves template, install, upgrade and recovery compatibility.
