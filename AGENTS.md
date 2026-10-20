# AGENTS.md

Derived from [`CLAUDE.md`](CLAUDE.md), which is the source of truth for engineering
discipline in this repository. Summary for agent runners:

- Read `CLAUDE.md` first; follow the seven principles and the dev-loop table.
- `make check` must be green before a change is proposed; `make test-integration` for
  anything touching SQL or migrations; `make helm-lint helm-template-smoke` for the chart.
- Never add hand-written SQL to `internal/handler`; new domains go under
  `internal/<domain>/{handler,service,store}` (ADR 0002).
- Never add a `:latest` image, a `Down` migration, a compose/systemd deployment path, or a
  new language without an ADR in `docs/decisions/`.
- Use Conventional Commits; one logical change per commit.
