---
status: "accepted"
date: 2026-10-20
deciders: ["AlphaBravoCompany"]
title: "Helm is the only supported deployment path"
tags: [infrastructure, deployment]
---

# Helm is the only supported deployment path

## Context

The repository shipped three deployment paths: the Helm chart, a 12-service
`docker-compose.yaml` with a `compose.dev.yaml` hot-reload overlay, and a native systemd
installer (`deploy/systemd/`, 539-line `install.sh`). Each duplicated configuration
(DSNs, tokens, image tags) and each had its own docs and Makefile targets. Guide ch.11
forbids N parallel copies of deployment configuration; ch.04 prescribes Air + Vite +
a compose stack for backing services only as the dev loop.

## Decision Outcome

Helm (`deploy/charts/constellation`, Helm v4 CLI, chart apiVersion v2) is the only
supported way to run Constellation. The compose and systemd paths, their Dockerfiles
(`Dockerfile.seed`, `Dockerfile.scanner-driver`, `Dockerfile.go-dev`, `Dockerfile.cli`) and
docs were deleted on 2026-10-20. `deploy/dev/compose.yaml` runs only Postgres and the
observability stack for the dev loop; application binaries run on the host under Air via
`scripts/dev.sh`.

### Positive Consequences

- One configuration surface (`values.yaml`) to document, validate and test.
- The dev loop is seconds, not container rebuilds.

### Negative Consequences

- Single-host evaluation requires k3s (one command via the upstream installer) instead
  of `docker compose up`.

## Links

- Guide ch.04, ch.11; `docs/deployment-helm.md`; `scripts/dev.sh`.
