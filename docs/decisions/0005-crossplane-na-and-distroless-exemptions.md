---
status: "accepted"
date: 2026-10-20
deciders: ["AlphaBravoCompany"]
title: "Crossplane/CAPI not applicable; distroless exemption for tool-bundling images"
tags: [infrastructure, images, operator]
---

# Crossplane/CAPI not applicable; distroless exemption for tool-bundling images

## Context

Guide ch.01 says new operator projects SHOULD adopt Crossplane v2 and evaluate Cluster
API. Guide ch.04 says production runtime images MUST be `scratch` or distroless with no
package manager and a numeric non-root `USER`.

The Constellation operator reconciles the product's own policy CRs and agent workloads
inside the cluster it protects; it provisions no cloud resources and no clusters. Six of
the role images bundle third-party CLIs or kernel-facing tools: scanner (syft, grype,
trivy, cosign, oras), runtime-agent (`dp`, iptables, tcpdump, crictl; must run as root
for BPF/NFQUEUE), kube-bench-runner (kube-bench), audit-archiver (cosign), the Postgres
and barman-sidecar images (upstream CNPG operands).

## Decision Drivers

- Do not add infrastructure frameworks without a use case.
- Keep every image as small and as pinned as its payload allows.

## Decision Outcome

1. **Crossplane / Cluster API: not applicable.** The operator manages in-cluster policy
   state; controller-runtime's per-key workqueue is the reconcile lock; leader election is
   on by default in the chart.
2. **Distroless exemption** for the tool-bundling images listed above. They stay on
   `debian:*-slim` (digest-pinned), run with a numeric non-root `USER` where the payload
   allows (runtime-agent is the only root image and says so in its Dockerfile), and never
   carry `apt` in the final stage beyond what the base provides. All pure-Go images
   (api, operator, admission, discoverer, compliance-scheduler, bootstrap, migrate) are
   distroless `static:nonroot` by digest.

### Positive Consequences

- No speculative framework; the chart stays the single deployment path (ADR 0007).
- Exemptions are enumerated, so a new debian-based image needs this ADR updated.

### Negative Consequences

- The exempted images have a larger CVE surface; they are gated by the release image
  scan (`cmd/tools/release-gate`).

## Consequences

Any new image MUST be distroless unless it is added to the list above with a reason.
Re-evaluate Crossplane/CAPI only if the product starts provisioning clusters or cloud
resources.

## Links

- Guide ch.01, ch.04; `deploy/docker/Dockerfile.*`.
