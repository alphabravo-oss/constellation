---
status: "accepted"
date: 2026-10-20
deciders: ["AlphaBravoCompany"]
title: "Vendored NeuVector C data-plane and eBPF programs in a Go service"
tags: [multi-language, runtime, security]
---

# Vendored NeuVector C data-plane and eBPF programs in a Go service

## Context

Guide ch.11 requires an ADR for every non-Go language in the repository, naming the
driver, the alternatives, the support obligation and the boundary. Constellation ships
two: the NeuVector data-plane (`dp`, C, 51 files under `third_party/neuvector/`, three
local patches) and eBPF programs (`internal/runtime/ebpf/bpf/*.c`). The runtime agent
supervises `dp` as a child process (`internal/runtime/dp`, `cmd/constellation-runtime-agent/
dp_session.go`); the image builds it in `deploy/docker/Dockerfile.runtime-agent`.

## Decision Drivers

- Inline deep-packet inspection and L7 policy at line rate on every node.
- Proven, audited enforcement engine rather than a new one.
- Keep the request/operator path in Go (ch.11).

## Considered Options

- Re-implement DPI/enforcement in Go (or Rust).
- Vendor the NeuVector `dp` C code and drive it from Go.
- Depend on a third-party enforcement product (Cilium L7 policy, Falco).

## Decision Outcome

Chosen option: "vendor NeuVector `dp` + eBPF", because a Go re-implementation of a
hyperscan-backed DPI engine is multi-year work and external products do not expose the
per-workload L7 rule model the product sells. The boundary is strict: the only C in the
tree is `third_party/neuvector/` (upstream revision recorded in `NOTICE`, drift checked by
`make vendor-neuvector-diff`, re-vendored by `make vendor-neuvector-sync REV=`) and the
eBPF programs under `internal/runtime/ebpf/bpf/`. Go talks to `dp` over its control
socket (`internal/runtime/dp`); no C is linked into any Go binary (`CGO_ENABLED=0`).

### Positive Consequences

- Mature enforcement engine; upstream security fixes flow through re-vendoring.
- Pure-Go binaries everywhere; `dp` is an isolated process with its own failure domain.

### Negative Consequences

- The runtime-agent image cannot be distroless/scratch (needs the `dp` runtime libraries,
  iptables, tcpdump); see ADR 0005.
- A C toolchain is part of the image build; `tests/native-policy/` keeps a C-level
  regression for the local patches.

## Consequences

Support obligation: the team tracks NeuVector releases, re-vendors at least quarterly,
and keeps the local patches minimal and listed in `third_party/neuvector/local-patches/`.
eBPF programs are compiled with the pinned clang in the image; no pre-built `.o` is
committed.

## Pros and Cons of the Options

### Re-implement in Go

- Good, because single language.
- Bad, because multi-year effort and a new attack surface.

### Vendor NeuVector dp (chosen)

- Good, because production-proven engine with an explicit boundary.
- Bad, because a second toolchain in the build.

### Third-party product

- Good, because no runtime code to own.
- Bad, because the product's L7 rule model and FQDN/DLP features are not available.

## Links

- `third_party/neuvector/README.md`, `docs/network-enforcement-model.md`.
