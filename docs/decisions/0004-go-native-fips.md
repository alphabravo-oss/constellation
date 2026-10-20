---
status: "accepted"
date: 2026-10-20
deciders: ["AlphaBravoCompany"]
title: "Go-native FIPS 140-3 module instead of microsoft/go + BoringCrypto"
tags: [security, build]
---

# Go-native FIPS 140-3 module instead of microsoft/go + BoringCrypto

## Context

Guide ch.06 prescribes a separate `make fips-build` whose output links a validated
crypto module, and names the `microsoft/go` toolchain with BoringCrypto as the reference.
Since Go 1.24 the standard toolchain ships its own FIPS 140-3 module (CMVP certificate
#5247 for `GOFIPS140=v1.0.0`), selectable at build time without a forked toolchain.

## Decision Drivers

- A single, upstream toolchain for every build (no forked compiler to track).
- Runtime-verifiable FIPS status (`crypto/fips140.Enabled()`).
- Separate FIPS artefacts; default builds MUST NOT link the FIPS module.

## Considered Options

- `microsoft/go` + `GOEXPERIMENT=boringcrypto`.
- Upstream Go with `GOFIPS140=v1.0.0` and a `fips` build tag.

## Decision Outcome

Chosen option: "upstream Go FIPS module", because it is the toolchain the rest of the
build already uses, it is CMVP-validated, and `pkg/version/fips.go` can assert the mode
at startup and expose it in `/version` and the heartbeat. `make fips-build` sets
`GOFIPS140=v1.0.0 -tags fips`; images built with `FIPS=true` are tagged `-fips`.
The C data-plane and hyperscan are explicitly out of FIPS scope (`docs/fips.md`).

### Positive Consequences

- No toolchain fork; Dependabot and `go.mod` bumps cover FIPS builds.
- Startup guard refuses to run a `-fips` binary without the module enabled.

### Negative Consequences

- Validation lineage differs from BoringCrypto-based products; auditors need the CMVP
  reference above.

## Consequences

`make fips-build` and `make fips-test` are part of CI. The runtime-agent FIPS scope is the
Go agent only; `dp` remains non-FIPS and is documented as such.

## Pros and Cons of the Options

### microsoft/go + BoringCrypto

- Good, because the guide's reference path.
- Bad, because a forked toolchain and cgo in every FIPS binary.

### Upstream Go FIPS module (chosen)

- Good, because pure Go, upstream, validated.
- Bad, because newer lineage than BoringCrypto.

## Links

- `docs/fips.md`, `deploy/docker/Dockerfile.fips`, `scripts/test-fips.sh`.
