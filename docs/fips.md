# FIPS build and runtime contract

Updated: 2026-10-12. The Go build path is implemented; whole-product and deployed
FIPS qualification remain open in [the parity plan](NEUVECTOR-PARITY-PLAN.md).

## Supported source build

The API, scanner, operator and runtime-agent can be compiled with the frozen Go
Cryptographic Module selected by `GOFIPS140=v1.0.0` and the `fips` build tag. Use
the repository's Go version. The tag activates `pkg/version/fips.go`: before
`main`, it rejects a disabled runtime or a module other than `v1.0.0`. All four
roles import this package. Startup logs record `fips_enabled` and `crypto_module`.

```sh
GOWORK=off GOFIPS140=v1.0.0 go build -tags fips -o /tmp/constellation-api-fips ./cmd/constellation-api
go version -m /tmp/constellation-api-fips
make test-fips
```

`make test-fips` builds all four roles, checks their build metadata and executes
the shared startup guard in a test binary. It verifies the enabled pinned module
is accepted and that disabling the runtime or compiling with an unpinned module
fails. CI runs this as a separate required `fips` job and retains the evidence.
It does not start an agent, access a database, or qualify production workflows.

Go documents module v1.0.0 under CMVP certificate #5247. Module identity and the
approved operating environment must be assessed together; this source build does
not certify Constellation, its deployment or its external tools. Go's runtime
mode enables module self-tests and approved TLS negotiation. It does not reject
every nonapproved application operation. `GODEBUG=fips140=only` is a diagnostic
mode with potential panics and is not a production recommendation. See the
[Go FIPS documentation](https://go.dev/doc/security/fips140).

## Containers

`deploy/docker/Dockerfile.fips` builds the API with the pinned Go module and tag.
Its runtime is the ordinary pinned Wolfi base with CA certificates and timezone
data. The statically linked Go binary does not use an OpenSSL provider from that
base; the image is not evidence of a Wolfi/OpenSSL FIPS certification.

```sh
docker build -f deploy/docker/Dockerfile.fips -t constellation-api:fips-local .
make image-runtime-agent FIPS=true
```

The runtime-agent Dockerfile selects the same Go module and tag when `FIPS=1` or
`FIPS=true`. The default Makefile image target keeps the normal version tag;
it does not automatically publish `fips-latest` or a `-fips` tag. Select a distinct
`VERSION` and qualified registry destination for release artifacts.

Agent image labels record the requested Go build mode and explicitly mark the
C data plane as outside that scope. Labels and `/etc/constellation/fips` are
build metadata, not runtime attestation. Inspect the executable's build metadata
and startup logs as well. The runtime image does not contain the Go toolchain;
copy its binary out before running `go version -m` on the host.

## Runtime-agent boundary

The agent contains a Go supervisor, the vendored NeuVector C data plane and eBPF
probes. The FIPS build option changes the Go cryptographic module only. It does
not certify the C libraries, packet parsers, probes, kernel, host tooling,
PostgreSQL, RustFS, scanner executables or other external services. Whether a
component falls inside a particular deployment's cryptographic boundary requires
an explicit review; a noncryptographic dependency is not independently a claim
about that deployment's compliance.

The code has no `fips_only` policy rejection field, no tag-selected alternate slog
hash, and no `constellationctl version --fips` command. Earlier documentation
claimed these mechanisms; the implemented guard and logs described above replace
those claims. Audit-chain and evidence algorithms are unchanged by the tag.

## Remaining release qualification

- Inventory each cryptographic operation, key type and custody boundary, including
  password KDFs, JWT/session/federation signing, backup encryption, SAML and tools.
- Exercise identity, ingest, scan, audit, backup/restore and certificate rotation
  with the frozen module in an approved operating environment. Test unsupported
  keys/algorithms and fail-path behavior explicitly.
- Qualify and sign immutable role images, record the module security policy,
  native dependencies and deployment boundary, and verify the exact deployed
  runtime. Current generic release images are not a FIPS release channel.
- Keep this evidence separate from the ordinary Go tests and from HA/CNI/offline
  acceptance. Passing the build/runtime gate alone does not close OPS-2 or TSG-4.
