# Scanner tool source locks

Syft 1.54.1, Grype 0.120.1, and Cosign 3.1.3 upstream binaries embed older Go
runtimes and libraries. These locks retain the upstream tool versions while
rebuilding with Go 1.26.9 and patched dependencies. Trivy and ORAS continue to use
checksum-verified upstream binaries in the scanner Dockerfile.

`sources.json` pins each upstream Go module checksum and records its source
commit. Each tool's `go.mod` and `go.sum` are the reviewed dependency graph.
Syft and Grype update `golang.org/x/net` to 0.60.0. Cosign also updates gRPC to
1.83.2; Go's dependency resolution raises x/text to 0.42.0 and related x/* modules.
The build uses `-mod=readonly`, a required compiler version, disabled CGO, and the
upstream container image build tags. Tool version output includes
`-constellation.1` to distinguish these builds from upstream release binaries.

Build from the repository root using Go 1.26.9:

```sh
python3 scripts/build-scanner-tools.py --work /tmp/scanner-tool-source --output /tmp/scanner-tools
```

Use a dedicated work directory: the builder replaces the three tool source
subdirectories. `GOARCH` selects the target architecture; the scanner Dockerfile
passes its target architecture to the builder. Do not treat a successful compile
as runtime acceptance. Exercise `scripts/test-scanner-runtime.py` against the
resulting image and its private, signed vulnerability fixture, then retain a scan
of the exact image digest. Package-matching, keyless and legacy signature checks,
wrong key/identity/predicate rejection, database access, and normal-user read-only
operation are required before rollout.

To update these locks, start from the checksum-verified upstream module, apply
explicit dependency versions, inspect the go.mod diff, and regenerate go.sum.
Never edit a module's reported version or omit package evidence to hide findings.
