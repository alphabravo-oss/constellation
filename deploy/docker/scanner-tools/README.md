# Scanner tool source locks

Syft 1.54.1, Grype 0.120.1, and Cosign 3.1.3 upstream binaries embed older Go
runtimes and libraries. These locks retain the upstream tool versions while
rebuilding with the compiler pinned in `sources.json` (currently Go 1.27.3) and
patched dependencies. Trivy and ORAS are also rebuilt with this compiler from
verified upstream tag commits in the scanner Dockerfile.

`sources.json` pins each upstream Go module checksum and records its source
commit. Each tool's `go.mod` and `go.sum` are the reviewed dependency graph.
Syft and Grype update `golang.org/x/net` to 0.60.0. Cosign also updates gRPC to
1.83.2; Go's dependency resolution raises x/text to 0.42.0 and related x/* modules.
The build uses `-mod=readonly`, a required compiler version, disabled CGO, and the
upstream container image build tags. Tool version output includes the lock's
`patchRevision` to distinguish these builds from upstream release binaries.
Grype uses `-constellation.2`: its local-image completion uses the maintained
Moby client, removing the retired `github.com/docker/docker` module while
preserving daemon API negotiation, tag-prefix filtering and shell fallback.

Build from the repository root using the compiler pinned in `sources.json`
(which must agree with `go.mod`). The builder rejects a different compiler:

```sh
go run ./cmd/tools/scanner-tools --work /tmp/scanner-tool-source --output /tmp/scanner-tools
```

Use a dedicated work directory: the builder replaces the three tool source
subdirectories. `GOARCH` selects the target architecture; the scanner Dockerfile
passes its target architecture to the builder. To check the built Grype binary:

```sh
CONSTELLATION_TEST_GRYPE_BINARY=/tmp/scanner-tools/grype \
  go test -race -shuffle=on -count=2 ./cmd/tools/scanner-tools -run '^TestGrypeBinary$'
```

The same test accepts a Grype executable extracted from an immutable scanner
image. It checks linked dependencies and invokes the real shell-completion CLI
against disposable HTTP daemons: negotiated/explicit API versions, prefix
filtering, empty/unmatched results, and daemon failure fallback. It does not need
a Docker socket or vulnerability database. `Scanner tool validation` runs both
the patched upstream tests and these executable checks on relevant pull requests
and pushes, retaining dependency, version and test evidence as CI artifacts.

Do not treat these checks as complete scanner runtime acceptance. Run
`TestBundledTools` in `internal/scanner`, `TestGoSymbolsActualTools` in that same
package, and `TestBundledCosign*` in `pkg/sigverify` with the packaged tools and
their required immutable vulnerability/signature fixtures. Each test documents
its environment inputs; missing fixtures cause skips and do not establish
acceptance. Retain a scan of the exact image digest. Package matching, keyless and
legacy signature checks, wrong key/identity/predicate rejection, database access,
and normal-user read-only operation remain required before rollout.

To update these locks, start from the checksum-verified upstream module, apply
explicit dependency versions, inspect the go.mod diff, and regenerate go.sum.
Never edit a module's reported version or omit package evidence to hide findings.
