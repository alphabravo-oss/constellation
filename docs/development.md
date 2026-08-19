# Development

This repository consumes `github.com/alphabravocompany/constellation-vulndb`
through its public `pkg/*` packages. The VulnDB repository remains a separate
producer and publisher of signed bundle artifacts; Constellation should not
vendor or copy it under `third_party/`.

## Local Multi-Repo Workspace

For local work on Constellation and VulnDB at the same time, clone the
repositories as siblings:

```bash
gh repo clone AlphaBravoCompany/constellation
gh repo clone AlphaBravoCompany/constellation-vulndb
cd constellation
cp go.work.example go.work
go work sync
```

The example workspace maps Constellation's required VulnDB module version to
the sibling VulnDB checkout without adding a permanent `replace` directive to
`go.mod`. If the VulnDB version in `go.mod` changes, update the version in the
local `go.work` file as well, or regenerate it with:

```bash
version="$(go list -m -f '{{.Version}}' github.com/alphabravocompany/constellation-vulndb)"
go work edit -replace="github.com/alphabravocompany/constellation-vulndb@${version}=../constellation-vulndb"
```

## Private Module Fetches

No-workspace builds that fetch `constellation-vulndb` from GitHub need normal
GitHub credentials and private-module settings so Go does not ask the public
checksum database for the private module:

```bash
export GOPRIVATE=github.com/alphabravocompany/*
export GONOSUMDB=github.com/alphabravocompany/*
```

CI jobs that checkout both repositories create a temporary local workspace, but
release builders that do not use that workspace should set these environment
variables before running `go mod download`, `go mod tidy`, or `go test`.

## GitHub Actions Cross-Repo Access

The committed CI and Security workflows need read access to the private
`AlphaBravoCompany/constellation-vulndb` repository before they can run Go
tests, govulncheck, or CodeQL for Constellation. Configure a repository or
organization secret named `CONSTELLATION_VULNDB_TOKEN` with read access to
that repository. When the secret is absent, the workflows still run Helm and
static guard checks, but they emit a notice and skip private-module Go analysis.

## Module Boundary

Keep these invariants in place:

- Constellation imports only public VulnDB packages such as `pkg/model`,
  `pkg/bundledb`, `pkg/bundleimport`, and `pkg/compat`.
- `go.mod` uses a real VulnDB module version or pseudo-version.
- `go.mod` does not contain a local `replace` for
  `github.com/alphabravocompany/constellation-vulndb`.
- `third_party/constellation-vulndb` must not reappear.
- CI may create a temporary `go.work` file to test both repositories together,
  but that workspace file is not committed.

## Useful Checks

```bash
go mod verify
go test ./...
test ! -d third_party/constellation-vulndb
! grep -n "replace github.com/alphabravocompany/constellation-vulndb" go.mod
! grep -n "v0.0.0-00010101000000" go.mod
! git grep -n -E "third_party/constellation-vulndb|v0.0.0-00010101000000" -- \
  ':!docs/development.md' \
  ':!.github/workflows/*'
```
