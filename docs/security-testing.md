# Blocking security and test tooling

The `CI` workflow runs on every pull request (including forks), main-branch pushes,
merge queues and manual dispatch. Repository administrators must require the
`required` check in the branch/ruleset settings; workflow files cannot enable
branch protection. That check fails if any dependency fails, is skipped or is
cancelled. No scan is advisory and no job uses `continue-on-error`.

## Reproduce the gates

Use the Go version in `go.mod` and Node in `.node-version`. On Linux amd64:

The Go test and security runners set `GOWORK=off` so an enclosing developer
workspace cannot select an older toolchain or replace the module graph. For
direct Go/Make commands inside such a workspace, export `GOWORK=off` yourself.
The enclosing workspace is not modified by these runners.

```sh
make tools
export PATH="$HOME/.local/bin:$PATH"
make test-tooling
make lint fmt lint-shell
make test-race
make test-integration
make security
cd frontend && npm ci && npm run test:ci && npm run build
```

`make lint` fails if golangci-lint is absent or reports findings. The v2 config
uses upstream `standard` plus explicit correctness, security, context, SQL and
complexity checks; no standard linter is disabled. The guide's complexity
thresholds and readonly module loading are configured. `make fmt` verifies
gofmt/goimports without rewriting files. Generated Go is excluded using strict
generated-file markers; vendored `third_party/` code is not reformatted/linted.
ShellCheck scans tracked and new first-party shell scripts, including deployment
helpers, rather than silently restricting itself to the newly added scripts.

`scripts/test-go.sh unit|integration [package patterns]` runs uncached, shuffled
race tests through gotestsum. The integration mode starts a disposable pgvector
PostgreSQL database, migrates twice, and preserves the existing serialized,
twice-repeated `-tags=integration -p 1 -count=2` suite. Containers are removed on
failure; cleanup errors do not mask a test failure. The release clean-database
gate retains its original default execution; `TEST_GO_USE_GOTESTSUM=1` opts that
script into reports/races. `GOTESTSUM_BIN` and `GOOSE_BIN` support local installs.
Isolation is **per suite**, not per test; this does not prove fixture isolation.

## Security evidence and enforcement

| Gate | Evidence and failure behavior |
| --- | --- |
| gosec | SARIF; native nonzero finding/error status, no `-no-fail` |
| govulncheck | One source scan to streaming JSON, converted to SARIF and text; text conversion enforces reachable vulnerability failures against the same evidence |
| gitleaks | Full fetched history/all refs, redacted SARIF; shallow clones are rejected |
| npm audit | Full lockfile including development dependencies for frontend and VS Code extension; any advisory or scanner error blocks |
| pip-audit | Resolves and audits the integration harness requirements; any advisory or scanner error blocks |
| Go/frontend tests | JUnit and JSON, uploaded even after a failed test step |
| Lint/format | golangci-lint JSON, ShellCheck JSON, formatter diff |

govulncheck's JSON/SARIF modes deliberately return success even with findings;
the subsequent text conversion is essential. Load/parse/network errors also
fail rather than producing a successful empty scan. Gitleaks uses `fetch-depth:
0`, `--log-opts=--all` and `--redact=100`; no secret baselines or allowlists were
added. This covers all fetched refs, not inaccessible remote refs or deleted
objects that are no longer reachable.

CI writes `artifacts/`, retaining uploads for 14 days. Local lint/security
defaults use ignored `test-results/`; test runners default to `artifacts/`.
Use `ARTIFACT_DIR=/tmp/constellation-reports` to move shell-runner artifacts.
Frontend `test:ci` writes `artifacts/frontend-junit.xml` and
`artifacts/frontend-tests.json`. Do not commit reports. Go security SARIF uploads
to GitHub code scanning on same-repository events; fork PRs still run blocking
scans and upload artifacts without requiring write access. Code scanning must
be enabled in repository settings; upload failures are not hidden. Secret
reports remain redacted artifacts rather than annotations tied to old commits.

## Pins and maintenance

`scripts/install-ci-tools.sh` owns executable pins. It verifies binary archive
checksums and uses versioned Go module installs for source-built tools. The
archive installer intentionally supports Linux amd64, matching CI; on other
platforms install these same versions manually. GitHub Actions use commit SHAs.

| Tool | Pin | Verification source |
| --- | --- | --- |
| golangci-lint | 2.11.4 | [Official release](https://github.com/golangci/golangci-lint/releases/tag/v2.11.4); Go 1.26 support starts in 2.9.0 |
| gosec | 2.29.0 | [Official release](https://github.com/securego/gosec/releases/tag/v2.29.0); includes the taint-analysis hang fixes introduced in 2.25.0 |
| govulncheck | 1.8.0 | [Official source](https://github.com/golang/vuln/tree/v1.8.0); modern Go parser and convert-mode support |
| gitleaks | 8.30.0 | [Official release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.0) |
| gotestsum | 1.13.0 | [Official release](https://github.com/gotestyourself/gotestsum/releases/tag/v1.13.0) |
| goose | 3.27.1 | Existing clean-database/release pin, retained |
| actionlint | 1.7.11 | [Official release](https://github.com/rhysd/actionlint/releases/tag/v1.7.11) |
| ShellCheck | 0.11.0 | [Official release and asset digest](https://github.com/koalaman/shellcheck/releases/tag/v0.11.0) |
| pip-audit | 2.10.0 | [Published package metadata](https://pypi.org/project/pip-audit/2.10.0/) |
| Python (CI tooling) | 3.12.14 | [Official security release](https://www.python.org/downloads/release/python-31214/); available in Actions' Python versions manifest for Ubuntu 24.04 |
| Node / npm | 24.21.0 / 11.19.0 | [Official Node release index](https://nodejs.org/dist/index.json); `.node-version` and frontend engines/packageManager match |

Node 24 LTS preserves the release workflow's existing major version and supports
the installed Vite 8 engines. This is not an approval of divergence from the
guide's historical Node 25 example. Both PR and release workflows consume the
same `.node-version`; release and Makefile frontend builds pass it as
`NODE_VERSION`. The Dockerfile default matches, with a tooling regression test
preventing drift. Weekly Dependabot updates cover Go, npm, Python, Actions
and Docker dependencies; scanner/runtime pins embedded in scripts still require
manual review and patching, including checksum updates. Dependency updates never
auto-merge. Review pins monthly and immediately for relevant security notices.

## Remediation and exceptions

Treat findings as unresolved until verified, not as proof of exploitability.
The owning component maintainer triages each finding with the security reviewer.
Exposed credentials require immediate revocation/rotation and incident triage;
removing the source line does not remove history. Critical issues have a 24-hour
triage/72-hour remediation target, high issues 7 days, medium 30 days, and low
90 days. These deadlines do not waive the blocking PR check.

Exceptions require a reviewed issue recording the exact rule/advisory and
location, false-positive evidence or compensating control, accountable owner,
security approver and expiry (at most 30 days). A narrow inline exception must
link that record and explain the reason. Renewals require re-review. Do not
disable scanners, lower exit-code enforcement, add broad path/rule exclusions,
or baseline the existing findings to make CI green. No new finding exceptions
are introduced here. Existing inline exclusions still need review.

## Scope and remaining acceptance

This is a tooling gate, not a claim that the current application passes every
gate or satisfies TSG-4. Baseline findings must be fixed by their source owners.
Go tests still need per-test real-backend isolation and complete build-tag
separation; a shuffled shared database can expose existing fixture collisions.
The Python harness has unbounded requirements rather than a reproducible lock;
its audit reflects current resolution, not a verified deployed environment.
Python deployment/runtime alignment, type/lint/lock checks and native/vendored
dependency audits remain separate work. Browser production/auth flows, distinct FIPS checks,
Air/dev orchestration, Docker runtime alignment/digests/labels and live-cluster
acceptance are not implemented by this slice. No API or OpenAPI change is needed.

Before claiming acceptance, record actual hosted CI/SARIF uploads, required-check
configuration and complete unit/integration runs, not only fixture-based tooling
tests. The [guide's tooling chapter](https://technology-selection-guide.aws.ablabs.io/04-infra-tooling/)
and [govulncheck exit-code documentation](https://github.com/golang/vuln/blob/v1.8.0/cmd/govulncheck/doc.go)
explain the baseline and the SARIF enforcement distinction.

## Local acceptance snapshot — 2026-09-26

The tag-release workflow also invokes the reusable CI workflow before verification
and image publication. Release tags therefore cannot bypass these source/security
gates. Hosted execution and repository-required-check configuration still need
verification; local results below are not a release certification.

These observations are from the shared, changing worktree, not hosted CI or a
release certification. Findings are not suppressed to make the gates pass.

- All 25 tooling regression tests passed on the pinned Python 3.12.14. These
  cover missing tools, nonzero scan/test status, same-evidence SARIF enforcement,
  full-history/redaction arguments, migrations, cleanup and runtime-pin drift.
- golangci-lint configuration verification, actionlint, syntax/ShellCheck for
  the five owned runner/installer scripts, and scoped `git diff --check` passed.
- Actual gotestsum runs passed: 9 tests in `pkg/redact` and `pkg/risk` with
  races/shuffle/count=1; 28 executions in `pkg/audit` with integration tags,
  races/shuffle/count=2 on a fresh database migrated through 163 and a second
  migration no-op. JUnit and JSON reports parsed successfully. These are focused
  package runs, not the full source suite.
- The runtime subagent passed three focused frontend tests under Node 24.21.0,
  parsed both report formats and verified the package dependencies were unchanged.
- pip-audit 2.10.0 on Python 3.12.14 completed successfully with no known
  vulnerabilities in the harness's currently resolved requirements. The host
  Python lacked ensurepip, so this acceptance used the pinned Actions Python
  distribution, not a weakened audit mode. The unpinned requirements remain a
  reproducibility gap. Evidence: `/tmp/tsg4-pip312-audit.json`.
- The pinned `node:24.21.0-bookworm` image manifest resolved successfully, and
  `make -n image-frontend` passed the `.node-version` value as a build argument.
  This verifies the reference/wiring, not a complete image build.
- Full lint completed and failed with 1,895 findings. Full standalone gosec
  2.29.0 completed and failed with 256 SARIF findings. An initial gosec 2.24.0
  run stalled and was terminated; the installed pin was updated to include
  upstream's analysis-hang fix, without disabling rules.
- Full govulncheck completed and failed with exit 3 for 37 reachable
  vulnerabilities: 28 in the Go 1.26.0 standard library and 9 across six
  dependency modules. SARIF and JSON were retained before enforcing failure.
  Earlier attempts encountered transient compile errors during concurrent
  auth/migration edits; the completed rerun supersedes those attempts.
- Full-history gitleaks scanned 371 commits and failed with 18 detections;
  reports are redacted and still require owner triage. The frontend npm audit
  reported one high and two moderate affected packages; the extension audit
  reported one moderate affected package. Both returned nonzero.
- Repository-wide ShellCheck failed with six findings in preexisting deployment
  helpers; formatter verification failed with a 6,534-line diff. Neither command
  rewrote or relaxed the source baseline.

Local evidence is under `/tmp/tsg4-results-final/` (completed Go scans),
`/tmp/tsg4-results/` (history/ShellCheck/format), `/tmp/tsg4-unit/`,
`/tmp/tsg4-integration/`, and `/tmp/tsg4-*-audit.json` in this working environment.
Reports are not committed. Complete-suite race/integration, hosted uploads,
branch protection and image build/deployment acceptance remain unverified here.

## Targeted dependency remediation — 2026-09-26

The follow-up dependency-only slice supersedes the reachable-vulnerability and
npm-audit counts in the initial snapshot, not the unrelated lint/secret baseline.
All dependency edits used reviewed minimum fixes, without forced npm updates or
scanner exclusions. Some upstream security fixes require minor releases rather
than patch-only version increments; compatibility caveats are explicit below.

| Component | Resulting version | Reviewed upstream evidence |
| --- | --- | --- |
| Go source and Go Docker builder defaults | 1.26.8 | [Supported 1.26 patch history](https://go.dev/doc/devel/release#go1.26.8) |
| cilium/ebpf | 0.22.0 | [BTF parsing advisory](https://pkg.go.dev/vuln/GO-2026-6238), [release notes](https://github.com/cilium/ebpf/releases/tag/v0.22.0) |
| chi/v5 | 5.3.0 | [Release notes](https://github.com/go-chi/chi/releases/tag/v5.3.0) |
| goxmldsig | 1.6.0 | [Signature validation fix](https://github.com/russellhaering/goxmldsig/releases/tag/v1.6.0) |
| OpenTelemetry API/SDK selected by gRPC | 1.44.0 | [Release notes](https://github.com/open-telemetry/opentelemetry-go/releases/tag/v1.44.0) |
| x/text | 0.39.0 | [Normalization advisory](https://pkg.go.dev/vuln/GO-2026-5970) |
| gRPC | 1.83.1 | [Security release](https://github.com/grpc/grpc-go/releases/tag/v1.83.1) |
| Vitest and companion packages | 4.1.11 | [Traversal advisory](https://github.com/vitest-dev/vitest/security/advisories/GHSA-82fw-gwwq-j7x9) |
| js-yaml | 4.3.2 | [Merge-source CPU advisory](https://github.com/nodeca/js-yaml/security/advisories/GHSA-2883-xcg3-v3hh) |
| Extension esbuild | 0.25.0, exact pin | [Development-server fix](https://github.com/evanw/esbuild/releases/tag/v0.25.0) |

Go's required transitive versions were resolved by the module tool and go.sum
was tidied. Esbuild crosses a pre-1.0 minor boundary, but the extension uses the
CLI bundler rather than its changed development server: compile/build passed,
the bundle was byte-identical to 0.24.2, and watch rebuild/failure/recovery passed.

Validation explicitly used `GOWORK=off GOTOOLCHAIN=go1.26.8`. Both the built API
binary (`/tmp/tsg4-patched-constellation-api`) and rebuilt govulncheck executable
report `go1.26.8` in `go version -m`; the scan JSON and race-test JUnit also record
that version. The full rescan passed with **zero reachable vulnerabilities**,
retaining JSON/SARIF/text at `/tmp/tsg4-patched-security/`. It still reports two
non-called imported-package advisories and seven module-only advisories, so
this is not a claim of a vulnerability-free dependency graph.

Both resulting npm lockfile audits passed with zero findings. Staged frontend
tests passed 74/74 across 23 files; five migration DTO TS2345 errors reproduced
with both old and new lockfiles during the concurrent migration work. Staging
evidence is at `/tmp/dependency-remediation-axa7ds3m`.

All packages compiled with the staged Go graph. Focused application tests passed
for auth, eBPF, observability, handlers and runtime-agent; upstream goxmldsig,
chi and Unicode normalization suites passed. A broader server-package attempt
encountered browser-session creation errors against its ambient database. A
fresh migration-163 database then passed 20 focused server test executions with
races, shuffle and count=2; its JUnit is `/tmp/tsg4-dep-db/integration.xml`.
The workspace-isolation tooling regressions passed 27/27. The parent's complete
integration/container/browser acceptance runs are separate evidence.

Known compatibility boundary: OTel 1.44 introduces a default per-instrument
2,000-series limit. Above that limit it aggregates into the overflow series,
changing OTLP route-level detail; no global override was added. The eBPF APIs
removed in 0.21/0.22 and the XDP attach-type transition are not used by this
loader, but real-kernel load/attach/event validation remains required. Signed
IdP ACS and live Hubble streaming acceptance also remain deployment checks.
No auth/session implementation, API contract or OpenAPI change was made by
this dependency slice, and the parent workspace/CI browser job was left alone.
