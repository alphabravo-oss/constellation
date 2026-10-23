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
# Install Helm v3.21.0, then use an isolated Python environment.
python3.12 -m venv /tmp/constellation-tooling-venv
. /tmp/constellation-tooling-venv/bin/activate
python3 -m pip install --requirement scripts/requirements-tooling.txt
make test-tooling
make lint fmt lint-shell
make test-race
make test-integration
make test-fips
make security
cd frontend && npm ci && npm run test:ci && npm run build
```

`make lint` fails if golangci-lint is absent or reports findings. The v2 config
uses upstream `standard` plus explicit correctness, security, context, SQL and
complexity checks; no standard linter is disabled. The guide's complexity
thresholds and readonly module loading are configured. `make fmt` verifies
gofmt/goimports without rewriting files. Generated Go is excluded using strict
generated-file markers; vendored `third_party/` code is not reformatted/linted.
The formatter uses the module package list so ignored reference checkouts do not
change local results. ShellCheck scans tracked and new first-party shell scripts, including deployment
helpers, rather than silently restricting itself to the newly added scripts.

`scripts/test-go.sh unit|integration [package patterns]` runs uncached, shuffled
race tests through gotestsum. The integration mode starts a disposable pgvector
PostgreSQL database, migrates twice, seeds its isolated demo fixtures, and runs the serialized,
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

The gosec runner enumerates package directories with `go list ./...` before
scanning. This matches the module's build scope and avoids recursively compiling
ignored, nested reference repositories such as the local Rancher checkout.
Package-discovery failures and empty results fail closed. All discovered packages
retain the full rule set and native finding/error exit status. A single scan
emits JSON and SARIF from the same issue list. The normalizer verifies each
finding's identity before restoring repository-relative SARIF paths from JSON;
otherwise package-local roots would flatten distinct files such as `main.go`.
Mismatched or missing reports fail rather than producing misleading annotations.

Defaults are two scan workers, `GOMAXPROCS=2` and `GOMEMLIMIT=2GiB`. Override with
`GOSEC_CONCURRENCY`, `GOSEC_GOMAXPROCS` and `GOSEC_GOMEMLIMIT` when sizing a dedicated
runner. The memory limit is a Go runtime soft budget, not a hard RSS cap. Unless
`GOTMPDIR` is supplied, each scan creates and cleans its own scratch directory
under `${XDG_CACHE_HOME:-$HOME/.cache}/constellation`, avoiding memory-backed `/tmp`.
Caller-owned scratch directories are preserved. Run full scans separately from
browser/capacity benchmarks on shared hosts.

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
| PyYAML (chart tests) | 6.0.3 | [Published package metadata](https://pypi.org/project/PyYAML/6.0.3/); `scripts/requirements-tooling.txt`, included in dependency audit |
| Helm (CI chart tests) | 3.21.0 | [Official release](https://github.com/helm/helm/releases/tag/v3.21.0); explicit quality-job pin |
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

## Wrapped errors and archive extraction

Error handling now recognizes wrapped sentinel errors in authentication,
federation, migration, compliance, scanning and runtime paths. This removes 49
errorlint findings without disabling rules. Serverless ZIP extraction uses an
`os.Root` directory handle and private directory/file permissions; it rejects
non-local paths, duplicate files and archives exceeding the entry budget,
including directory entries. This intentionally rejects ambiguous duplicate-path
packages that previously overwrote an earlier entry. Symlink-escape and package
permission regression tests exercise the actual filesystem.

A later full scan reports 253 gosec findings (previously 261), with no Go load
errors. This remains a failing gate, not security acceptance. The archive changes
do not close the separately documented serverless DNS-rebinding or scanner
isolation requirements.

## Admission TLS capture remediation

The October 12 continuation removes the historical admission TLS Secret capture
from the current tree. The scenario now generates fresh one-day certificates in
a private temporary directory, streams the Secret to kubectl, and deletes private
material on success or failure. Regression tests exercise both paths using real
certificate generation and a fake Kubernetes boundary; no live scenario is run.

The historical server key is still exposed in Git history, with a certificate
valid until May 2036. A wider local-ref scan also found its matching CA private
key; publication of that older commit is unconfirmed. The owner is unsure about
use outside local development. Both CA and server keys must be replaced wherever
used, together with the corresponding trust. The repeatable read-only
`scripts/audit-admission-tls-trust.py` compares certificate and public-key
fingerprints in named certificate fields in Secrets of all types, ConfigMaps and
admission webhook CA bundles. It found zero matches and zero verification errors
across 20 certificate occurrences in the main local cluster and 45 in the
isolated CNPG cluster. Other fields, trust stores and clusters remain unverified.
The [scenario remediation record](../deploy/e2e/threat-scenarios/04-admission-tls/EVIDENCE.md#october-12-credential-remediation)
records scope, commands, counts and unresolved revocation requirements. No
gitleaks suppression, history rewrite or security-review exception was added.

### Historical secret finding triage

The ten detections in the earlier retained redacted scan were inspected at their scanned
commits without reproducing credential values. Eight have evidence of prose,
browser storage identifiers or synthetic test data; one is an expired JWT and
one is the exposed admission private key. These assessments prepare review;
they do not waive the scanner or supply the reviewed exception records required
above. No signing-key safety conclusion follows from an expired JWT alone.

| Scanned location | Assessment and evidence |
| --- | --- |
| `docs/NEUVECTOR-PARITY-PLAN.md:268` at `e51a69a2` (`generic-api-key`) | Documentation prose about recovering keys and sessions, with no credential assignment. |
| `internal/migration/neuvector/testdata/remaining_families.yaml:75` at `800b0ef1` (`kubernetes-secret-yaml`) | Synthetic Kubernetes Secret in the migration fixture; its password is an uppercase `SECRET_` placeholder, and `TestRemainingCanonicalFixture` checks that serialized conversion omits those markers. |
| `deploy/e2e/threat-scenarios/04-admission-tls/captures/secret.yaml:4` at `3b15b3ea` (`private-key`) | Actual exposed leaf private key; source capture removed, deployment/trust inventory and revocation remain unresolved as above. |
| `docs/deployment-helm.md:266` at `3b15b3ea` (`generic-api-key`) | NetworkPolicy documentation prose listing allowed component-to-component traffic. |
| `docs/e2e-results.md:210` at `3b15b3ea` (`jwt`) | Actual HS256 JWT recorded in historical results; decoded expiry is **2026-05-12 15:15:32 UTC**, before the initial public commit and this review. The token value and signature are not reproduced. |
| `frontend/src/components/CommandPalette.tsx:41` at `3b15b3ea` (`generic-api-key`) | `RECENT_KEY` is a localStorage namespace for recent command items, not an authentication key. |
| `frontend/src/components/ScopeBar.tsx:14` at `3b15b3ea` (`generic-api-key`) | `STORAGE_KEY` is a localStorage namespace for UI scope selection. |
| `internal/handler/auth_security_review_test.go:240` at `3b15b3ea` (`generic-api-key`) | Deliberately wrong password in a test asserting HTTP 401 for a fixture user. |
| `internal/handler/password_change_test.go:68` at `3b15b3ea` (`generic-api-key`) | Synthetic current/new password inputs in a fixture test asserting HTTP 401. |
| `pkg/redact/redact_test.go:60` at `3b15b3ea` (`generic-api-key`) | Synthetic input to the redaction test, followed by an assertion on redacted output. |


A subsequent `--all` scan at `659104c` inspected **434 commits** reachable from
local refs and reported **20 detections**, including older branches absent from
the fetched PR history. The additional ten comprise seven earlier detections in
the same prose, storage-identifier, synthetic-password/redaction and expired-JWT
families, and three actual private-key detections (`ca.key`, `tls.key` and the
serialized Secret at `4333d28b`). The CA key is a distinct compromised key, not a
false-positive fixture. The matching leaf key and certificates are the same
identities described above. Current GitHub refs did not contain that older
commit; its publication cannot be established from this inventory. The redacted
all-ref report is `/tmp/constellation-659104c-gitleaks/gitleaks.sarif`. Counts are
scope-dependent; do not substitute a narrower hosted scan for this local-ref
inventory or treat repeated findings as newly introduced credentials.

## Scope and remaining acceptance

This is a tooling gate, not a claim that the current application passes every
gate or satisfies TSG-4. Baseline findings must be fixed by their source owners.
Go tests still need per-test real-backend isolation and complete build-tag
separation; a shuffled shared database can expose existing fixture collisions.
The Python harness has unbounded requirements rather than a reproducible lock;
its audit reflects current resolution, not a verified deployed environment.
Python deployment/runtime alignment, type/lint/lock checks and native/vendored
dependency audits remain separate work. The October 12 continuation adds a distinct
FIPS build/runtime guard job; see [its exact scope](fips.md). Full deployed
cryptographic qualification, Air/dev orchestration, Docker runtime
alignment/digests/labels and live-cluster acceptance remain open. No API or OpenAPI change is needed.

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

## October 12 continuation

The production browser runner now defaults to the complete suite; pass explicit
spec names only for a focused local run. CI also enables the loopback-only fixed
migration apply/idempotency/rollback fixture. The rebuilt local suite passed
191/191 without retries and the frontend suite passed 133 tests. Compiled assets
use `/static/`, preserving the application `/assets` route. Login setup honors
actual Retry-After cooldowns without weakening the production rate limit.

The clean-database runner seeds its newly created disposable database after both
migration runs. This exercises legacy seed-dependent tests instead of treating
their skips as coverage. It never seeds an operator-supplied DSN. Per-test fixture
isolation remains unfinished. The full seeded run passed 5,556 test executions
with repetition, shuffling and the race detector, with no skips or failures;
JUnit/JSON are in `/tmp/constellation-parity-seeded-race/`. New federation redirect tests own their org.

Repository Go formatting and ShellCheck pass locally. The remaining strict lint
and security findings still block release; they have not been suppressed.
See [the canonical tracker](NEUVECTOR-PARITY-PLAN.md) for current gate evidence.

## Resource and conditional-editor fixes — 2026-10-12

The first local full gosec attempt recursively entered the ignored Rancher
reference checkout, exhausted memory/swap and filled the 16 GiB memory-backed
`/tmp` with abandoned compiler scratch. The runner now discovers this module's
packages, uses two workers and a 2 GiB runtime soft memory budget, and owns disk
scratch. The completed rescan covered 120 packages in 15.64 seconds; GNU time
reported 284,376 KiB maximum resident set size. This is observed process usage,
not an aggregate host-memory cap; the final run used warmed build caches. All
261 SARIF paths resolve to repository files and the JSON reports no Go load errors.
It exited 1 with **261 findings**, down from
268 in hosted run 38191094639; no rule/path allowlist was added. Evidence:
`/tmp/constellation-bounded-full-gosec-final.log` and
`/tmp/constellation-bounded-full-security/gosec.sarif`.

The configuration API rejects stale conditional edits without writing, and both
shared forms preserve drafts after conflicts or failed background refreshes.
Argon verification bounds stored-hash work without changing locally generated
parameters; imported hashes above those bounds fail format validation. Kafka
header parsing is frame-bounded, and plugin example HTTP servers have deadlines.
Latest affected-package validation passed 586 executions (twice, shuffled, race
detector, fresh migration-170 PostgreSQL, zero skips/failures), followed by 40
findings-package executions after extracting a fixture helper. Full immutable
`3944e02` validation passed 5,572 executions. Frontend component/unit tests pass
143/143. The new-code lint check against `3b2f2aa` reports zero issues; this does
not clear the full repository's existing lint backlog.

The repaired Accept Risk/comment tests wait for their filtered response and the
corresponding row. Eight focused production-container browser cases pass without
retries, including real API HTTP 412/draft recovery. The final rebuilt full
suite passes 194/194 with zero retries and the migration apply/rollback recipe
enabled; all 78 tooling tests, ShellCheck and module formatting pass. Evidence:
`/tmp/constellation-resource-fixed-full-browser.log` and
`/tmp/constellation-fixed-tooling-final.log`. The failed hosted browser
run 38191094639 predates this repair; subsequent full/hosted evidence is recorded
in the canonical tracker. Reports remain local artifacts and are not committed.


## October 17 release-readiness continuation

Hosted CI at `7ba816e` still fails quality, gosec and historical gitleaks.
A local baseline reports 2,024 quality findings and 256 standalone gosec findings;
the frozen remediation candidate `034f2baf49c1` reports 1,813 and 224 respectively.
The quality baseline includes four downloaded JavaScript-fixture Go findings
outside the Go module. Quality now enumerates the module with `go list`, matching
formatting and security scans; empty/failed discovery and linter failures remain
blocking. No rule thresholds, security exits or historical-secret exclusions
were relaxed. The full repository is not security-clean.

The candidate fixes backup tenant reads, agent policy-bundle cluster scope,
unsafe process/conntrack response selectors, private artifact writes, signing
staging paths, wire-ID overflow, CLI false-success output and compliance delivery
false success. Serverless downloads validate DNS results at dial time, pin numeric
addresses and retain destination TLS identity through numeric CONNECT tunnels.
Proxy authentication stays on the proxy hop. Signed URLs are excluded from scan
logs and persisted failure reports; wrapped cancellation remains identifiable.
Focused negative tests and fresh-database evidence are indexed in the canonical
parity plan. Candidate images and the combined source qualification are recorded
under `/tmp/constellation-security-034f2baf49c1/` on the development host.

The new all-ref redacted history scan still reports 21 detections. They include
previously documented actual historical private keys and false-positive fixtures;
removing current source does not revoke an exposed certificate or rewrite history.
The additional admission-inventory test detection contains an intentionally
invalid fixture, not a new usable credential. No history rewriting or finding
suppression was performed. The main-cluster read-only trust audit on October 17
examined 39 certificate occurrences across Secrets, ConfigMaps and webhooks, with
zero historical certificate/key matches and zero read errors. Its JSON report is
`/tmp/constellation-admission-trust-main-20261017.json`. External clusters and
trust stores remain unproven; this local audit does not authorize a global
revocation-complete claim.


### Exact process-response candidate (schema 178)

Commit `9b637f1` adds a separate process-response queue and protocol, isolated
from legacy agents during rolling upgrades. The queue preserves the triggering
process event's node, boot ID, kernel start time, PID, command and container
identity. An agent opens a pidfd, then verifies the exact kernel identity and
current container/workload before signaling. Unknown identities, protected host
or system workloads, missing hooks and unsupported pidfds refuse the action.
The process response flag remains opt-in; the deployment does not enable it.

The agent writes intent to its private durable telemetry volume before an
effect, and saves the outcome before delivery. A crash with intent but no result
becomes `uncertain`; the agent never repeats that effect. Results are removed
only after an exact durable server receipt, whose audit write commits with the
terminal queue state. `applied` means SIGKILL was accepted, not that process exit
was observed. This durability starts after enqueue commits; source-event
response dispatch remains a separate best-effort post-commit step. Runtime
credentials authenticate a cluster; the node selector is not independent node
authentication.

Journal entries and response envelopes have matching byte limits. Unknown,
corrupt or interrupted journal files stop new effects. A drained journal permits
credential rotation within the same API/cluster/node scope. A journal with pending
intent or results requires operator reconciliation before a credential or scope
change; it is never silently rebound to a different identity.

Qualification includes 192 fresh178 focused executions without skips, 136
focused local executions, a real pidfd lifecycle against a disposable child,
and two strict real-kernel BPF lifecycle executions. The kernel test requires
`CONSTELLATION_TEST_BPF_IDENTITY=1` and privileges; it rejects degraded capture,
checks its own child's exact event/map identity after nonleader thread exit, and
checks removal after normal leader exit. Ordinary integration runs explicitly
skip that opt-in test and its child helper. This does not qualify a deployed
response-rule workflow or the CNI enforcement matrix. Evidence is retained in
`/tmp/response-v2-final-fresh-db/`, `/tmp/response-v2-review-final.json` and
`/tmp/response-v2-kernel-identity-final.json`.

Candidate source `ce667d1` also adds the missing conntrack executable to the
runtime image. Image provenance/native dependency checks pass; the unprivileged
image startup check intentionally has no kernel privileges or uploads. Dedicated
kernel tests provide the kernel evidence. The combined fresh178 suite passes
1,648 executions with four explicit opt-in kernel/helper skips; its separate
privileged kernel run passes twice. The first recovery drill completed its
scheduled backup but stopped at a fixture queue-order assertion before restore.
The corrected harness gives its proof job first FIFO position while retaining
the exact-job assertion. Its retry passes scheduled backup, WAL/PITR boundary,
session/configuration and credential recovery, wrong-key rejection, restored-key
recovery, audit continuity and fresh login. The recovered pod restart/reconnect
takes 196 seconds, including CNPG's 180-second smart-shutdown window. This is
isolated single-node recovery; off-host recovery and real-node failure remain
deferred. The candidate is deployed at Helm77/schema178 with all application
deployments and the runtime DaemonSet ready; live v2 queue authorization checks
pass, and process/dataplane enforcement remain disabled. Recovery and rollout
evidence is retained under `/tmp/constellation-response-ce667d1/`.
The repository's global security and quality gates remain failing and no findings
have been suppressed by this candidate.


### Scoped policy and compliance follow-up, Helm 78

Frozen source `6c4a1cc` combines the scoped native bundle protocol, DLP cluster
ownership, generated-policy atomic auditing, compliance authoring/claim audit
transactions, strict benchmark request parsing and numeric boundary fixes.
The combined fresh178 suite passes 2,194 executions without skips. API/runtime
images report the exact source revision at startup; native library, conntrack
and BPF-object checks pass. Exact-image isolated CNPG/RustFS backup and PITR,
restored session/credentials/audit/fresh login, wrong-key rejection, retained-key
recovery and 195-second database-pod restart pass. This remains a same-host,
single-node drill, not HA or off-host recovery.

Helm78/schema178 deploys those two images; migration and other roles retain
previously qualified images. Seven deployments and the runtime DaemonSet are
ready. Live scope bundle v2 succeeds, legacy bundle reads return 426, unknown
cluster returns 404, and v2 response queue anonymous/foreign/duplicate-node
requests return 401/403/400. Live policy and response queues are empty; process
and native dataplane enforcement stay disabled. Evidence:
`/tmp/constellation-scope-6c4a1cc/`.

Commit `d28433e` separately adds a test-only actual native parser/staging/matcher
harness. Production Go translation and Unix-datagram encoding feed unchanged
vendored C control/matching objects in nonroot containers with no network,
capabilities, host namespaces or host mounts. Thirty-four matcher assertions run
twice, plus fixture generation, all without skips. Malformed/unknown commands,
a deliberately wrong expected action and a stale-image source manifest are
rejected. Exact vendor/harness/object provenance is recorded; copied build
objects are removed and native compilation is forced. Ordinary integration
runs report two explicit opt-in skips unless this harness is configured.
Evidence: `/tmp/run1-native-proof-hardened/summary.json`. This proves policy
parsing, table staging, two-endpoint scope, keyed/range/application/default
matching, monitor/protect actions, ICMP transitions, partial-transfer retention,
scoped deletion and shared-handle isolation. Packet interception, live CNI
verdict delivery, session re-evaluation and application classification remain
separate acceptance work.

Commit `ae8cd73` makes edge entity/membership completion audits transactional;
HTTP audit failure rolls back edge and policy mutations with 503, and uncertain
commit acknowledgements remain explicitly unknown. Full runtime qualification
passes 826 executions; final focused qualification passes 150, without skips.
These edge-entity changes and the benchmark lifecycle179 work are not in the
Helm78 image.


## Durable benchmark candidate qualification (schema 179)

Frozen `1cb1045` passes 2,304 combined fresh-database executions, with eight
explicit gated native/kernel fixture skips. Those fixtures have separate earlier
proof and are not claimed as executed by this suite. Full frontend validation
passes 2,336 tests on Node 24.21.0, plus typecheck and production build. Exact
API/runtime image metadata, native libraries, conntrack and BPF-object checks
pass. A disposable schema178→179 drill preserves existing legacy pending/claimed
rows and uses the exact source legacy claim SQL to prove v2 queued requests
remain unavailable to legacy workers. Repeating migration is a no-op.

Exact-image isolated CNPG/RustFS backup and PITR, restored sessions/configuration/
credentials/audit/fresh login, wrong-key rejection and retained-key recovery pass.
Database-pod restart recovery takes 196 seconds. This remains a single-node,
same-host drill. Evidence: `/tmp/constellation-bench-1cb1045/` and restricted
recovery details `/tmp/constellation-cnpg-test.Utv4zU`.

The separate runner610ad3d image includes the actual kube-bench v0.10.7 executable,
all 204 configuration files and procps required by upstream process checks.
The original limited fixture uncovered missing `/bin/ps`; the corrected image
passes executable and owned-process discovery probes. Its controlled receipt
loss/restart proof resends the original durable result without executing again.
A real API+PostgreSQL16.15+worker fixture additionally queues through authenticated
user HTTP, executes two actual source checks, commits two evidence rows and one
completion audit, and returns the actual request/attempt receipt. Recreating all
three processes with owned persistent volumes preserves exact receipts, evidence
timestamps and audit counts; a deliberately missing executable on the restarted
worker verifies no rerun. The old signed user session also survives API restart.
All owned containers/volumes/network are removed. Evidence:
`/tmp/constellation-bench-real-e2e/evidence/summary.json`.

The report contains one PASS and one FAIL, not an all-clean result. No host PID
namespace or host filesystem was exposed. This proves limited container checks
and restart persistence, not host/fleet coverage, backup restoration of the new
execution ledger or disconnected operation. The benchmark worker remains disabled
in the main deployment. Authenticated main-site browser smoke is currently limited
by a stored bootstrap credential returning401; no account reset was attempted.


Helm79/schema179 deploys API/runtime-agent/migrate/frontend from frozen1cb1045
following a completed fresh main-cluster backup. Seven deployments and the
runtime DaemonSet are ready. Live health/readiness, v2 scoped bundles and exact
response-queue boundaries pass; the bundle and queue are empty. Process/native
enforcement and benchmark workers remain disabled. Public login preserves
Constellation/by AlphaBravo and hides unconfigured SSO. The later procps and
application-ID source fixes are qualified separately and are not deployed as a
worker or added to the frozen API artifact.


## Unsigned threat identifiers (schema 180 candidate)

The candidate preserves the native uint32 range through threat/flow ingestion,
rollups, reads, CSV and UI. The database uses BIGINT with bounds 0..4294967295;
new runtime records still reject ID zero. Policy generation excludes every
nonzero threat signature. Existing wrapped negative IDs are decoded exactly.
Historical nonnegative rollup maxima, including zero, may have hidden larger
unsigned IDs. They remain explicitly incomplete unless retained raw rows prove
the entire organization/cluster/tuple bucket at the locked watermark and retention
fence. Migration repairs metadata only; traffic counters remain unchanged.
Late folds preserve uncertainty; a complete rebuild can restore completeness.
Map and conversation rows disclose an unproven maximum locally, with the full
matching incomplete count available in existing Details. Incomplete maxima sort
last in both directions. This adds no page-wide explanatory banner.

Frozen qualification passes 46 fresh-PostgreSQL race/shuffle executions without
skips, 101 focused Node24 frontend tests, whole-project TypeScript checking and
Go compilation. Scoped configured lint removes six G115 findings and adds none.
Evidence: `/tmp/threat180-manifest.json`, `/tmp/threat180-frozen-db/integration.json`
and `/tmp/threat180-release-notes.json`. These are candidate results, not a
schema180 deployment claim.

This migration requires a controlled stop/replace of all old API readers/writers.
Do not use mixed old int32 readers with new unsigned writes. Before migration,
measure table/index sizes, free space, lock timeout and maintenance duration;
qualify a backup and review the affected historical cohort. Stop old readers and
writers, migrate, start only compatible binaries and verify boundary reads and
ingests before reopening traffic. ALTER TYPE can rewrite retained tables and
requires exclusive locks. Prefer roll-forward. Down refuses high IDs or
incomplete history before changing data/schema; reverting old binaries requires
a qualified restore or a separately reviewed compatibility migration.


## Runtime80 and subsequent bounded fixes

Helm80 deploys exact runtime950ca77 with redirect refusal, after 582 full-runtime
fresh179 passes and four explicit opt-in skips. Native/BPF dependencies are
unchanged. Chart8beefb4 persists the existing execution dry-run flag; main process,
file, exec, native and DLP enforcement remain false. API/migration/frontend stay
on1cb1045/schema179. OCI index, platform manifest and config digests are verified
separately; Docker's containerd image store reports an index as image ID. Initial
cache validation incorrectly compared it with a config digest and stopped before
deployment. The corrected exact-chain guard passes. Two unchanged ephemeral-job
images had been evicted; exact prior bootstrap/migrate artifacts were reimported.
Deployment evidence: `/tmp/constellation-upload-950ca77/`.

Schema180 exact5b82b12 broader qualification passes 2,930 fresh-database executions
without skips and 2,344 frontend tests. Full-chain179→180 preservation and guarded
downgrade proof passes, as do exact API/migration/frontend image checks. The fresh
main backup is complete. Enhanced exact-image CNPG scheduled backup/PITR and
201-second PostgreSQL pod restart preserve exact high unsigned threat IDs and
incomplete aggregate metadata, alongside session/configuration/credentials/audit
and wrong-key checks. Main schema180 deployment completed at Helm81; isolated
namespace and owned PV cleanup completed normally. This does not qualify HA, off-host
recovery or node loss. Evidence: `cnpg-recovery-summary.json` under the candidate
evidence directory.

PCAP private-file and serialized completion source68e75a6 passes64 focused179
executions. Source638ca7e rejects status-only completion and receipt downgrades;
verified downloads require matching private bytes, size and SHA256. Its62 focused
180 executions and6 API-contract executions pass. Full runtime qualification
passes890 executions without skips. Actual isolated RWO PVC proof retains an
identical synthetic capture and private permissions through API replacement,
with the same PVC and authenticated session. No main durable storage enablement,
real traffic capture, RWX or node-loss acceptance is claimed. Evidence:
`/tmp/pcap-pvc-proof/result.json`. Failed or unknown
commit can retain a private complete orphan, without reporting success.

Flannel actual-packet acceptance is currently failed: native named allow works,
but unmatched monitor traffic enters unknown-peer temporary OPEN. The fixture
records queue/server/native evidence and cleans all owned resources. It does not
claim protect-mode or full CNI acceptance. The canonical plan records the exact
immutable failure evidence and bounded production-fix work.


Helm81/schema180 controlled replacement uses API/migrate/frontend5b82b12 and
unchanged runtime950ca77. All regular/hook image graphs were checked; five exact
helper images have verified CRI pins with prior labels retained. A cache script
path-construction error stopped before image/API changes and was corrected with
an execution-path regression. After successful migration/Helm, a verifier counted
an old terminal frontend Pod and held API0. Root verified exact deployment
UID/template, current ReplicaSet ownership and OCI identities, then restored the
qualified API. Seven deployments/runtime are ready; live health, tenant queue
checks and public frontend bytes pass. Main retains 838 incomplete rollup maxima.
No old-image/schema rollback occurred. Evidence:
`/tmp/constellation-threat180-rollout-5b82b12/`.

Native6a8057c terminal defaults preserve endpoint/direction/RID0 and explicit rule
precedence, with a 65,536 expanded-row limit before allocation/IPC. Controlled
full-wrapper proof passes70 assertions twice; agent/DP tests pass796 executions
and the two DB-gated replay cases pass separately on fresh180. Real Flannel proof
remains pending. Main enforcement remains disabled.

PCAP retention metadata was not wired to a background sweeper. Main durable
storage enablement awaits bounded fair cleanup and explicit shared-root guards;
local-path capacity requests are not quotas. No existing main capture records or
files were found in the read-only preflight; recheck before changing storage.


Additional source qualification through7d54c3d (not yet main-deployed): SAML
RelayState query encoding passes188 auth executions and unpatched injection
negative controls. The G710 annotation is limited to the reviewed metadata-bound
IdP redirect; no scanner-wide exclusion is used. Federation environment-token
binding passes34 fresh180 plus28 focused executions, including an actual hostile
TLS receiver and explicit-token control. Harbor/GitLab bounded response reading
passes90 executions and rejects read/close failures and secret-bearing invalid
request errors. Follow-up b862c65 covers twelve remaining enumeration/authentication reads:
240 race/shuffle executions pass without skips, 48 unpatched negative controls
fail, and scoped registry lint drops 30→19 without additions. Existing best-effort
GitLab tags/JFrog repository fallback remains explicit.

Retained capture cleanup is now chart-gated/default-off, pinned to a verified
single/shared durable root and fair across failed/locked receipts. Its88 focused
fresh180/21 chart checks pass. Broad8e runtime/server qualification exposed a
shared GroupEdge port-slice race (1345pass/1fail/0skip). Defensive copy5328083
passes the original failing regression and ten race repetitions of netpolicy;
combined `7d54c3d` full qualification passes 2,926 fresh180 executions without
skips. Exact image `7d54c3d` passes actual PVC replacement and leader-driven expiry:
the same capture/hash/session and 0700/0600 permissions survive replacement; the
elected minute-loop removes two expired receipts/file while unexpired bytes
survive. All owned fixture namespace/PVC/PV/tunnels are removed. Main rollout
is still pending; no real capture/RWX/node-loss claim.

The first exact6a Flannel run passes all four monitor probes but fails at the
first protect-a named-allow probe because fresh native evidence is missing. A
subsequent diagnostic-only run passes all 24 strict packet probes. Its Python
verifier initially rejects base64 native MAC versus colon-form endpoint encoding;
b4fb38d compares the exact six bytes. Independent revalidation of unchanged
evidence passes five denied/19 server observations/16 fresh native verdict probes.
Negative controls still reject foreign/malformed MAC, stale verdict and scope/
queue/server mismatches. Original failures remain sealed; all owned resources
are removed. Single-node disposable Flannel only; no other CNI/BPF/HA/node-loss
claim or assertion about the cause of the earlier missing event.

Hosted f309982 run `39016297844` reports 172 gosec findings. Quality stops before
lint because chart tests lack declared PyYAML. Source `e4a8d7f` declares PyYAML 6.0.3
and Helm 3.21.0, with dependency audit. All 110 tooling tests pass in an isolated
local Python 3.14.4 environment. Hosted run `39016927220` then passes pinned 3.12.14
tooling, endpoint/plan, format, shell and workflow checks. Lint reports 1,515 and
gosec 172; those blocking gates remain failed.

SAML browser-cookie G124 findings are narrowly annotated: the IdP returns through
a cross-site HTTP-POST, requiring SameSite=None on the Secure/HttpOnly five-minute
single-use binding cookie and its deletion response. Existing nonce/expiry/replay/
cookie/session tests pass 34 fresh180 executions without skips; scoped G124 scan
reports zero findings. An initial run against the default pre-existing local test
database failed session issuance; it is retained as failed environment evidence,
not used for qualification. No cookie behavior or scanner-wide policy changed.

A local-only history-remediation candidate for source `e4a8d7f` is frozen at
`/tmp/constellation-history-local-20261017-3115588e/frozen-manifest.json`.
Eight synthetic parser/Git tests and every-commit preservation checks pass:
585 commits and 44 local refs retain all non-secret content, modes, authors,
committers, messages and parent order. Four exact credential-bearing blobs are
redacted, and one invalidated historical signature is explicitly removed while
its original remains in a separate private backup. All 14,016 candidate objects
contain zero original key/JWT/base64 matches; the four original blob IDs are absent.
Full unchanged gitleaks still exits 1 with 19 classified findings (nine previously
reviewed, six local-history benign variants, four redacted-placeholder/public-cert
contexts). This is not a green gate. No current checkout/ref, published history,
certificate trust or external JWT state is changed; later commits require a new
candidate before any reviewed publication decision.

## Session controls, snapshot privacy and native accounting

Source `5b417c0` additionally rejects incomplete, oversized, malformed or null
session-control responses and preserves the applied weak-TLS setting when the
server omits it. Explicit true/false still apply. Seventy repeated race-test
executions pass without skips; eight unpatched negative-control executions fail
as expected. Runtime package lint remains 107 findings with none added; existing
upload-loop complexity decreases from 31 to 30. This is not yet deployed.

Source `16956f6` makes quarantine snapshot output private and atomic through the
shared securefiles streaming writer. Producer, sync, stat, close and publication
errors propagate; root substitution cannot return a misleading artifact path.
Forty-two core and 176 fresh180 consumer executions pass without skips; scoped
lint falls from ten to four with none added. Restore and best-effort collection
semantics remain unchanged. Snapshot collection is currently a library path,
not an active production integration.

Source `faf627d` initializes the actual native connection lookup key and sets its
application identifier before lookup. The reporter regression passes 97 assertions
under both standard and deterministic initialization flags; the unpatched control
reproduces duplicate connection buckets. Existing matcher assertions pass 70×2.
Declared vendor patches and sync/restore handling now have 14 shell/Python tests.
The initial native proof explicitly reused seven verified objects; a full native
rebuild is in progress and no new runtime image is deployed. Evidence manifests:
`/tmp/constellation-native-connect-package6a8057c/review-manifest.json`,
`/tmp/constellation-quarantine-private-1304c6f/frozen-manifest.json` and
`/tmp/constellation-session-control-review/qualification-summary.json`.

Hosted `39016927220` has completed: unit/integration, browser, frontend, FIPS
and all dependency checks pass. Quality, gosec and historical gitleaks remain
blocking failures. No broad scanner exclusion or lowered threshold was added.

## Combined runtime qualification and retained capture storage

Source `fcfe91b` also fixes the server side of session controls: an operational
threat-setting read error returns a categorical 500 before consuming pending
kills, while the committed snapshot remains retryable. Missing settings still
deliberately default false. The full network package passes 214 fresh180 repeated
race tests without skips; the unpatched permission-denied fixture fails twice
with a false-disable response and lost pending command. Scoped lint adds nothing.

Combined exact `5b417c0` passes 3,700 fresh180 repeated race executions with zero
failures. Four explicit harness skips remain: native-generator and isolated
Flannel tests, each twice. They are not excluded or counted as packet proof.
The separate canonical full native rebuild at `faf627d` passes all matcher and
reporter assertions without object reuse. A canonical optimized production DP
build at `5b417c0` compiles 51 C units; all 23 linked runtime dependency files
match the qualified base byte-for-byte. New agent/native binaries are assembled
with unchanged BPF/base layers and verified hashes/modes in candidate
`controls-20261017-5b417c0-r2`; its actual packet acceptance fails as detailed below.
An initial private assembly had agent mode0700 from the host umask; its image is
preserved and explicit0755 COPY fixes the candidate. Neither image is deployed.
Evidence: `/tmp/constellation-combined-5b417c0-db/evidence-manifest.json`,
`/tmp/constellation-native-full-faf627d/review-manifest.json`,
`/tmp/constellation-native-prod-5b417c0/review-manifest.json` and
`/tmp/constellation-runtime-combined-5b417c0/image-manifest.json`.

The combined runtime's first isolated attempt stopped before traffic because an
inner test still pinned the previous image. A second attempt corrected only two
test image literals and retained every strict acceptance condition. Four baseline
and four Monitor probes pass, including four fresh native verdicts. The first
Protect allow reaches the expected server and advances its queue from 20 to 30,
but no fresh matching native verdict arrives within 35 seconds. Acceptance fails;
Protect and denial behavior are unqualified for this image. The cause remains
under investigation. All nine owned resources are verified absent; both failed
runs remain preserved. This does not invalidate or extend the separate earlier
24-probe proof for `6a8057c`. Current failure evidence:
`/tmp/constellation-flannel-policy-controls5b417c0-attempt2/actual-packet-evidence-manifest.json`
(SHA256 `0cd69c8d0dbd6a9d7368963e2c2238075a9b537793ee2c4bef451c77701e0615`).

Main is now **Helm82/schema180**, with API source `7d54c3d` on its retained
RWO capture volume and leader-driven retention enabled. Runtime remains
`950ca77`; migration/frontend remain `5b82b12`; other roles and hooks are unchanged.
The fresh CNPG backup completed at 08:56:55 UTC before the controlled API replacement.
Exact API/CLI binaries, volume identity and Retain policy, 0700 capture permissions,
new leader ownership, health/readiness and protocol/tenant boundary reads pass.
Live queues are empty, so positive execution remains separate fixture evidence.
The 2Gi local-path request is not a quota; real traffic capture, node loss and
off-host recovery are not established by this rollout.

The initial storage attempt stopped before API shutdown because admission
rejected the provisioner helper's stale scan. A reviewed single-operation helper
used the deployed API's official target upsert and atomic audit transaction to
queue the exact immutable image, without impersonating a user or altering policy.
Its disposable schema180 checks pass 22 repeated race executions plus seven
wrapper guards. The real scanner completed at 09:25:00 UTC: exact digest and
linux/amd64, successful Syft/Trivy/Grype, one busybox 1.37.0 package, two medium
and four low findings, none with fixes. The original PVC then actually bound
under the unchanged policy. Recovery preserved the failed receipt and exact
resource identities. A second check stopped on an inherited setgid bit; clearing
only that bit changed the same empty directory from 2700 to 0700. The verified PV
was set to Retain and only the owned bootstrap Pod removed before the upgrade.
Original failures, scan results and successful deployment are sealed in
`/tmp/constellation-pcap-main-7d54c3d/evidence/deployment-manifest.json`
(SHA256 `eeaf02b7d276c9c0679fca7151a557e6628cbdfafa638bb11753adefe81f9f13`).

Source `4e5b62c` makes API/scheduled backup filenames unique to their existing job
IDs and publishes completed private archives atomically. CLI output paths and
regular-file overwrite remain supported without changing caller directory modes.
Explicit directory configuration failures no longer silently fall back. Legacy
external download paths remain usable with checked file identity and safe headers;
retention preserves artifacts referenced by another catalog row, including foreign
or null-owned rows. This does not provide a filesystem/database transaction,
repair old overwritten files, or fix the separate CLI S3 naming paths.

Backup qualification passes 366 fresh180 repeated race executions with no test
skips, plus 32 preparation unit executions. Both CLI consumers compile; the
standalone backup command has no test files. Original writer and scheduler
negative controls each fail twice as expected. Vet passes; scoped lint decreases
447 to 443 with no new findings. One test-only G306 annotation deliberately keeps
an existing 0644 hardlink fixture to prove private replacement without changing
the original. No production suppression or scanner configuration changed. These
backup and later session-server fixes are not in the deployed `7d54c3d` image.
Evidence: `/tmp/constellation-backup-artifacts-fcfe91b/frozen-manifest.json`
(SHA256 `8223867e0cc9634214d2967c4ed33304802147115bd2743e4d686a0dc0d85f85`).

Hosted `39020011292` at `29a11dd` has completed: unit/integration, browser,
frontend, FIPS and dependency/vulnerability checks pass. Lint1509, gosec166 and
historical gitleaks remain failed. These are blocking results, not a baseline
waiver. No overall parity acceptance row is closed by these bounded corrections.

Source `46df2d6` closes a remaining proxy-header rate-limit bypass. The trusted
socket peer is checked before client-IP resolution; only `X-Forwarded-For` is
used, walking trusted hops from right to left until the first untrusted address.
Client-controlled prefixes, `True-Client-IP` and `X-Real-IP` cannot override that
address. Missing/invalid trusted suffixes and excessive chains retain the socket
address. Explicit federation transport trust is unchanged. Broad private-network
defaults remain a documented compatibility assumption; operators must configure
actual proxy ranges and append or overwrite verified forwarding evidence.

The full server package passes 494 fresh180 repeated race/shuffle executions,
with zero skips. All three spoofing paths defeat the original limiter twice;
the candidate rejects request11 and preserves the caller's request. Vet passes.
Compared with hosted39020011292, scoped server lint decreases74→73 with no added
findings; the remaining73 still fail the unchanged gate. No scanner settings or
production suppressions changed, and this source is not yet deployed. Evidence:
`/tmp/constellation-client-ip-a6b20a2/evidence-manifest.json`
(SHA256 `d6f355dc918af69ee6c9c52365e5078d74a4fd234f3f46330bd929a49d96a14b`).

Hosted `39022267072` at `a6b20a2` has completed. Unit/integration, browser,
frontend, FIPS, dependency and govulncheck jobs pass. Lint1505, gosec 163 and
historical gitleaks remain blocking; the required gate fails. These counts
precede `46df2d6`; they do not qualify later signing or CLI changes.

Source `76c3262` validates backup signing requests before job, audit or artifact
creation. A bounded 64KiB single JSON object rejects malformed/trailing documents,
duplicate or unknown fields, null/non-string modes and unknown enum values.
One-off empty bodies/omitted modes still mean `none`; schedule omission still
means `static-key`. Both workers validate again, preventing an unknown mode from
silently producing an unsigned successful archive. Valid modes with unavailable
signing infrastructure fail asynchronously without publishing an unsigned archive.

Qualification passes 88 unit and 266 selected fresh180 repeated race/shuffle
executions with zero skips, plus vet. Scoped lint remains340 with no added
findings or suppressions. Eight failed original-worker test executions confirm
the prior false-success behavior; the initial unused-import compilation failure
is preserved separately. All three owned database fixtures are verified removed.
This source is not yet deployed; CLI flag/transport work remains separate.
Evidence: `/tmp/constellation-backup-signing-4e5b62c/evidence/frozen-manifest.json`
(SHA256 `3b12d66aa6e9f45533f9f1c2cb54c93b4945fa426ccdd5c3e6e8bb8822fe680d`).

The strict diagnostic run of the unchanged `5b417c0` runtime candidate records
18 probes, of which 17 complete all criteria (13 fresh native verdicts and four
qualified denials); it does not pass the required 24 probes. Probe18 reaches the
exact server endpoint and advances its queue46→56. Its post-cursor native Allow
record has the expected endpoint, IPs, TCP port18081, application1001 and RID11,
but reports FirstSeenAt/LastSeenAt1792232195 against StartedAt1792232196. A later
end record repeats that timestamp. Raw receipt times prove the report arrived;
the freshness predicate, rather than missing export, rejects this observed case.
The native coarse clock is a supported cause of this one-second discrepancy;
causes of prior runs without raw records remain unproven. The diagnostic leaves
the strict matcher, 35-second deadline and 24-probe matrix unchanged. All nine
owned fixture resources are absent. Root verification matches all 76 evidence
sizes/hashes. No runtime rollout or acceptance row follows from this failed run.
Evidence:
`/tmp/constellation-flannel-policy-clock-diagnostic5b417c0/actual-packet-evidence-manifest.json`
(SHA256 `2c5828967f4d96c1c3040bb117caf5ea626152134bc690b92d3989737ac77b2e`).

The additive OpenAPI correction `f3cc8c5` documents the signing contract and
actual one-off202 asynchronous receipt / schedule200 response. Static checks
cover 48 positive/negative instances, 891 local references and unchanged other
operations/existing schemas. Hosted run 39024761342 at ef0d7a9 also passes
TestGenerateOpenAPI, TestOpenAPICompleteness and TestOpenAPINoNewStubs. This
qualifies the contract checks, not deployment. Static evidence:
`/tmp/constellation-backup-signing-contract-76c3262.l30cb6p5/evidence/frozen-manifest.json`
(SHA256 `9b1d26bdb72e3fc6affe830528c9388e5b5ba5c0a74341b0a7e7c024312f77c7`).

Hosted `39024761342` at `ef0d7a9` has completed: Go unit/integration, browser,
FIPS, dependency and govulncheck jobs pass. Frontend fails one timing-sensitive
compliance sorting test; quality reports 1504 findings, gosec 163, and historical
gitleaks remains failed. The required gate fails; no thresholds or exits changed.
Completed CI and the bound OpenAPI/lint/security checkpoint are recorded in
`/tmp/security-triage-39024761342/completed-manifest.json`
(SHA256 `c6fe1fa6ae88aae26fb8dd0984de7ae14c39c32799a24e9d22aef38e06a7c99c`).

Test-only correction `730e531` holds the sort response until the loading state is
observed, then waits for the rendered ascending header before asserting history
navigation. This removes the request-versus-render race while retaining server
sorting and row assertions. All 15 focused tests and all 2344 frontend tests across
158 files pass on Node 24.21.0. The other 598 frontend blobs match ef0d7a9; no product
code or warning suppression changed. This local result does not rewrite the
failed hosted run. Evidence:
`/tmp/constellation-compliance-sort-ef0d7a9/evidence-manifest.json`
(SHA256 `f84cd7428cdc606fe8350c721aeed32c30bec112878359d322dd0305aa71aa29`).

Source `be15c7c` requires complete discovery/token HTTP responses before OIDC
identity acceptance. Decoded bodies are capped at 1 MiB; read and Close errors,
invalid documents and unsuccessful provider responses produce categorical
errors. The browser callback returns 401 without provider response/URL details.
Normal signature, issuer/audience, nonce, PKCE, roles and valid-session behavior
remain; JWKS response policy and provider redirects are separate unchanged work.

Qualification passes 482 fresh180 repeated race/shuffle test executions without
skips, plus 78 focused unit executions and vet. Scoped lint decreases 333→331 with
no added findings or suppressions. Original signed-token controls fail eight
expected executions; malformed-token controls still reject. Ten original browser
failures include four concrete truncated/oversized response cases that issued a
303 response, one session and two cookies. The candidate rejects those responses
without issuing sessions/cookies and records the failure audit. Both owned
PostgreSQL fixtures are absent. This source is committed but not deployed.
Evidence: `/tmp/constellation-oidc-response-ef0d7a9/evidence/frozen-manifest.json`
(SHA256 `b95a28d4c62fe3e1b6138d701a09cc357616ed275e7c73581e7edf64395c088c`).

Source `7d51fa8` completes the CLI artifact boundary: job-unique S3 names, private
workspaces, checked completion/catalog receipts, pinned upload files and strict
signing flags. pg_dump receives a private libpq service profile instead of a DSN
in its arguments; password remains in the child environment. Bounded complete
service reads reject a valid truncated prefix before it can choose a target.
Help/parse failures no longer expose inherited database/endpoint defaults.
Signature inspection caps all decompressed bytes at 512 MiB, including framing and
trailing data, and validates the gzip trailer. Actual S3 service acceptance and
full disaster recovery remain unqualified.

The original CLI snapshot passes 208 top-level /402 including-subtest fresh180
race/shuffle executions without skips, vet and builds. A network-none real PG16
fixture checks URI/keyword/multihost export, authentication/TLS failures, private
modes, redaction and readable dump contents; eight owned containers are absent.
The two-file bounded-reader follow-up separately passes 30 standalone repeated
race/shuffle executions, tagged vet, a fresh build and actual help. Its negative
control reproduces the exact original valid-prefix/omitted-target failure.
The original full DB/PG16 proof is retained as ancestor evidence, not relabelled
as an exact-source follow-up integration run. Scoped original lint decreases
48→42; follow-up standalone lint remains6. Reviewed new gosec findings remain
open, with no production suppression or gate waiver. No main rollout occurred.
Combined source/evidence seal:
`/tmp/constellation-backup-cli-service-bound/FINAL-SEAL.json`
(SHA256 `b1859c18e464706cf9a3563c09f4f0d51a9aba273c546f8adfb1b85a619c99ab`).

Source `0f33141` makes standalone scanner output truthful: --sarif writes the
shared SARIF 2.1.0 representation, and JSON/SARIF publication must finish before
scan completion is logged. Output flags require --ref; conflicting destinations
are rejected. The existing pinned-root private atomic writer preserves prior
reports on encoding/write/cancellation failure. Parents must already exist and
retain their permissions; publication is per file, so an earlier complete report
remains when a later output fails.

The scanner, shared writer and SARIF packages pass204 repeated race/shuffle test
executions with no skips. Vet passes. Scoped lint 44→43 removes the permissive
output-file finding; existing main statement complexity moves 67→68 and nested
complexity 7→6. No new issue location remains. One test-only G204 annotation
explains execution of the current os.Executable test binary with fixed arguments;
no production suppression was added. Original lint attempts are retained.
The source is committed but not deployed. Evidence:
`/tmp/constellation-scanner-output-ef0d7a9/evidence-manifest.json`
(SHA256 `f2e3da18c458a0c7c64e4074a8a5cb2798ad7f4d99bc5aed79d781a5a0541a15`).

Source `ad0a3a1` uses checked wall time for native connection reports while
preserving the existing coarse timer used for expiry and rate accounting. The
reported timestamp subtracts the existing Idle duration; nonzero Idle remains
an approximation of historical last activity. Failed, negative, overflowing or
underflowing time values are rejected before connection-map/counter mutation.
The strict packet matcher, 35-second deadline and 24-probe matrix are unchanged.

Fresh native tests pass both reporter variants with 97 existing plus 66 new
assertions each. Reversing the clock patch reproduces the exact one-second
mismatch; the existing application-key negative remains. The generator and two
race/shuffle parser/matcher executions pass without skips, including 70 matcher
assertions per execution. Seven vendor-sync tests pass, and the imported shell
scripts pass ShellCheck. The normal production daemon compiles all 51 C units
with canonical -Os flags, required libraries/rpath and no test time wrapper.
Its 23 linked library hashes and package inventory match the qualified parent.
DP SHA256: `e00f06c52439f109c8e95c225eec94e94766b643ff1b697124c6a14934a84eb3`.

Qualification preserves the failed builder-format preflight, raw-index FROM
attempt and subsequent make failure. The production recipe was corrected to
use the locally verified tag, canonical serial make without command-line linker
overrides, and visible compiler failures. The hidden make error from the earlier
attempt remains unproven; the final corrected build and verification pass.
Evidence binds the ten-file overlay on f3cc8c5 through local-only synthetic
snapshot e0e3fa775a59; it is not a published release identity. The new integrated
Go runtime and strict packet run are still required before runtime rollout.
Final 90-file evidence seal:
`/tmp/constellation-native-report-clock-f3cc8c5/qualification-final-evidence-manifest.json`
(SHA256 `3ef9ba77742f7289e550d9913397b4b15c98331abecc261a0fb86406339e7a87`).

Hosted `39026348360` at `c309a21` completes frontend (2344 tests/158 files),
browser (279 cases), Go unit/integration, FIPS, dependency audits and govulncheck
successfully. Unit/integration report 732/14 skips. Quality remains1504, gosec163
and redacted historical gitleaks11; the required gate fails. Formatting, shell
lint, actionlint, tooling, endpoint mapping and parity-plan checks pass. Normalized
lint identities match the prior ef0d7a9 run. This qualifies the sorting-test
correction without changing the previous failed result; later backend commits
are outside this hosted run. All22 evidence artifacts are independently verified:
`/tmp/security-triage-39026348360/completed-manifest.json`
(SHA256 `174ab5baf6da151fa1496382c256747a4d7e66f759d3c63fa54356b30cf6ebd8`).

Combined exact source `314afad` passes 4586 fresh180 repeated race/shuffle test
executions across14 packages, with zero failures and four explicit opt-in skips
(native fixture generator and Flannel acceptance, twice each). Both migrations
and seeding complete; all2596 tracked source blobs remain unchanged and the
owned PostgreSQL container is absent. This includes the final bounded-service
backup CLI source together with OIDC, scanner, backup, server and runtime changes.

The first launcher incorrectly inherited umask077, producing four permission
fixture failures before being stopped with exit143. Those results are preserved.
The two affected tests pass four executions with child umask022, then the entire
combined run passes with that same mask. No product change or weakened assertion
was needed; evidence remains private. This is combined backend qualification,
not strict packet acceptance or deployment. Evidence:
`/tmp/constellation-integrated-314afad/combined-db-evidence-manifest.json`
(SHA256 `024399a77d511e9f94136c81c6db78c8d76140a887ce2b53f23c4258f81cc760`).

Exact `314afad` now has five fresh Go1.26.9 linux/amd64 binaries and three
qualified local image assemblies (API/CLI, scanner and runtime). The runtime
packages the fresh integrated Go agent and the normal production DP above;
all95 native vendor files match the qualified source. Base layers/configuration
and BPF remain verified. Images pass nonroot payload readability and0755 modes;
API/CLI/scanner also execute --help successfully. The runtime has no CLI help
mode; that extra smoke invocation timed out and was removed, with no runtime
help pass claimed. This was local artifact assembly over qualified bases, not
a fresh full Docker/native/BPF pipeline rebuild. The52-artifact image seal is
`/tmp/constellation-integrated-314afad/image-qualification-manifest.json`
(SHA256 `8bdc02411d6cff62b667e2c1ac95750a86d46c29f416ed1066bb9abbe052b717`).

The actual strict Flannel run on runtime index9df9ce866d0d passes all24 probes:
five denied,19 server observations and16 fresh native verdict checks, including
policy changes and DP-stopped bypass. Independent verification uses the unchanged
matcher/deadline/matrix and byte-identical actual inputs. All26 raw post-cursor
records remain available; every accepted native payload appears in that capture
and has FirstSeenAt equal to the probe start, including the previously failing
change-a/server-a/18081 case. Nonzero Idle remains an approximation outside
these observed cases. All23 actual linked-library hashes match the qualified
production build. All nine owned resources are absent by recorded identities;
all250 artifacts from four previous failed runs remain unchanged. This qualifies
the disposable single-node Flannel fixture, not BPF, other CNIs, off-host recovery,
real node failure or main-cluster enforcement. Main rollout remains separate.
The119-artifact completed seal is
`/tmp/constellation-flannel-policy-clock314afad/actual-packet-evidence-manifest.json`
(SHA256 `a524f229aefd20ed7d54fb4be81055b8cad119ac394a6b37bf26222a9d225327`).

Hosted `39028433987` at exact `314afad` is completed. Frontend passes2344 tests
across158 files; browser passes279 cases. Go unit/integration, FIPS, govulncheck
and all dependency jobs pass. Gotestsum reports3642 unit tests including737 skips
and8302 integration tests including14 skips; these totals are not zero-skip
qualification. Configured lint decreases1504→1495 and standalone gosec163→156;
historical gitleaks and the required gate still fail. Four added standalone
occurrences remain at reviewed CLI local-file/subprocess boundaries; the net
decrease does not imply no added findings. Previous checkpoints and report/ZIP
hashes are preserved. No gate waiver or overall release-complete claim follows.
Completed evidence:
`/tmp/security-triage-39028433987/COMPLETED-MANIFEST.json`
(SHA256 `7731efd3a798b8fed77c90092b6e3eeb69b89d373eca33eb681ad8193aecf889`).


### Main deployment of the qualified 314afad candidate

Main development now runs **Helm 83 / schema 180**. API, scanner and runtime-agent
use exact source `314afad`; the API image also contains its qualified CLI.
Migration/frontend remain at `5b82b12`. A fresh CNPG plugin backup completed at
2026-10-17 11:56:36 UTC before the normal Helm upgrade. All three candidate images
were imported and pinned by exact OCI identity, preserving every existing pin.
The reviewed render changes only those three images and the API migration-wait
init image. Normal migration/bootstrap hooks completed; all seven deployments
and the runtime DaemonSet are ready.

Live checks verify all six Go/native/BPF payload hashes, health/readiness 200,
protocol-v2 policy reads, legacy 426, unknown-cluster 404, anonymous 401,
foreign-cluster 403 and duplicate-node 400. The live policy and response queues
are empty; positive enforcement remains the separate strict Flannel fixture.
The original retained PCAP PVC/PV, private 0700:10001:10001 directory, Recreate
strategy and new API leader ownership are preserved. Enforcement remains off,
execution dry-run true and benchmark workers off. Public browser login shows
“Constellation” / “by AlphaBravo”, email/password and no unconfigured SSO option.
Authenticated browser navigation remains unverified without a user session;
preview preload diagnostics and unauthenticated 401 responses are retained.

The initial read-only payload wrapper used `runtime` where the rollout receipt
uses `runtimeAgent`; its KeyError is preserved. The corrected role mapping passes
all payload checks. No workload or acceptance change was needed. The frozen
preparation README describes its earlier unexecuted state; the completed phase
receipts and deployment status supersede it. Evidence binds 135 files:
`/tmp/constellation-rollout-314afad/deployment-evidence-manifest.json`
(SHA256 `c50be2f8a698f1dacadb17bb9811187973c6b032e0696eacafd4a977b732cd29`).

This rollout includes the previously source-only API, OIDC, proxy, backup,
signing, scanner and native report-clock fixes through 314afad. It does not deploy
the separately built standalone backup binary or the later private registry/spool
preparations. Hosted quality 1,495, gosec 156 and historical gitleaks still block the
required gate. Overall acceptance remains 66 checked / 87 open; broader CNI, HA,
disconnected and recovery boundaries remain unchanged.


### Telemetry spool ownership and lifecycle qualification

The disk queue now pins its private directory and checks directory/lock identity.
A lifetime directory-inode flock closes the reviewed in-flight lock-file
replacement race; the existing file flock retains ordinary legacy exclusion.
Close serializes with active operations, and closed or identity-lost queues cannot
resume delivery mutations. Atomic private writes retain directory fsync; state
and batch reads reject symlinks and nonregular files. Existing queue metadata and
batch formats remain compatible. This is advisory exclusion among cooperating
updated queues, not protection from privileged writers or an old process ignoring
the directory lock after lock-file replacement.

Final queue/shared-writer qualification passes 60 repeated race/shuffle executions
without skips. Fresh schema-180 runtime callers pass 66 more, including lost-ack
replay; their evidence precedes only production import grouping, whose exact
import set and remaining bytes are unchanged. Both old-behavior controls fail by
intended assertions: four in-flight ownership failures and six closed/root/state
identity failures. Vet passes; scoped configured lint falls from 15 to zero,
without suppressions or configuration changes. The owned database is absent.
Initial lint findings and two Python-only evidence-packaging errors are preserved.
The reviewed final seal binds three source files and 88 evidence files:
`/tmp/constellation-telemetryspool-7831c59/evidence/FINAL-SEAL.json`
(SHA256 `b57feaf1a093bf957af4e8fb7bde1a432ef937b6a9237fa117b67be4bf50ab20`).
This follow-up is included in the combined qualification and deployed 877a1c2
artifact set recorded below. Fleet delivery and overall release acceptance remain
open.


### Registry V2 response completion qualification

Manifest, digest, tag and token responses now require complete bounded reads and
successful closure before exposing successful data. Manifest/tag limits remain
8 MiB / 4 MiB; token responses gain a 1 MiB bound and single-document parsing.
HEAD closes before returning a digest or issuing GET. The missing-digest GET drain
is bounded and checked. Initial challenge retry, child-token reuse, platform
selection order, metadata overlays and partial-repository behavior are preserved.
Redirect/auth-destination policy and broader cloud-provider acceptance are separate.

The full registry package passes 390 repeated race/shuffle executions with zero
skips. Eight old-code regression functions fail by intended assertions. A final
test-only extraction preserves the exact assertions; its two repeated executions
and vet pass, with production and all other tests unchanged. Configured lint falls
from 19 to 11, removing eight targeted diagnostics and adding none; the remaining
cloud-auth/IBM/test findings stay open. The initial test-complexity warning and
its correction remain in evidence. Root independently verified the 85-file seal:
`/tmp/constellation-registry-v2-a274245/FINAL-MANIFEST.json`
(SHA256 `40f78898ac267f3c225279bad1a5a3ff324b89c3f71d8ebdc3808238c4c56da1`).
This follow-up is included in the combined qualification and deployed 877a1c2
artifact set recorded below. No release gate or provider acceptance is waived by
this bounded correction.


### AWS Lambda package download qualification

Lambda package downloads now publish a private file atomically only after bounded
copy, successful response closure, cancellation checks and pinned-directory
identity checks. Failed reads, response closure, overflow or file finalization
preserve a previous complete package and leave no partial first download. The
response is closed exactly once on success and failure paths. Categorized errors
keep presigned URLs and transport credentials out of job summaries while retaining
errors.Is/As causes. Existing size defaults and accepted HTTP statuses remain;
an unrepresentable overflow-check limit fails before dispatch. Redirect policy,
archive extraction and cloud SDK behavior are unchanged.

The final AWS/shared-writer suite passes 112 repeated race/shuffle test executions
with zero skips. Nine public-path old-code functions fail by intended assertions;
the compatibility shim does not replace the old public downloader. Vet passes,
and scoped configured lint falls from nine to six with no new finding signatures
or suppressions. Response-ownership helper changes and test fixture extractions
were followed by the full scoped suite and fresh negative controls. Original
preparation and all attempt logs are preserved. Root independently checked the
62-file seal and all three imported source hashes:
`/tmp/constellation-lambda-download-a557389/evidence/qualified-manifest.json`
(SHA256 `98e78e3c23c118cdc0f4f061362886588a2dd9b82b35ad8c4f96ccb011e10b08`).

This qualifies atomic visibility, not power-loss directory durability. A detected
postpublication directory change may leave a complete artifact while returning
failure, which prevents catalog/report advancement. Tests use injected transports
and no cloud credentials. This follow-up is included in combined qualification
and deployed 877a1c2, recorded below. Broader serverless acceptance and release
gates remain open.


### Cloud registry credential-cache isolation qualification

Shared cloud tokens now require trusted organization and registry identity plus
the effective credentials and authentication target. The two owned-row handler
paths supply that scope; payload credential fields cannot supply it. Direct or
legacy callers without complete scope still authenticate but bypass shared
caching. GCP binds the private key; static ACR binds its client secret; managed
ACR resolves its current identity token before lookup. ECR captures the actual SDK
credentials and uses the same snapshot for minting. Incomplete explicit ECR
credentials fail before ambient or anonymous fallback; fully ambient mode remains
supported. Length-prefixed hashed keys and 256-entry / 8-MiB bounds limit retained
rotations without exposing raw credentials in cache keys.

The full registry ancestor passes 476 repeated race/shuffle executions. Its five
production files are byte-identical to the final candidate; affected test-fixture
cleanup passes 92 repeated executions. Actual connection Test and SyncOnce paths
pass six repeated executions against fresh schema180, proving valid reuse, wrong
and rotated credential handling, sibling organization/registry isolation, ignored
payload scope spoofing and uncached legacy authentication. The corresponding old
caller control records six failure events: four failing workflow executions and
their parent tests. Six direct old-cache regression functions also fail as intended. Vet passes and
configured registry/handler lint remains 332 with identical diagnostic identities.
No skips, suppressions or configuration exceptions were introduced.

Initial test-fixture lint findings and an insufficient old anonymous-fallback
control that attempted reserved .example DNS are retained. Corrected controls
intercept that path; final caller tests terminate cloud traffic at an owned local
proxy. Root verified all 215 sealed records, eleven imported source hashes, full-
suite production lineage and absence of all four owned caller-test databases.
Evidence: `/tmp/constellation-registry-cache-51abb25/FINAL-MANIFEST.json`
(SHA256 `65578c941d2a92a6a766668c271253ef9152aa94afbb8351a66c71ed0f76351a`).

This source qualification does not establish real cloud-credential acceptance.
Combined qualification and deployment of 877a1c2 are recorded below.
ECR AuthToken currently has no non-test repository caller; its exported capability
and the live list/digest credential checks have distinct reachability. Existing
authentication destinations/redirects and broader provider acceptance are unchanged.
The cloud/IBM error-message correction is qualified in the following section.
This correction is included in the deployed 877a1c2 artifact set.


### Cloud registry error redaction qualification

Cloud authentication, IBM registry requests, and Google/Azure catalog failures now
expose a categorical stage and HTTP status without upstream bodies, URLs or parse
values. Wrapped causes remain available through errors.Is/As. Successful responses,
bounds, response closing and cache behavior are unchanged. Real handler tests cover
connection Test, SyncNow, persisted LastSyncError, owning List/Get, foreign-owner
isolation and walker audit records, including successful control requests.

Qualification passes 572 registry and 16 fresh-schema180 handler executions with
race/shuffle/count2 and no skips. Original-code controls produce 22 intended
assertion failures. Vet passes; configured lint remains 332 with no added or
removed diagnostics. Root verified all 77 sealed records, seven imported sources,
unchanged production lineage and absence of all three disposable databases. The
initial test-only compile failure is preserved; its sole correction renamed a
fixture response variable. Evidence:
`/tmp/constellation-registry-errors-376f4b8/evidence/FINAL-SEAL.json`
(SHA256 `aec15eb17c95fb2d860cd10c0d9e328f4f3be11c3f23ba1a7d5fd0ba6fccd221`).

This prevents new disclosures in those paths; it does not rewrite historical audit
or log data. DockerHub/GHCR, other catalog connectors, generic V2/Nexus/OpenShift,
V2 challenge/manifest/tag errors and ECR SDK errors remain separate review work.
Combined qualification, image verification and deployment of this correction in
877a1c2 are recorded below. No release gate is closed here.


### Combined qualification and hosted checks for 877a1c2

Exact source `877a1c2` combines the telemetry ownership, complete registry V2
response, private Lambda download, cloud credential-cache isolation and cloud/IBM
error-redaction fixes above. A fresh owned PostgreSQL 16 database was migrated to
schema 180 twice and seeded. Sixteen packages pass 5,064 repeated race/shuffle test
executions, with zero failures and four explicit native/Flannel opt-in fixture
skips. Vet passes for all sixteen packages. All five Go1.26.9 linux/amd64 binaries
build successfully; all 2,609 frozen source blobs remain unchanged. The owned
database was removed and independently confirmed absent.

Root verified all 48 qualification records and the five binary hashes and modes.
Evidence: `/tmp/constellation-integrated-next-preparation/evidence/combined-qualification-summary.json`
(SHA256 `a2c4f49f61fadd7e7fb2e478ac6042067928c08bd4dcaaa736c677e34333bd9b`).
The qualification manifest is
`/tmp/constellation-integrated-next-preparation/evidence/qualification-evidence-manifest.json`
(SHA256 `a1d5fba6ca32778432cfec1790d8968d60f5ba2460887c2decfa2cf19bf8733d`).

Three images copy only the new Go payloads over the exact qualified 314afad
parents. Parent layers and runtime configuration are preserved apart from reviewed
version labels. Supported nonroot help checks pass; native DP, BPF and 23 native
library hashes and dependency mappings remain unchanged. All thirteen temporary
verification containers are independently absent. This is a verified thin image
assembly, not a fresh native/BPF pipeline build or a new 877 packet acceptance run.
The strict 24-probe Flannel evidence above remains specific to source 314afad.
Assembly receipt:
`/tmp/constellation-images-877a1c2-preparation/execution/ASSEMBLY-RECEIPT.json`
(SHA256 `12ead4cb43276e797b1569a95784d0a1324acc1239e9ccfdead3a1d8f49bb275`).

Hosted [run 39035438259](https://github.com/alphabravo-oss/constellation/actions/runs/39035438259)
completed for exact source 877a1c2: nine jobs pass and four fail. Frontend passes
2,344 tests and browser acceptance passes 279 cases with no failures, retries
classified as flaky, or skips. Go unit records 3,124 passes and 739 skips;
integration records 8,742 passes and fourteen skips. These hosted totals are
separate from the owned-database qualification above. FIPS and dependency and
vulnerability checks pass. Overall CI remains failed: configured lint is 1,469,
standalone gosec 153, historical gitleaks eleven, and the required gate fails.
Normalized comparison against the prior 314afad run removes 26 lint and three
gosec findings with none added; this is not a claim of zero additions against the
original PR baseline. No gate, suppression or configuration was relaxed. Root
verified the completed reports and sealed thirty evidence files:
`/tmp/security-triage-39035438259/COMPLETED-MANIFEST.json`
(SHA256 `8a0733816c3343de5592bab1d8e322b95b0836691cb769b58cf71b4180242a35`).

The separately prepared CIS and remaining catalog-error corrections are outside
this source and artifact set. Real provider credentials, broader enforcement,
other CNIs, HA, disconnected delivery and remaining recovery acceptance are still
open. Off-host recovery and deliberate real-node failure remain deferred. No
parent acceptance checkbox is closed by this qualification.


### Main deployment of the qualified 877a1c2 candidate

Main development now runs **Helm 84 / schema 180**. API, scanner and runtime-agent
use exact source `877a1c2`, including the five follow-ups above. The API image also
contains the matching CLI. Migration and frontend remain on `5b82b12`; the freshly
built standalone backup binary is not part of this workload update.

The normal Helm upgrade followed a new completed CNPG backup (UID
`aa4a7208-4056-4ed6-9ff9-6c94daaad0d3`, completed `2026-10-17T13:56:05Z`). The server
dry-run and installed manifest differ only in the three role images and matching
API init-container image; hook revision names advance normally. All seven
deployments and the runtime DaemonSet are ready. All thirteen image dependencies
and original pins remain verified, with three new image pins added. Six live
payload hashes match the qualified API, CLI, scanner, runtime, native DP and BPF.
The retained PCAP PVC/PV, private directory mode, Recreate strategy and elected
API lease ownership are preserved. Enforcement remains disabled, monitor mode and
execution dry-run remain enabled, and benchmark workers remain disabled.

Post-upgrade health/readiness return 200. Policy protocol 2 succeeds, the unsafe
legacy protocol returns 426, and an unknown cluster returns 404. Response protocol
2 succeeds; anonymous, foreign-cluster and duplicate-node requests return 401,
403 and 400 respectively. Live policy and response queues remain empty, so these
checks do not establish positive enforcement. The exact owned smoke port-forward
was terminated and its process and listener independently confirmed absent.
Public login recheck confirms “Constellation” / “by AlphaBravo” and no SSO button;
authenticated navigation remains unverified without a valid user session.

Root verified 210 deployment evidence files. Evidence:
`/tmp/constellation-rollout-877a1c2-preparation/deployment-evidence-manifest.json`
(SHA256 `05a0e2ca8471ffbfd4f449c35f201052e4510c914fb2ff5d48fb0cc90932f7f6`).
The prepared inputs, failed bytecode-only seal attempt and subsequent reviewed
seal are retained; no cluster mutation occurred during that failed seal attempt.
No quality/security gate or broader acceptance row is closed by this deployment.

### Completed docs-head CI and main binding inventory

Hosted [run 39038892262](https://github.com/alphabravo-oss/constellation/actions/runs/39038892262)
completed for `fed732e` with nine jobs passing and four failing. Frontend passes
2,344 tests and browser acceptance passes 279 cases with no unexpected, flaky or
skipped cases. Go unit records 3,124 passing and 739 skipped test events;
integration records 8,742 passing and fourteen skipped events, including parent
and subtest events. Lint, gosec and gitleaks reports are byte-identical to the
877a1c2 run: 1,469, 153 and eleven findings respectively. The required gate still
fails. Root sealed 31 evidence files in
`/tmp/security-triage-39038892262/COMPLETED-MANIFEST.json`
(SHA256 `dca1319cf262e72d848fe409a2eb8d43f817fa4e03a658aa6a51abf42ff5d5ef`).

The four previously added gosec diagnostics concern backup credential transport
and S3 delivery. They are separate from existing CLI report-file findings; this
distinction does not waive either set of findings.

A read-only transaction on the identity-checked main CNPG installation found
schema 180, zero group DPI bindings, zero orphan or wrong-organization bindings,
and the validated composite group foreign key. No data repair was performed.
Receipt: `/tmp/constellation-main-binding-inventory-fed732e/inventory-review.json`.
This inventory does not establish the state of other installations or close the
broader tenant/cluster acceptance gate.

### Catalog errors at API, status and audit boundaries

The source follow-up to 877a1c2 uses the existing categorical error wrapper for
DockerHub, GHCR, Generic V2, Nexus, OpenShift, Quay, Harbor, GitLab and JFrog
catalog responses. Constant provider/stage labels and HTTP status replace raw
upstream bodies, transport URLs and parser values. Wrapped causes remain
available through `errors.Is`/`errors.As`. Existing bounded reads, close-error
handling, pagination and partial-page behavior are preserved.

The full registry race/shuffle/count-two suite passes 676 test executions.
Fresh schema-180 handler tests pass 46 executions covering catalog failures,
existing cloud-error behavior and credential-cache owner boundaries. The seven
configurable providers exercise actual Test, SyncNow, List/Get, persisted status
and walker audit paths against local TLS fixtures. Fixed-authority DockerHub and
GHCR use injected transports. Original 877a1c2 production fails 100 connector
and 28 handler leaf assertions as intended; there are no build failures or
skipped cases. Including parent failures, these are 104 and thirty failure
events. Both owned PostgreSQL fixtures are independently absent. Scoped vet
passes; configured count-aware lint remains 332 findings with zero additions.

Root verified all seven imported source hashes and 72 qualification records:
`/tmp/constellation-registry-catalog-errors-877a1c2/evidence/FINAL-SEAL.json`
(SHA256 `e695fb3a54dc569389e7bacbcda13d5b41219cd1e5e7c45a6c14a45e9efe40b4`).
This is source qualification only; combined binaries, images and deployment are
pending. ECR SDK and shared V2 scanner errors, live provider credentials and
broader registry acceptance remain outside this bounded correction.

### Complete evidence before a passing CIS result

The CIS follow-up reads module and plain SSH evidence through pinned roots with
bounded bytes, lines, tree entries and depth. A module observed loaded or built
into the running kernel fails. Complete, coherent running-kernel inventory can
establish absence; missing, malformed, unreadable, truncated, symlinked or
otherwise incomplete inventory cannot pass. An available but unloaded module
warns. Blacklist/install text alone does not prove effective disabling. The
conservative tree check can produce more skipped results where module trees
contain symlinks, including build/source links.

SSH checks consume the complete bounded configuration and check read/close
failures before returning a verdict. Plain supported settings retain first-value
semantics; Include, Match and unsupported syntax require review. Incomplete reads
skip. Directory completion accepts only a terminal EOF through a bounded linear
error chain; joined failures and cyclic or excessive wrapping cannot hide behind
EOF. This inspects configuration evidence, not the effective running sshd state.

Final fresh-schema-180 race/shuffle/count-two qualification passes 252 hostscan
and 624 runtime-agent test executions. Both packages pass vet. Four skips are
the two explicit native/Flannel opt-in fixtures repeated twice, not new packet
acceptance. Count-aware configured lint improves from 176 to 172 with zero added
occurrences. The exact owned PostgreSQL fixture is independently absent.

Six original-behavior controls fail as intended (35 failure events and two
passing controls). Injected old module/read helpers preserve original logic but
substitute test IO; this does not claim a natural-host execution of old code.
Earlier 234-pass and 252-pass attempts were rejected for new lint findings and
remain in the evidence. Final-source tests include all corrected EOF controls.
Root verified 119 sealed records and the three imported source hashes:
`/tmp/constellation-cis-evidence-877a1c2/handoff/qualified-manifest.json`
(SHA256 `8b1ec347e94c888a1fa26949297b206e3c307fc3614658d266b421989a145826`),
with `QUALIFIED-SHA256SUMS`
(SHA256 `f180065c690055b0c56fb0882e5534a1b1667d356037905742ad2b3348b21bf6`).
Combined binaries/images and deployment remain pending; benchmark workers remain
disabled on main. No parent CIS or enforcement acceptance item closes here.


### CLI private file publication (2026-10-17, source qualified)

Seven CLI outputs now use the existing atomic file writer through a pinned
parent directory: four image formats, IaC SARIF, policy CRD export and API-token
configuration. Completed files have mode 0600, existing parent modes remain
unchanged, known final symlinks/nonregular destinations are rejected, and a
completed artifact survives a later stdout failure. Parent identity checks detect
observed replacement; they do not lock pathnames. Registration YAML and compliance
export are separate remaining adoptions.

Both affected packages pass 312 race/shuffle/count-two test executions and vet.
Eight database-dependent skips (four identities repeated twice) must execute in
the combined fresh-database qualification. Replaying the seven original writes
compiles and fails the intended four top-level tests with twelve subtest failures.
Configured lint falls from 16 to 10: six G306 findings removed. Raw diagnostic
identity comparison includes the unchanged complexity-52 function rename and
existing CRD complexity improving from 70 to 60; these remain disclosed debt.
No suppressions or lint configuration changes were made.

The reviewed eight-file handoff is
`/tmp/constellation-cli-publication-877a1c2/FINAL-HANDOFF/FINAL-MANIFEST.json`
(SHA256 `50c639ef53fc7dceeee65e2b7c8f5d9337c4b8168bc85f09c8422bb98a589ba0`),
with sixteen verified handoff records. Minimum free space during final stages was
46,774,669,312 bytes on root and 3,059,589,120 bytes on /tmp. Combined database
qualification, binaries, images and deployment remain pending. Main remains on
877a1c2 / Helm revision 84; no parent acceptance item closes here.


### Combined source 414887a qualification and continuation (2026-10-18)

The exact combined catalog/CIS/CLI source passes 3,384 fresh-schema-180
race/shuffle/count-two test executions across eight packages. The database
migrated twice, seeded and was removed; all previously skipped CLI database
cases executed. Only four explicit native/Flannel opt-in fixture events skip.
No new binaries or deployment are claimed for this source. Vet and the final
combined build follow the remaining bounded CLI/registry changes.
Evidence: `/tmp/constellation-integrated-security-followup-preparation/evidence/combined-qualification-summary.json`.

Hosted CI run 39042839041 completed on exact 414887a: nine jobs pass and four
fail (quality, gosec, gitleaks and the aggregate required gate). Unit, integration,
browser, frontend, dependency, govulncheck and FIPS jobs pass. Configured lint
findings decrease from 1,469 to 1,459; raw diagnostic identities include the
previously disclosed complexity-52 rename and CRD complexity 70 to 60. Gosec
findings decrease from 153 to 144 with zero added identities. The gitleaks report
is byte-identical to the previous completed report. These gates remain open.
Completed metadata and the three inspected reports are recorded in
`/tmp/security-triage-39042839041/COMPLETED-REPORT-MANIFEST.json`.

The user selected continued isolated checks; authenticated live browser workflow
acceptance remains unverified. The user reports that use of the historical
admission TLS key outside disposable test clusters is unknown. The prior local
certificate inventory does not establish external non-use. Public history and
external trust remain unchanged, and replacement/revocation scope remains open.


The resumed tooling pass first recovered capacity without clearing the warm Go
cache: 1,188 regenerable module ZIP downloads were removed only where matching
extracted module directories existed; module metadata, hashes and extracted code
remain. Fifteen inactive tool releases were removed after complete hash/identity
verification and a fresh process-reference scan with zero matches. Current and
fallback tool versions remain. These steps reclaim approximately 8.7 GB; no
backup, cluster volume, evidence archive or image was removed. Private receipts
are retained under `/root/constellation-cache-recovery-20261018`.


### Remaining CLI export publication (2026-10-18, source qualified)

The two cluster registration YAML outputs and compliance export now also use
`securefiles.WritePath` with the current command context. Mint/rotate requests
still occur once before file publication; failures do not retry or roll back
those server mutations. Explicit stdout output remains available. Tests prove
private replacement without changing linked originals or parent modes, symlink
rejection, source-failure preservation, cancellation before publication and
completed-file retention when confirmation output fails.

Both affected packages pass 360 race/shuffle/count-two executions and vet. Eight
isolated database skips remain explicit and must execute in final database
qualification. Literal original 414887a production files compile and fail exactly
three intended top-level controls and nine subtests. Scoped lint remains ten
existing findings; its report is byte-identical to the approved baseline.
Root verified all six stage seals and the three imported source hashes.
Evidence: `/root/constellation-cli-residual-publication-414887a-qualification/FINAL-RESULTS.json`
(SHA256 `9ccbd2db6cc07275a3fc0907c473169a5fadf30e55818804252b29e3bb1af6db`).
Final combined qualification, binaries and deployment remain pending.


### ECR and shared V2 diagnostic boundaries (2026-10-18, source qualified)

ECR repository, image and authorization SDK failures now expose constant
operation/category text while preserving typed underlying causes. Missing digest
errors omit supplied references. Shared V2 request, transport, read/close, status
and decode errors omit remote diagnostic values, URLs and authentication headers.
The internal unauthorized error retains its challenge for the existing token
retry; its public message is constant. Unsupported challenge, repository and
platform-selection errors also omit untrusted values. Successful metadata,
authentication, pagination, partial results, complete bounded reads and response
closure behavior are preserved. This does not add SDK body bounds or claim
complete provider acceptance.

The complete registry package passes 768 race/shuffle/count-two executions with
zero failures or skips, and vet. Configured lint remains eleven existing findings
with zero additions/removals. Literal original 414887a production files compile
and fail eight intended top-level tests and 38 subtests (41 leaf assertions):
37 untrusted-value assertions and four missing categorical-context assertions.
Those four are not claimed as demonstrated numeric-value disclosures.
Root verified 75 evidence/input/source records and the four imported hashes.
Handoff: `/root/constellation-ecr-errors-414887a-qualification/handoff/QUALIFIED-RESULTS.json`
(SHA256 `e6483b70cef56c86e5a5578b2a8b15fe21062d1808dc6252a77a0433c498c254`),
seal SHA256 `9250d285431b077f63fe8771a5774c892a9317530b41499f7e07b45fc22c1d67`.
Final combined database qualification, artifacts and deployment remain pending.


### Final combined c5428cc qualification and artifacts (2026-10-18)

Exact source `c5428cc7d8d5928b06f8fcc58c4852a366d88943` combines the
catalog/ECR/shared-V2 diagnostic boundaries, complete bounded CIS evidence and
ten selected CLI private-file outputs. Complete source binding covers 2,619
files; protected module, dependency, native/BPF, migration and chart inputs remain
unchanged from the reviewed baseline.

The final fresh-schema-180 race/shuffle/count-two run passes 3,524 test events
across eight packages, with no failures. Only four explicit native/Flannel opt-in
events skip (two fixture identities repeated twice). All earlier CLI database
skips execute. The owned PostgreSQL fixture migrated twice, seeded and was
independently confirmed absent. All eight packages pass vet. Four CGO-disabled
Linux-amd64 binaries build with mode 0755 and version `security-c5428cc7d8d5`:
API, CLI, scanner and runtime agent. The unchanged standalone backup tool is not
rebuilt or packaged in this batch.

Final qualification evidence:
`/tmp/constellation-integrated-security-final-preparation/FINAL-QUALIFICATION-MANIFEST.json`
(SHA256 `0980f57aac323d64d0cf26fba95be4feb014d51edcdab5dadabffc48f1af8782`,
56 records). Complete source binding SHA256 is
`17eaed187d76ca6355e07d010e8355d987fe125ae2e568a434ca2f31642d47f5`;
the four-binary receipt is
`/tmp/constellation-integrated-security-final-preparation/evidence/binary-build-receipt.json`
(SHA256 `300a1aec3ac7ad608c9b6fbadf62ff0dd1302e0b4b3c280fe7876457cb96e266`).

Three local thin COPY assemblies retain the exact qualified 877a1c2 parent OCI
chains, runtime configuration, layers and inherited history. Four fresh Go
payloads are verified in the images as root-owned mode-0755 executables
readable by uid/gid 10001. API, CLI and scanner help checks pass as that nonroot
user; runtime help is unsupported and was not invoked. Native DP, BPF, all 23
linked-library hashes and their SONAME paths remain unchanged. All thirteen
owned probes pass, and a separate pass of 26 exact-CID/name inspections confirms
their absence. This is thin local assembly proof; the prior isolated packet
acceptance remains its own evidence and no new native/BPF rebuild is claimed.

Assembly evidence:
`/tmp/constellation-images-c5428cc-preparation/ASSEMBLY-EVIDENCE-MANIFEST.json`
(SHA256 `ecc8fec59152c5e253454d3a5aa47e7432792624c4365cf2b6006b7959d67028`,
405 records). Assembly receipt SHA256 is
`c7e7bb256c38e3f9563150ca7b22894de060507326f84a925ac4d14b2a63e442`.
Tags are `constellation/{api,scanner,runtime-agent}:security-20261018-c5428cc`;
OCI version labels match binary version `security-c5428cc7d8d5`.

Three exclusive private Docker-save exports pass exact tag/index/amd64-manifest/
config checks, bounded single-tag tar validation, whole-file hashes and stability
checks. Archives total 853,020,672 bytes under
`/root/constellation-rollout-c5428cc-archives` (directory 0700, files 0600).
All continuous 40-GiB root/Docker and independent 2-GiB /tmp floors held during
assembly and export. The export-end capacity observation satisfies the separate
42-GiB-plus-archive-bytes import threshold; capacity must be freshly rechecked
before import or backup. This observation does not approve deployment.

Export evidence:
`/root/constellation-rollout-c5428cc-archives/EXPORT-EVIDENCE-MANIFEST.json`
(SHA256 `968b9cbee7d11d83d2442a348a7cd090467ac6a5c7d61e1cd7fa6a8b99e6a9ea`,
26 records); export receipt SHA256 is
`a12fd4504261b93258fe50628573fd705fb58d910a6e18f4050c875e9dc6e8a1`.
These artifacts are now deployed as Helm85/schema180 with sourcec5428cc, after
the separately reviewed rollout and live smoke below. No parent parity,
enforcement or infrastructure acceptance item closes here.

### Completed exact c5428cc hosted CI (2026-10-18)

Hosted [run 39139492997](https://github.com/alphabravo-oss/constellation/actions/runs/39139492997)
completed on exact c5428cc with nine successful jobs and four failures: quality,
gosec, gitleaks and the aggregate required gate. Frontend passes 2,344 tests;
browser acceptance passes all 279 cases with zero unexpected, flaky or skipped
cases and no report errors. Go unit records 3,365 passing and 740 skipped test
events; integration records 9,254 passing and fourteen skipped events. These
counts include parent/subtest events; each mode has 99 passing package completions
and 26 empty/skipped package completions. Dependency, govulncheck and FIPS jobs
also pass.

Lint remains 1,459 findings and its report is byte-identical to exact414887a.
Gosec remains 144 findings; complete issue records are identical after ordering
normalization, while report metadata differs. Gitleaks retains eleven identical
result identities after excluding only commit metadata from partial fingerprints;
rule, location, message and properties remain included. No diagnostic occurrence
was added or removed in those comparisons. Existing findings and required CI
remain failing; no finding or threshold was suppressed or waived.

Final run/job metadata, structured test artifacts and comparison evidence are in
`/tmp/security-triage-39139492997/COMPLETED-MANIFEST.json`
(SHA256 `5942d8a0f132848766048c2e86fb7a17bf4b8f86dd87de8ce2a62693960a9639`,
33 records). Original initial metadata/reports remain preserved. Authenticated
main-browser acceptance, historical TLS use outside disposable test clusters and
broader acceptance deferrals remain as recorded above.


### Completed c5428cc deployment (2026-10-18, Helm85/schema180)

The reviewed c5428cc API/scanner/runtime-agent images are deployed through a
normal Helm84-to85 upgrade with unchanged hooks, reuse-values and schema180.
Migration/frontend remain source5b82b12. All seven deployments and the runtime
DaemonSet are ready with the expected specifications. Four live Go binaries
(API/CLI/scanner/runtime), native DP and BPF match their six exact reviewed
payload hashes. API Recreate, original PCAP PVC/PV and Retain policy, evidence
mode0700/uid10001/gid10001, leader lease identity and runtime token ownership are
preserved. Runtime remains monitor-only, process/file/exec/DP/DLP enforcement is
off, execution dry-run is true and benchmark workers remain disabled.

Three exact private archives were imported and their three candidate pins
confirmed while all thirteen existing pins were preserved. A newly created CNPG
backup completed with original UID `7110dd38-e01d-48e4-b26e-4811c53c53a9`:
`constellation-pre-security-c5428cc-20261018-dade0378`, backup ID
`20261018T154438`, stopped `2026-10-18T15:56:17Z`. It completed within one hour
before upgrade. The exact prefix measures 900,423,680 allocated filesystem bytes
and 900,096,430 apparent bytes; these are filesystem aggregates, not S3 object
Content-Length or a maximum future backup-size guarantee.

Owned loopback smoke passes health/readiness200; legacy policy protocol426,
empty v2 policy200 and unknown-cluster404; empty response-v2 queue200,
anonymous401, foreign-cluster403 and duplicate-node400. The positive authorization
checks use the resolved current cluster; empty live queues do not establish
positive live enforcement. The API pod UID is
`13b95346-3a5f-4732-8ac1-9dc1a873294b`. Smoke exits0, and the exact owned forward
PID2456267 is terminated with the port19385 listener independently absent at
`2026-10-18T15:59:12Z`. Frontend is unchanged; no fresh authenticated browser
acceptance is claimed.

The resource monitor retains 99 ten-second samples plus the final observation;
its initial cache-phase samples are partial, so it does not establish continuous
coverage before monitoring began. Observed backup minima are 47,685,992,448 root
bytes and 2,352,189,440 /tmp bytes; upgrade/smoke minima are 47,685,623,808 and
2,352,136,192 bytes. All observed phase-specific42/40-GiB root and2-GiB /tmp
floors hold. Final available bytes are 48,688,906,240 on root and 2,352,136,192 on
/tmp. Owned process/container cleanup and regenerable-cache maintenance retain
separate receipts; no off-host recovery, deliberate node failure or new packet
qualification is claimed.

Root sealed 259 deployment records in
`/tmp/constellation-rollout-c5428cc-preparation/DEPLOYMENT-EVIDENCE-MANIFEST.json`
(SHA256 `55a20f5d7075ffe7208b7d3fac311f5c946ed12c2a29660360016a73931dde62`),
with 260-record `DEPLOYMENT-SHA256SUMS`
(SHA256 `af19f52685a1a352319d631441b80d8fd3b557068cf24c257118a55314d43631`).
Deployment-status SHA256 is
`f4e52622195840c599854123909a8154307a932bdda2afbe1d4d85b4c2324150`;
live-smoke SHA256 is
`2bc05da7294f48fdf9c3be33aa967cc0900a2ca6470b761ac1cb2cb233a84051`.
Quality/security and broader parent acceptance gates remain open.

### Follow-up source and runtime readiness finding

The notifier delayed-retry, backup terminal-status and federation response/error
follow-ups passed the isolated eight-file qualification recorded below. At that
checkpoint they were undeployed; the later combined qualification and Helm 86
deployment are recorded below. The federation correction retains trusted private endpoints,
implicit-token destination binding and redirect refusal. Credential/state
transaction semantics remain unchanged. This source evidence is separate from
the deployed c5428cc evidence.

The separate runtime source audit identified cumulative DP counters satisfying
readiness after process exit or while a replacement awaits its first reply.
The correction was subsequently qualified and deployed in 2b29b63 as recorded
below; this audit did not observe a live outage. Original audit:
`/root/constellation-runtime-readiness-audit-c5428cc/AUDIT.json`
(SHA256 `cd80025441d7f7e531d166021943046a819c2d5e1dd85c55ee06189814891bfc`).
Fresh tap reconciliation and live readiness/enforcement acceptance remain open;
no new checklist row or completion is recorded.


### Qualified notifier, backup and federation follow-ups (2026-10-18)

Eight source files over exact c5428cc passed qualification. Delayed notifier
retries observe parent/dispatcher cancellation, preserve the original enqueue
watermark and report bounded bookkeeping errors. Backup failure finalization uses
an independent bounded context and exact org/id/running-state guards. Federation
join requires a complete bounded read and successful close before credential
writes, with categorical API errors that preserve internal causes.

A fresh owned PostgreSQL 16 database passed migrations through 180 twice and seed.
The full notify/handler suite passes **1,584** race/shuffle/count-two test
executions, **zero failures/skips**, and all fifteen new top-level regressions
twice. Vet passes for those packages and their API embedding. Count-aware scoped
lint changes 347 to 344: zero added, three removed (unchecked response close,
detached retry context and process statement count). These scoped counts are
separate from hosted whole-repository debt.

Adapted old-behavior controls reproduce four notifier and five backup failed
test events. The federation control overlays only literal old c5428cc
`fed_join.go`, retaining new helpers/tests: sixteen expected failures comprise
four actual diagnostic disclosures, five missing categorical boundaries, four
incomplete-response database mutations and three parents. Exact-bound acceptance
and ordinary read-error rejection both still pass. These are expected regression
failures, not sixteen diagnostic leaks or a whole-old-package run. All owned
process groups and separate PostgreSQL containers are verified absent.

Qualification manifest:
`/root/constellation-next-security-c5428cc-final-handoff/QUALIFICATION-MANIFEST.json`
(SHA256 `3ef59e28a05f6427415d9b398a9b29df8584ebcb30c54f7d603969cc3c1129f8`).
It links the preparation, adaptation, stage and hosted evidence, plus the complete
baseline/candidate source inventories and reviewed results. Controls used a
reviewed 42.5 GiB warm admission estimate; continuous early stops and hard
resource floors remained unchanged.

Broader notifier Dispatch/HTTP-shutdown durability, retry when bookkeeping DB is
unavailable, federation credential/state write atomicity and actual 30-minute
export-timeout acceptance remain open. Runtime-health source qualification is
recorded below. These eight files were source-qualified while main still ran
Helm 85/schema 180 with c5428cc; the later combined 2b29b63 artifact and deployment
records below supersede that pending state.
External provider/IdP, authenticated browser, broader enforcement/CNI/HA and
recovery acceptance remain open. The checklist remains 66 checked / 87 open.

Completed documentation-head [CI 39143874523](https://github.com/alphabravo-oss/constellation/actions/runs/39143874523)
on exact 8daad55 has nine passing/four failing jobs. Lint 1,459, gosec 144 and
history-secret 11 diagnostic identities are unchanged against c5428cc; quality,
gosec, gitleaks and required remain failed. This hosted run predates these eight
files. Root verified 38 hashes in
`/root/security-triage-39143874523/SHA256SUMS`; completed manifest SHA256 is
`adf35dcc90f29f680f41a37a7191846a467a9a6b2cd18be4b8a59a446cc111ac`.


### Qualified current-generation runtime readiness (2026-10-18)

Three source files over frozen c5428cc pass isolated qualification. The readiness
handler requires the active supervisor generation to be ready and keeps cumulative
start, keepalive and tap counters as diagnostics. Nil/disabled DP remains ready;
process exit and replacement startup cannot borrow historical replies. Fresh tap
reconciliation remains a separate acceptance signal. The existing search-only
Flannel fixture passes its owned directory as inherited fd4 to the unprivileged
child; UID/GID 65534, directory-read denial and literal-readlink assertions remain.

Fresh owned PostgreSQL 16 migrations through 180 twice and seed precede the full
runtime-agent/DP race/shuffle/count-two suite: **876 passing test events**, zero
failures, two passing packages and exactly six native opt-in skip events. The
HTTP regressions, active supervisor epochs, database replay and corrected fixture
each pass twice. Vet passes both packages. Configured count-aware lint remains
165 to 165 with no added or removed findings and no typecheck errors; these
existing diagnostics remain debt. The adapted original cumulative-predicate
control produces four HTTP 200-versus-503 leaf failures and two parent failures
at count-two, with no compilation failures or skipped/passing extras. Raw
assertions remain retained. All owned test/analysis groups, PG containers and
active v3 locks are absent. The earlier v2 attempt failed before its fixture
assertions because UID 65534 could not traverse private TMPDIR ancestors; this
was a test setup issue, not a demonstrated readiness regression. V3 fixes that
path with the inherited descriptor and passes the complete suite. The failed v2
attempt, original source and active lock remain preserved as history.

Qualification manifest:
`/root/constellation-runtime-health-c5428cc-final-handoff/QUALIFICATION-MANIFEST.json`
(SHA256 `381e344b8a4215b307c22f1c23d8c54f9a2e0ca9efaa95bc681b93214efd495f`).
It links the exact three source hashes, full 2,619-path inventories and all seven
sealed stages. Warm initialization 42.75/42.625 GiB and command 42.5 GiB
admission used the reviewed same-package observations; hard 40 GiB root/Docker and
2 GiB /tmp floors, early stops and owned process/database cleanup remained.

The import was onto b5e4200, where the three original file hashes matched
the frozen base. The preceding eight notifier/backup/federation files retain their
separate qualification. This checkpoint preceded combined artifact qualification
and deployment, when main still ran Helm 85/schema 180 with c5428cc; the completed
2b29b63 qualification and Helm 86 deployment are recorded below. Native/Flannel, fresh tap, broader
enforcement/CNI/HA and recovery acceptance remain open. No parent checklist item
is closed; the plan remains 66 checked / 87 open.


### Combined exact 2b29b63 artifact qualification (2026-10-18)

Exact source `2b29b6350c2c43e4b8656e213738e7c67c98b58d` combines the eight
notifier/backup/federation files and three runtime-readiness files above. The
complete frozen inventory contains 2,624 paths, checked against Git bytes, types
and modes. A fresh owned PostgreSQL 16 database was migrated through schema 180
twice and seeded before the four affected packages ran with race detection,
shuffle and count two: **2,460 passing test events**, zero failures and exactly
six native opt-in skips. All new regressions execute twice; all four packages pass
vet without diagnostics. Hosted full-suite results below are separate evidence.
The owned database and test/analysis process groups are independently absent.

The combined test result is
`/root/constellation-next-release-2b29b6350c2c-preparation/build/evidence/FINAL-TEST-RESULT.json`
(SHA256 `29b15bb03183a05b8f21436cef351091ff266a45bb8c99a2e313824f479b6327`).
The exact source binding has SHA256
`11062a470961e50eefd19933e6969adc3764788e40343bbd9631a3d51bb12832`.
The original 2,662-record input seal remains intact.

All four Go1.26.9 linux/amd64 binaries build with CGO disabled and trimpath.
The first build completed the API, then stopped before launching the CLI because
fresh free space missed the unchanged 43 GiB admission requirement. That partial
attempt remains sealed. After exact unused build-cache recovery, a separately
reviewed continuation copied the verified API into an independent file and built
only the remaining CLI, scanner and runtime binaries. Original API bytes, mode
and inode remain unchanged; all final binary hashes and build metadata are
verified. No failed stage was blindly rerun and no resource floor was reduced.
The complete receipt is
`/root/constellation-next-release-2b29b6350c2c-build-continuation-v1/evidence/binary-build-receipt.json`
(SHA256 `46b80ac86d809cf4bc0b3fdf9133494a875323dbd9d86f0956f7bb88d7c47ddd`).

Three thin images copy only these Go payloads over qualified c5428cc parents.
Parent configuration, layers and history are preserved apart from reviewed
version labels. Packaged hashes, root ownership and executable modes pass;
API/CLI/scanner supported help checks pass as nonroot. Native DP, BPF and all
23 runtime libraries and dependency mappings remain unchanged. All thirteen
owned probe IDs, names and nonces and all build groups are independently absent.
The assembly receipt is
`/root/constellation-images-2b29b63-preparation/execution/ASSEMBLY-RECEIPT.json`
(SHA256 `fffa78f98e8d9f0697fa024b79eb24bcd1e99840a3227359f0a24bbd0066277a`).
This is a verified thin assembly, not a new native/BPF build or packet acceptance
run. The earlier Flannel packet evidence remains specific to 314afad.

Three private raw single-tag archives total 906,605,056 bytes. Full hashes,
regular bounded root `index.json`/`oci-layout`, sole top-level descriptor/reference,
Docker manifest and nested OCI/config/layer identities are verified before
publication. Directory mode is 0700 and all files are 0600. Export receipt:
`/root/constellation-rollout-2b29b63-archives/EXPORT-RECEIPT.json`
(SHA256 `81dced95c237ea9d6fa7a70adcbe94a12beb742595ea2cedba03e774358aae79`).
The 27-record archive seal is
`467e445e477405ef3a58d7df92db6b6d4b0504f2c1f44470c6d5e2e92fb0e63d`.
The original source preparation, focused evidence and earlier c5428cc artifacts
remain preserved. Artifact qualification alone does not establish live behavior
or close a parent acceptance gate.


### Completed exact 2b29b63 hosted CI (2026-10-18)

Hosted [run 39148334138](https://github.com/alphabravo-oss/constellation/actions/runs/39148334138)
completed on exact combined source `2b29b6350c2c43e4b8656e213738e7c67c98b58d`
with nine passing jobs and four failing gates: quality, gosec, gitleaks and required.
Frontend passes 2,344 tests; browser passes all 279 cases with zero failures,
flakes, skips or report errors. Go unit records 3,411 passing test events and
745 skips; integration records 9,368 passes and fourteen skips. Both Go reports
have 99 passing package completions, 26 package skips and no failed tests. These
hosted totals include parent/subtest events and remain separate from isolated
fresh-database qualification.

Count-aware diagnostic comparisons against documentation-head run 39143874523
and c5428cc run 39139492997 remove three lint identities (1,459 → 1,456) and one
standalone gosec identity (144 → 143), with none added. Historical-secret identities
remain eleven, unchanged. Raw reports are retained; location drift is excluded
from normalized lint/gosec identity keys, and multiplicity is preserved. No debt,
suppression or gate is waived. FIPS and dependency checks pass. Govulncheck reports
zero reachable vulnerabilities while retaining two imported-package and three
required-module findings that the code does not appear to call.

The fourteen integration skips cover native/Flannel fixtures, privileged BPF/owned
child fixtures, missing Syft and a directory-ownership case requiring root.
External acceptance remains open. The superseded b5e4200 run was cancelled and
its evidence is explicitly partial; it is not counted as a completed test run.

The sealed manifest
`/root/security-triage-39148334138/COMPLETED-MANIFEST.json`
has SHA256 `5a2224303a06bee91bdc1375e7f01ef9675a25af9b192ddfc6ff5076a73cf3bf`;
the 174-record seal is `d151842bb5656907595843f5a9b23584c927c0c4d45c437fca07c22141365d70`.
Retained evidence totals 7,466,137 bytes, with no videos. Hosted source evidence
does not close broader enforcement, recovery or release-acceptance gates; the
canonical checklist remains 66 checked / 87 open.


### Completed exact 2b29b63 deployment (2026-10-18, Helm 86 / schema 180)

The reviewed API, scanner and runtime-agent images are deployed through the
normal Helm 85-to-86 update. The server dry-run and installed manifest differ
only in the three role images and matching API init image; normal hook revision
names advance. Frontend and migration remain on 5b82b12. All seven Deployments
and the runtime DaemonSet are ready; both StatefulSets match desired replicas
(the retired PostgreSQL StatefulSet remains scaled to zero). All sixteen prior
pins remain, three new candidate pins are acknowledged by CRI, and all thirteen
rendered image dependency chains verify.

The new pre-upgrade CNPG backup
`constellation-pre-security-2b29b63-20261018-cfbd6e20` retained original UID
`879e1770-4d88-4fb1-82de-023d170cb3b2`, backup ID `20261018T175148`, and completed
at `2026-10-18T17:58:45Z`. Fresh storage mapping and the reviewed 2 GiB additional
backup estimate passed before creation. This estimate is not a quota or future
size guarantee. No prior backup was adopted, replaced or blindly rerun.

Six live Go/native/BPF payload hashes match the qualified artifacts. The retained
PCAP PVC/PV, directory mode 700 with ownership 10001:10001, API Recreate strategy,
leader lease, runtime token secret UID and controller identities are preserved.
Monitor mode and execution dry-run remain enabled, enforcement and benchmark
workers remain disabled. API pod UID is `88d2825f-6110-4650-8c40-f3abc940f292`;
scanner and runtime pod UIDs are recorded in the verification receipt. Root
independently rechecked current controller readiness and smoke-forward absence.

Health/readiness return 200. Policy protocol 2 succeeds with zero policies,
legacy protocol returns 426 and an unknown cluster returns 404. Response protocol
2 succeeds with zero pending actions; anonymous, foreign-cluster and duplicate-node
requests return 401, 403 and 400. Empty queues do not prove positive enforcement.
The exact owned loopback port-forward was terminated and reaped; both PID and
listener are independently absent. Live smoke SHA256 is
`4a708e2641d9460d0b5486fe81ee11495f3cdbff103e2701c51c2f956a4f1211`.

A separate read-only disk observer records 246 samples from 17:42:12 through
18:02:37 UTC. It began during export and covers subsequent import, backup, update
and smoke; the exporter retains its own full-phase samples. Minimum available
root/Docker/containerd space was 48,651,431,936 bytes and /tmp 2,350,751,744 bytes;
no warning or hard floor was crossed. The exact observer process is absent.
Observer evidence is `/root/constellation-rollout-2b29b63-disk-observer`, with
five-record seal `c9e79a0c99eaf984608955de60dba263685ab490dd564076ab84fce3939a2cd4`.
Host scanner DB restoration remains a separate pending guarded operation.

Root verified all 172 final deployment records. The immutable manifest is
`/root/constellation-rollout-2b29b63-preparation/DEPLOYMENT-EVIDENCE-MANIFEST.json`
(SHA256 `7a15369a75d8f7304ce7e7ac9983387524eccc7adf433c075b74d866c09c7267`);
its 172-record seal is
`d233b1e144f8bffa3576521f37969b3fd5a0f074c2d05d6158becd22d0469399`.
Final deployment-status SHA256 is
`db15a7813b6df44f72dc11ca31c55ed72113730bf551d7a0643ca3f01b12a7b1`.

This deploys the bounded follow-ups; fresh native/BPF compilation, new packet/CNI
acceptance, authenticated main-browser workflows and broader recovery remain
unverified here. Historical key use outside test clusters is unknown; external
revocation/replacement and public-history decisions remain open. Off-host recovery
and deliberate real-node failure remain deferred. No parent acceptance gate closes;
the canonical plan remains 66 checked / 87 open. Scheduler delivery and DP namespace
restoration candidates are separate unqualified preparations, outside this release.

### Documentation-head CI and saved-view test correction (2026-10-18)

Hosted [run 39152669250](https://github.com/alphabravo-oss/constellation/actions/runs/39152669250)
completed on exact `702b9396c043765cf602fd3468c88e0a9b1646a4`, whose only changes
from 2b29b63 are two documentation files. Eight jobs pass and five gates fail:
quality, gosec, gitleaks, frontend and required. Browser passes all 279 cases with
zero unexpected, flaky, skipped or report-error cases. Integration records 9,368
passes and fourteen skips; unit records 3,411 passes and 745 skips, with no failed
Go tests. Frontend records 2,343 passes and one saved-view timing failure. Lint
1,456, gosec 143 and eleven historical-secret identities are unchanged, with zero
added or removed normalized identities. FIPS and dependency checks pass; the
previously recorded uncalled govulncheck findings remain retained.

The complete manifest is
`/root/security-triage-39152669250/COMPLETED-MANIFEST.json`, SHA256
`3009b77b2c5b4c6445587220113844504aeb540b3c909ea4d0557a3cc38be9e2`.
All 122 records independently verify; the seal is
`d2d3bbbe03b3996040efce533c539aa0395c0ecacadc3a83df582822f69906e6`.

The unchanged test reproduces the identical immediate Save-disabled failure once
in twenty natural repetitions under Node 24.21.0, and three times in three
controlled runs delaying the existing query-notification scheduler by 50 ms.
React Query updates fetching state synchronously but notifies the UI later.
The correction changes only the test: it checks fetching state and blocked
submission before waiting for the button to become disabled, then retains draft,
pending-submit and successful-save assertions. It adds no arbitrary sleep.
Both full-file executions pass all 34 cases (68 total); twenty normal focused
repetitions and all three delayed-notification cases pass. Product code is
unchanged. This focused evidence does not convert the failed hosted run to green.

Private reproduction, original failed reports and candidate qualification are
retained at `/root/constellation-network-saved-view-702b939-reproduction`.
The 223-record seal is
`4b72dc595cdb215e1fd059da984af0003cfcd5491ca5a475fc57da59f75730be`;
the imported test SHA256 is
`f232e348d26be69ef38f77ca6e08a8a5cb35211c608acdc86ec83501075f4c68`.

### Saved-view correction hosted result and bounded capacity recovery (2026-10-18)

Exact correction head `c7d97b5c4bf15f70ebf62e1453b0a40974d8531f` completes
[hosted run 39157926527](https://github.com/alphabravo-oss/constellation/actions/runs/39157926527)
with nine passing jobs and four failing gates: quality, gosec, gitleaks and
required. Frontend passes all 2,344 tests, including the corrected saved-view
case; browser passes all 279 cases with zero unexpected, flaky, skipped or report
errors. Unit records 3,411 passes / 745 skips and integration 9,368 passes /
fourteen skips, with no failed Go tests. Both Go reports contain 99 passing
packages and 26 packages without tests. Lint 1,456, gosec 143 and eleven
historical-secret identities have zero count-aware additions or removals versus
702b939. FIPS and dependency checks pass; zero reachable govulncheck findings
does not erase the retained two imported and three required-module findings.
All 155 evidence records independently verify at
`/root/security-triage-39157926527`; seal SHA256 is
`f55be96491a116e117772c8830da2f006b801c3403bb3159bc083742e71b2d95`.

To admit the next isolated Go qualification, 104 unused historical role images
were first preserved in one complete 1,663,987,200-byte recovery archive, SHA256
`3b2df65661422e5a085381dc1488b11946dab2a4f748bb11a4e0378a83ae0604`.
Independent full-byte, graph and layer-DiffID verification passed. The initial
import failed its strict descriptor comparison because Docker applied the
archive's name annotations; its failed result and lock remain preserved. A
separately reviewed import allows only the exact observed annotation replacements and passes with
the complete raw image map unchanged. This proves importer idempotence in the
existing store, not restoration into an empty store.

One nonforce `image rm --no-prune` then exits zero and removes exactly the 104
selected images. Its strict post-check remains failed because 79 retained cache
records changed only their derived `Shared` flag from true to false. Separate
read-only reconciliation confirms two identical settled maps: all 79 other
images, 314 cache identity/dependency records, eight containers and external
references remain intact; only the 145 permitted snapshot chains disappeared,
and all 614 protected parent/kind rows remain exact. The archive, source,
preparations, original failed checks and locks remain preserved. Reconciliation
is `/root/constellation-role-image-recovery-104-retirement-reconciliation-v1`,
RESULT SHA256 `edc0f6e24cec90e71d029973d061412fe750cf5a0e54822a68955da00118d3eb`.
Observed net filesystem gain after retaining the archive is 2,787,889,152 bytes;
this includes background/evidence changes and is below the logical estimate.
Main remains Helm 86 / source 2b29b63; host scanner database restoration and the
new Go source qualification are separate pending work.


### Scheduler delivery, namespace restoration and report confinement qualification (2026-10-18)

Nine Go paths add bounded corrections in three packages. A malformed webhook
returns a categorical error before request headers are accessed; transport and
provider diagnostics remain inspectable through error unwrapping without
entering persisted status or worker logs. A requested S3 signature-sidecar upload
must succeed for delivery to succeed. Fresh-database tests exercise an actual
scheduler tick across two organizations and a real AWS SDK loopback upload
rejection, retaining subsequent deliveries and local report artifacts.

Container interface discovery runs on a dedicated locked worker. Restoration
failure joins the original error, discards interface results and exits without
unlocking; the caller never enters the target namespace. The fallback saves the
locked worker's own task namespace. Tests use fake namespace syscalls with actual
thread locks, TIDs and bounded complete goroutine evidence. Ordinary failed
workers terminate; Go's initial main thread may remain parked after its worker
goroutine exits. This is not a real Setns or fresh-tap acceptance claim.

Authenticated report downloads open only regular, singly linked files beneath
REPORT_OUT_DIR (default /tmp/compliance-out). Pinned directory descriptors,
no-follow/nonblocking opens and inode checks reject traversal, symlinks,
hardlinks, FIFOs and replaced entries without creating or changing the API's
report directory. Relative root configuration remains supported. Read-only main
inventory found zero compliance runs, so there is no existing file-URI
compatibility blocker; it does not establish a positive main artifact download.
The compatibility inventory's eight-record seal is
`79d606d1bf39a45aec356081bfc72ae271b3f5e2d2762c44858f9ebaecac28f9`.

V6 combined qualification passes 598 race/shuffle/count-two test executions
across all three packages on a fresh schema-180 database, with exactly two
explicit native opt-in skips and no failures. All 54 required named test nodes
run and pass twice. Vet has zero diagnostics. Configured scoped lint records
92 baseline and 85 candidate findings, with zero count-aware additions and seven
removals. Native and live-provider acceptance remain separate. The owned
PostgreSQL container is absent, source inventories are unchanged, and owned
process groups and successful-stage locks are released.

Qualification preparation is
`/root/constellation-scheduler-dp-compliance-next-preparation-v6`, with
46-record seal
`0581d2c7f3429fbb11325c4784c2b828cd3dec6ef502763ef225b9985266d6ae`.
Evidence is `/root/constellation-scheduler-dp-compliance-next-qualification-v6/evidence`.
Tests have fourteen-record seal
`5b26eb275c8979bc59f7d3de67a44fe896c676db1a9d7dcce1202c67ed06207b`;
vet has nine-record seal
`06ffa96cc9cef2752ae51bb099f54f2c8f150cbf7777d7d689a7dfef022085e2`.
The five-record lint comparison seal is
`257e876004ade0f9f5906029bb36b04da3026eae96e291510a91a82a685f6115`,
RESULT SHA256
`ab02f738708b4fe3efb699d9976cd42ec23e824c4c1fb525fece360a9ccda3e7`.
All four original-code controls reproduce the required failures: namespace
restoration has six expected failed test events; malformed webhook construction
panics once; ignored S3 signature failure has four expected failed events while
four healthy-case executions pass; and report confinement has ten expected
failed events. The latter verifies all four negative HTTP cases twice, each
returning the exact private fixture bytes with HTTP 200 under the old handler.
These are intended regression failures, with no compile, race or skip credit.
Control seals, respectively, are
`537376d14d66738cb9de6938722d1e731b7c661a557dd8808f14c13235742e0c`,
`30c65053154af217fb1ea94716c9db66cb3123ef848e6f1c1010c9564dfd9573`,
`f56da79833aea8ef78084342cb62b0eb49ce7238977e1c24a39fb66dddb8d757` and
`605819119c1d8beaba3e4196d6acd6a303dc483d1c953d4182e031c3262fa3fd`.
The API control's separately owned database is also absent. All ten stage seals
independently verify. The later exact ef0ca39 artifact, hosted-CI and Helm 87
deployment evidence is recorded below; these isolated source results alone do
not establish deployed acceptance.

After image retirement, a separately guarded official BuildKit prune removes
exactly 79 unused, now-unshared cache records (314 to 235), preserving every
remaining cache record, all 79 images/80 references and eight containers. Its
command exits zero; the owned process group is absent. Observed filesystem gain
is 1,225,666,560 bytes, distinct from nominal cache sizes. Ten-record execution
seal is `a69454f3ac6d6ae05a9b0a1541a6ea4b93f3c08c337e663b245d4460a0c1089c`
at `/root/constellation-build-cache79-preparation-20261018-v2/execution`.
Source, recovery archives, module downloads and host scanner database archives
remain retained. Scanner database restoration is still pending.

The scheduler remains a source/binary role without a deployed worker. Durable
shared report storage, signing keys outside the API report mount, real signing,
SMTP bounds, queue/crash recovery and live delivery remain open. Full parity
remains 66 checked / 87 open; no parent acceptance item closes.


### Exact ef0ca39 artifacts and completed hosted CI (2026-10-18)

Exact committed source `ef0ca39020514d57be2b6ece0e64d995ef17e039` captures
2,629 files and the nine qualified Go paths. Five fresh Go 1.26.9 binaries
(API, CLI, scanner, runtime agent and standalone compliance scheduler) total
225,002,282 bytes. The build receipt is
`/root/constellation-final-five-build-evidence-ef0ca3902051-v1/five-binary-build-receipt.json`,
SHA256 `5e9394c5ed281afe986edfce728eac6cdeccd1fcd0c0e6e02b255930065c870b`.
Three thin images package four payloads; inherited native DP/BPF and all 23
linked libraries match their reviewed parents. All thirteen owned image probes
are independently absent. Three fully verified raw single-tag archives total
960,199,168 bytes. The scheduler binary does not establish a deployed worker.

[Hosted CI run 39162714386](https://github.com/alphabravo-oss/constellation/actions/runs/39162714386)
completed on that exact source with nine passing jobs and four failing gates:
quality, gosec, historical-secret scanning and required. Unit records 3,455
passes / 748 skips, integration 9,474 passes / fourteen skips, and neither has
failed tests. Frontend passes all 2,344 tests; browser acceptance passes all 279
cases with no failures, flakes or skips. Count-aware lint falls from 1,456 to
1,449 and gosec from 143 to 136, each with zero additions and seven removals.
The eleven historical-secret identities remain unchanged. FIPS runtime and
dependency checks pass; zero reachable govulncheck findings leaves the two
imported and three required-module findings recorded. These are existing failed
release gates, not a green required check.

The completed evidence bundle is `/root/security-triage-39162714386`; all 197
checksum records independently verify. Its seal SHA256 is
`7be27bc7110241c5916bde2e66c7b3cd2d1a114a1bd2a857f18888e75df968df`.

### Compliance schedule request wording continuation (2026-10-18)

The next source change labels schedule actions “Request run” and discloses
“Enable and request run” for a disabled schedule. The existing notification
shows the API response instead of leaving a persistent queued banner. The API
and embedded OpenAPI describe enabling and marking a schedule due, requiring a
running report scheduler and reviewing History for execution and delivery.
They preserve HTTP 202 and the compatibility envelope without promising a
30-second execution deadline. The endpoint does not insert a run record.

A private frontend qualification passes all 45 ComplianceWorkflows tests,
TypeScript and a production build on pinned Node 24.21.0. All 800 evidence
records independently verify at
`/root/constellation-request-contract-frontend-qualification-v1`, seal SHA256
`0dc965e7433a781565116846aabb464c6ea8a9294e57c0beff9a393ca716d079`.
The backend tests check same-organization due/enabled state without execution
rows and foreign-organization rejection without changing either schedule.
The later exact 861d88a hosted run passes both backend roots twice but fails two
browser notification assertions, as recorded below. This source change is not
deployed and does not close scheduler delivery acceptance.


### Completed exact ef0ca39 deployment (2026-10-18, Helm 87 / schema 180)

The normal three-image upgrade completes after fresh backup
`constellation-pre-security-ef0ca39-20261018-597efdaf`, original UID
`d57b5be3-f614-44e7-9f3e-96a263c17583`, backup ID `20261018T204324`,
stopped at `2026-10-18T20:54:02Z`. The completed backup receipt and all nine
phase checksum records independently verify; no replacement or retry occurred.

Helm 87/schema 180 verifies all seven deployments, the runtime DaemonSet and
StatefulSet readiness. The API, CLI, scanner and runtime-agent live hashes match
exact ef0ca39 artifacts; native DP/BPF and their inherited libraries remain
unchanged. PCAP storage identity, ownership/mode, Recreate strategy, leader lease,
runtime-token identity and configuration remain intact. All nineteen prior pins
and three new image pins remain complete. Frontend and migration retain source
5b82b12; the scheduler remains a standalone binary, without worker activation.

Live API checks pass health/readiness 200, legacy policy 426, unknown cluster
404, empty authorized policy/response queues 200, anonymous response 401,
foreign-cluster response 403 and duplicate-node response 400. The exact owned
loopback forward, PID 3066527/start ticks 526160328, was terminated and reaped;
root independently confirms PID absence and port 19387 unbound. This is API
smoke under the isolated-check selection, not authenticated browser or positive
main enforcement evidence. Monitor mode, disabled enforcement and benchmark
workers, and execution dry-run remain preserved.

Evidence is `/root/constellation-rollout-ef0ca3902051-bound-preparation-v1`.
The seven-record upgrade seal is
`31c47aa675389407314dba2126f9c0863ba6f8a293d22b1f791d5cf4d12e4b9f`;
the eight-record smoke seal is
`05958c1c9a6c74246173587255ba3ad83b9ccecdd3eda2b729652c14f47b2480`.
All root-approved 108 inputs independently remain unchanged. The checklist stays
66 checked / 87 open; this deployment does not close a parent acceptance gate.


Completed deployment manifest:
`/root/constellation-rollout-ef0ca3902051-bound-preparation-v1/DEPLOYMENT-EVIDENCE-MANIFEST.json`,
SHA256 `fb4d02f3a748f613c5179d37b6d9247c3e10525fb7dc689cc1366d2934f70ef2`.
All 151 final checksum records independently verify, seal SHA256
`4bf89c6ae23573552f73e4bc8faa5d10e92ee9894432a0417cbc9c2a9b79d1aa`.
The stopped observer records 285 complete samples after exports, spanning image
imports/pins, backup, upgrade/verification and API smoke. Minimum available bytes
are 47,342,280,704 on root/Docker/containerd and 2,350,710,784 on tmp; no early or
hard floor crosses. Observer PID/group absence and all seven completion records
verify. This observer does not cover the earlier export phase, whose own samples
remain in the export receipt.

### Lossless closed-journal capacity recovery (2026-10-18)

A separately reviewed finite selection preserves the oldest 24 archived-state
system journals in one private, deterministic gzip/PAX archive before retiring
only those originals. Active system/user journals and all unselected files stay
outside the selection; no vacuum or rotation is used. The archive is
`/root/constellation-closed-journal-oldest24-recovery-v1/journals.tar.gz`,
261,082,525 bytes, SHA256
`457263a69d764a06aaaab376b6aeee58557dc5081f610e5a97710899abc7d296`.
Root independently verifies all 24 full payload hashes, exact 25 members,
canonical metadata/padding/trailer and a complete single gzip stream through
CRC/ISIZE and physical EOF. Original UID/GID/mode, xattrs and nanosecond times
remain recorded with concrete no-replace restoration instructions; inode and
ctime cannot be recreated.

Archive-only completes first, retaining all originals, with RESULT SHA256
`613b7bbb9fdb617bf5cc866cdd54a583392b4a46ea02812ee24359b8cafc50c8`.
Only after independent full recovery and source/FD/metadata checks does a separate
granted retirement complete all 24 exact dirfd-relative removals with durable
progress. Its RESULT SHA256 is
`7cded293ab395638c1bc94805b50024f0c3bd69a04d0add2cb23a23bd1bbcf22`;
all seven sealed evidence records and the separately bound result independently
verify, all selected originals are
absent and the full retained archive hash remains exact. The selected exclusive
source allocation was 1,137,127,424 bytes; recovery archive/evidence consume part
of that gain. Observed filesystem recovery during retirement is 1,095,626,752 bytes; net
since the archive phase began is 821,895,168 bytes. Both include background
writes and are distinct from nominal selected allocation. Prior executor versions and the long-path synthetic negative remain
preserved; the real operation uses the reviewed v3 with explicit PAX paths.
Scanner database restoration remains a separate pending operation.


### Completed 861d88a CI and notification assertion correction (2026-10-18)

[Run 39166039262](https://github.com/alphabravo-oss/constellation/actions/runs/39166039262)
completes on exact `861d88a9b02fdf34232c2d07a8d5fd6a9f5d60d8` with eight
passing and five failing jobs. Integration records 9,478 passes / fourteen skips
and zero failures. Both request-contract test roots actually run and pass twice;
their two unit-mode skips do not count toward that acceptance. Unit records
3,455 passes / 750 skips / zero failures; frontend passes all 2,346 tests. Lint
1,449, gosec 136 and eleven historical-secret identities retain exactly the same
normalized multiplicities as ef0ca39, with zero added or removed occurrences.
FIPS and dependency checks retain the previously stated boundaries.

Browser records 278 passing and two failing cases out of 280, with no browser
acceptance. Both failures assert visibility of Sonner's `section[aria-live]`.
The completed job log shows that section repeatedly resolves with the exact
notification message but returns hidden before the message expires. Sonner's
children use fixed positioning; its live-region section has no intrinsic height.
A small synthetic DOM geometry probe confirms that layout property (zero-height
region with a nonzero-height text child), not application visibility. The source
correction requires the exact notification text within the live region to be
visible. The historical failed run remains failed.

All 202 retained records independently verify at
`/root/security-triage-39166039262`, seal SHA256
`9ad2fdf4f84830bf91a5074282ddabf5e058674d70b71394b1439224efc23a2b`.
The bounded completed-job text log is 113,461 bytes. The 11,528,408-byte browser
artifact was not downloaded because it exceeds collector caps; no videos or
structural browser report were collected or credited.

The subsequent frontend snapshot additionally wraps schedule actions and long
metadata and uses the shared Button variants. Its mobile browser fixture checks
card/action bounds at 360 pixels with long unbroken names and templates. All 45
focused tests, TypeScript and the production build pass on pinned Node 24.21.0;
199 output files total 3,523,446 bytes. All 437 source hashes and tools remain
unchanged. The private qualification's 1,240 final checksum records independently
verify at `/root/constellation-request-contract-frontend-qualification-v3`, seal
`2af03ea89689e328dddc14732809b5687cb3032d1403826f66852e1594df39b6`.
That 281-case snapshot was not run in browser CI; the later enabled-state
follow-up below supersedes it with a combined 282-case snapshot pending. No
deployed frontend or positive main browser acceptance is claimed.

A separately reviewed official `golangci-lint cache clean` removes only the
inventoried regenerable analysis cache. Its explicit absolute cache override,
pinned v2.11.4 executable and upstream implementation are verified. All 2,823
protected files and ten directory identities remain unchanged; the exact owned
PID/group is absent. Six execution records independently verify, seal
`9ff4972aebe8c49de7d815f7b4f2c658d953f65285ee5447876c474dbfc0e996`.
Observed pre/post filesystem gain is 321,445,888 bytes, not continuous minima.
Only final preparation v2 is accepted: an in-flight pre-execution amendment
invalidated the earlier draft seal and lost its original resource snapshot;
that limitation remains recorded rather than reconstructed. No source, cache or
deployment execution data was changed by the draft amendment. Parked scanner
database restoration remains pending after isolated SMTP qualification and
separate compiler-cache recovery.

### SMTP cancellation and total-deadline continuation (2026-10-18)

The proposed scheduler SMTP transport carries the caller context through dialing
and protocol I/O, applies one total delivery deadline, closes blocked connections
on cancellation, and returns categorical delivery errors while preserving causes
for inspection. Configured authentication fails when AUTH is unavailable;
unauthenticated legacy HELO remains supported. Opportunistic STARTTLS keeps normal
certificate/hostname verification and an explicit TLS 1.2 minimum. No scheduler
workload, external mailbox delivery or positive TLS exchange is established here.

The first isolated iteration passes all fourteen SMTP test nodes twice (28 pass
events, zero failures/skips) and race-aware vet without diagnostics. Its complete
scoped lint finds seven baseline and eight candidate issues: the added G304 is
the test's variable-path read. No zero-added comparison or original-code controls
have passed for this iteration. The test now reads the literal report member
through its owned temporary directory's filesystem; assertions and production
bytes remain unchanged. A fresh source-bound qualification is required. Original
analysis, source and process receipts remain preserved at
`/root/constellation-scheduler-smtp-861d88a-qualification-v2`; that candidate is
not represented as lint-clean or fully qualified.

Fresh v4 qualification of the corrected source passes all fourteen SMTP nodes
twice: 28 passes, zero failures or skips. Race-aware vet has zero diagnostics;
complete scoped lint records seven baseline and seven candidate occurrences,
with zero count-aware additions or removals. Four original-code controls fail
their exact test-owned cancellation, shorter-deadline, diagnostic-redaction and
configured-AUTH-after-HELO assertions twice each. The expected child exit 1 is
retained; compilation, races, panics and unrelated failures do not count. All
owned process groups are absent and qualification locks are released.

Root independently verifies all 69 actual initialization, six-stage and outer
invocation evidence records, revalidates exact positive/control events, and
matches all 2,632 frozen candidate files to shared source before the separate
frontend import. Root acceptance is
`/root/constellation-smtp-v4-root-acceptance-v1.json`, SHA256
`a895bb70070841b5db9a9fa2f800eea33a7e38659d7e6e50505c2178ec9a06f1`.
The scoped lint uses the same pinned CGO/race profile for baseline and candidate;
the reviewed loader inherits GOFLAGS and disables external package drivers.
Cache hits are not measured, and default hosted lint remains a separate gate.
The original seven-to-eight first iteration and the official compiler-cache-only
checkpoint used before fresh cold qualification remain preserved. No external
mailbox, successful TLS exchange or deployed scheduler worker is established.

### Schedule enabled-state console follow-up (2026-10-18)

The console now exposes Enable/Disable separately from request-run and delete,
and displays configured enabled state independently from last-run status. It
uses the existing organization-scoped PATCH API without requesting execution.
Inherited organization actions retain their across-cluster scope label. Mutation
guards recheck identity, resolved cluster scope, idle/noninvalidated list data,
row scope and the reviewed enabled value. Failed updates retain configuration
and show a categorical error; counts refresh after successful PATCH. Disabling
does not cancel claimed work or establish scheduler execution/delivery.

The first private frontend attempt records 49 passing tests and one failing
pending-button assertion; TypeScript and build did not run. All 896 failed-attempt
records remain unchanged and independently verify. The fixture now awaits the
button's disabled render before resolving its pending API promise, retaining
the original state/count assertions. Fresh v2 qualification passes all 50
focused tests, zero failures/skips/todos, TypeScript and production build. All
four actual command exits are 0 with empty owned process groups; all 199 build
outputs (3,524,675 bytes), source/tool invariants and three SMTP Go files verify.
RESULT SHA256 is
`3fe625b06e0e089b62e0c6d765bf3abd5a8f921cf5a5ea175015d6e11133cdaf`
at `/root/constellation-schedule-enabled-frontend-qualification-preparation-v2`.
All 1,241 final checksum records independently verify, seal SHA256
`60d5eca61f98a4355fe037637fd00a2a574e87e3bb5206d7b2b7faac67a0e4fb`.
The combined 282-case browser snapshot remains pending, and this frontend is
not deployed. The canonical checklist remains 66 checked / 87 open.

### Additional closed-journal recovery before scanner-cache restoration (2026-10-18)

A second, disjoint selection preserves the next 24 oldest unreferenced archived
system journals. Active/user journals and all unselected files remain outside
the operation. The executor is byte-identical to the reviewed corrected-PAX
version; only the new selection, output bindings and exact raw cap change.
The private recovery archive is
`/root/constellation-closed-journal-next24-recovery-v1/journals.tar.gz`,
260,069,245 bytes, SHA256
`7f00d49aa5450ea9cab0980d612e35163ef455831ba89598311ee246ae41cf2c`.
Root independently reads the complete single gzip stream through CRC/ISIZE and
physical EOF, checks all 25 canonical members and 24 payload hashes, then
rechecks all original hashes, metadata/xattrs, archived state and zero FD
references. Archive-only completes before a separately granted retirement.

Retirement exits 0, records 24 durable exact-path removals and leaves all 24
selected names absent. The archive remains exact; owned worker PID/group and
lock are absent. All seven retirement evidence records independently verify,
seal SHA256
`199221a160b946b46fa2496a22788033397cf49b48a5e39eb3988a08a8f4ef2b`;
separately bound RESULT SHA256 is
`28d1df66cc396be4eb9e3955fdbff38d3f23ce9829e492228404422376509b7e`.
Observed combined archive/retirement available-space gain is 840,859,648 bytes,
including background activity and evidence costs. All resource floors remain
clear. Both recovery archives and concrete metadata restoration instructions
are retained. This does not establish off-host recovery; scanner database
restoration still requires the separate compiler checkpoint and fresh admission.

### Completed compiler checkpoint and original host scanner-cache restoration (2026-10-18)

After root accepts all six actual SMTP stages and the separately qualified
frontend, a new bound checkpoint executes only pinned Go 1.26.9 `clean -cache`.
Actual exit is 0, compiler outputs are zero, and all 6,554 protected source,
artifact, qualification and recovery records remain unchanged. All eight
execution records independently verify, seal SHA256
`de5314301a1ebbff9853fce0f65ce91bcf9928acd76563ab61ae30795b9eeff1`;
RESULT SHA256 is
`7f3451fa94cf7173b1e2ad3da04d166fde9c36318a571c114996aa6d4919a99d`.
Observed available-space gain is 1,089,814,528 bytes. No other cleanup is used.

Fresh preflight verifies both twelve-record original/durable preparations, both
complete compressed archive hashes, empty retained directories, no conflicting
files or prior restore attempts, no active FD/maps users, and combined capacity
for both trees plus per-tree allowances and a 128 MiB background reserve. A small
owned-process adapter imports the unchanged original restorer and raises only
its two runtime reserve constants to 40.5 GiB root and ceil(2.05 GiB) tmp. The
original restoration, metadata verification and partial-preservation behavior
remain intact; each tree requires a separate grant and actual first-tree proof.

Trivy then Grype each restore once with actual worker and outer exit 0. Root
independently verifies all five complete original files, totaling 4,701,282,746
bytes, exact directory inventories, UID/GID/modes, nanosecond atime/mtime, empty
xattrs and directory times. New inode/ctime values are expected. Both original
compressed archives remain exact, original receipts report RESTORED with no
errors, process groups are absent and locks are released. No scanner is launched,
database regenerated or scanner PVC changed. Sampled wrapper minima are
43,969,372,160 bytes on root/Docker/containerd and 2,350,706,688 bytes on tmp;
all configured floors remain clear.

Root acceptance is `/root/constellation-host-db-root-final-acceptance-v1.json`,
SHA256 `e0ae9fbf25e9a44db585124d7b63b395f15c7434ef7d37b454941641e037d319`.
Trivy's six-record seal is
`98c9a2eb8def3495d7901870c3469c1227a5610169f6c60b2c89c84d3e6b7f85`;
Grype's is
`4d2cca6d58ab6aaca99026e544bf2ce9a5e5bbd30493645294899168f15a2544`.
Their separately sealed actual outer invocations and independent five-file
verification remain under `/root/constellation-host-db-*`. This completes the
temporary host-cache parking operation; it does not establish fresh vulnerability
database updates, off-host recovery or a parent parity acceptance gate.

### Completed f519517 hosted qualification (2026-10-18)

[Run 39173527687](https://github.com/alphabravo-oss/constellation/actions/runs/39173527687)
completes on exact `f51951750f27ebb981dcea7548f857e4d01c3da4` with eight passing
jobs and five failures. Browser acceptance passes all 282 cases without
failures, flakes, skips, errors or retries. All five schedule cases pass once,
including both corrected notification assertions, 360px action bounds and
enabled-state PATCH. Unit records 3,469 passes / 750 skips; integration records
9,506 passes / 14 skips. All fourteen SMTP nodes pass once in unit and twice in
integration; both request-handler roots pass twice in integration without skips.

The frontend job records 2,350 passes and one failure in the unchanged Timeline
strict-boundary render assertion; all 50 schedule workflow cases pass. The next
source corrects that wait as documented below. Lint remains 1,449, gosec 136 and
normalized historical-secret identities 11, each with count-aware zero additions
and removals. Quality, gosec, history, frontend and required remain failed; no
gate is waived. Retained evidence is `/root/security-triage-39173527687`;
all 193 checksum records independently verify, seal SHA256
`fcda4384ebf3f9bb6c61906e2b3855d3bc05cf81fb3cea1fe641d3b026a14b67`.
This run accepts its exact source's browser behavior, not the later schedule
editing snapshot, a deployed frontend or scheduler execution/delivery.

### Scoped schedule editing and Timeline render synchronization (2026-10-18)

Schedule cards now expose a dedicated Edit route using the existing form and
PATCH API. The editor freezes the first matching organization/cluster record,
retains drafts across refresh failures, and rechecks current identity, resolved
scope, noninvalidated data and available replacement choices before saving.
Custom values and complete delivery objects remain intact, including multiple
targets, endpoints, receiver references and additional properties. Requests
contain only changed configuration fields; they omit enabled state and never
request a run. Inherited schedules retain their organization-wide scope label.
Already-observed changes to a dirty field block saving and explain how to copy
edits, cancel and reopen. Visit-specific ownership rejects an older save after
leaving and returning to the same context, protecting the new visit's draft.
The existing server
PATCH still lacks transaction/CAS protection; this is not a guarantee against
concurrent updates. No scheduler or provider acceptance closes.

The private five-path proposal and root import receipt are retained at
`/root/constellation-schedule-edit-f519517-preparation-v2` and
`/root/constellation-schedule-edit-root-import-v1.json`. Fresh isolated
qualification passes all 73 exact workflow cases (50 retained plus 23 added),
TypeScript and Vite build with actual exit 0. All 199 output files, totaling
3,531,651 bytes, and all 437 source bindings independently verify. RESULT is
`/root/constellation-schedule-edit-frontend-qualification-v3/evidence/RESULT.json`,
SHA256 `da5974f0f4c2a024aa83621ba8fb0bf0995785e0705ef07aa241037bcf6697dc`.
The fifteen-record execution seal is
`aea2c09b66c835e1c144e0b95fc9fb8a702ad1ef6dae209c2bdb76fc071588d4`;
the separately sealed outer command also exits 0. Owned process groups are
absent and the lock is released. The two added browser fixtures and existing
narrow-screen action check await a later exact-head 284-case run. This frontend
is not deployed; the canonical checklist remains 66 checked / 87 open.

The earlier 72-case v1 pass remains preserved. Follow-up v2 records 72 passes
and one failed synchronous enabled-label assertion; the new stale-save case
passes, but TypeScript/build do not run. Its nine-record seal is
`66767ab9ab86a85536f3fc3532eb540e8064c40bd5e662db60a5b652f16f73b8`.
V3 awaits rendered feedback for cache changes and completed mutations before
checking old-save navigation, retaining immediate no-write guards. The failed
work, source and lock remain intact; no in-place retry occurs.

The separate v3 original-code control uses the literal earlier form with the
new test. Its sole selected stale-save case fails at the owned navigation
assertion: the old completion redirects once after leaving and returning.
Actual child exit is 1; the expected-failure wrapper and sealed outer exit 0.
The other 72 cases are filtered without acceptance. All ten control/outer
records independently verify, groups are absent and the lock is released.
RESULT SHA256 is
`3f67241843076c66066b28a89ef36f15a2f2d4617625ea9ebeff62679aa0fcad`
under `/root/constellation-schedule-edit-aba-old-control-v3/evidence`; its
six-record seal is
`d5be22d590fa4633e54ee9f1f04196ab2dc0be2ed7576689fe3e9c87b71dee1c`.

The f519517 full frontend run also exposes an unchanged Timeline test that waits
for a refetch API invocation but immediately asserts the rendered result. The
fixture now waits for the same "Strictly after" assertion to render. Strict
14-day, exact timestamp, replace-history and pagination assertions remain.
Fresh isolated qualification passes all 30 exact Timeline cases without skips;
production Timeline bytes are unchanged. RESULT SHA256 is
`be5f240e5f08e1d827b7764bd92e4221c5df451374c0786cc4908bb639163583`
under `/root/constellation-timeline-settled-frontend-qualification-v1/evidence`;
the nine-record execution seal is
`1abcdb5eaa69d7a2338669601b5762a4156c42c9e2ddece192eaa5b9d3df7ab0`.
Actual child and separately sealed outer exits are 0, groups are absent and
the lock is released. The original hosted failure remains retained.


### Completed 029958a CI and console consistency follow-up (2026-10-18)

[Run 39176306397](https://github.com/alphabravo-oss/constellation/actions/runs/39176306397)
completes on exact `029958a747e7a53084abe042f19a22cf58b30398` with eight passing
and five failing jobs. Frontend passes all 2,374 cases, including all 73 schedule
workflow and 30 Timeline cases. Unit records 3,469 passes / 750 skips;
integration records 9,506 passes / 14 skips. All fourteen SMTP nodes pass once
in unit and twice in integration; both request-handler roots pass twice.
Lint remains 1,449, gosec 136 and historical-secret identities 11, with zero
count-aware additions or removals. Quality, gosec, history and required remain
failed; no gate is waived.

The bounded browser job log records 284 unique single attempts: 283 pass and
one direct-edit case fails before Save. The retained failed-page snapshot shows
the correct edit form and populated textbox named Name*, while the test requests
an exact Name label. Its correction uses the existing wizard-name field ID,
first requiring the correct heading and initial value, and preserves the
failed-write, draft, redaction and scoped Cancel assertions and timeouts.
Structured flaky/skip/error fields were not extracted; zero retry markers were
observed in the complete text log. The original 4 MiB artifact-cap stop remains
intact. Separately bounded follow-ups retain the 107,663-byte log, original
4,625,506-byte ZIP and only the 19,107-byte error-context text. No video, trace,
screenshot or browser report was extracted. All 175 records independently
verify under `/root/security-triage-39176306397`, seal
`5bfd671edd0737e1ea11c0276984c6dce0607e60bb77b645960a5b7383cabecb`.
Root review is `/root/constellation-029958a-ci-root-review-v1.json`.

The following source extends one reusable useEditorVisit hook across Registry,
Group, Exemption, schedule creation/edit, Policy and Admission Settings editors.
Owner/target keys remount the actual mutation observer; editor-local lifetime
checks also reject completions after same-target inner-editor unmount/reopen.
Existing mutation payloads, freshness/revision guards, safe cache invalidation
and draft retention remain. Requests already sent are not canceled; server
scope, concurrent-write CAS and delivery guarantees are not added by this UI
change. Images reuse shared naming and DigestDisclosure for inventory, preview,
identity, workload, layer, Diff ID and bundle hashes. Reported repository/tag and
normalized references remain readable; optional exact digests remain revealable.
Raw API values, matching filters and CSV identity remain unchanged; React-node
cells declare explicit raw export values. Login copy matches the shell branding.

The four reviewed private proposals compose twenty paths over029, plus a
one-line login branding correction and documentation. The isolated preparation
binds 438 baseline / 439 candidate frontend files and eight full test files,
forecasting 291 focused cases and 2,419 global frontend / 285 browser cases.
These are forecasts, not passes. Preparation seal is
`58d022c955110f0d5909152b97bd768d5fa17be732ede82f93e3a1059c2936b6`
under `/root/constellation-editor-images-frontend-qualification-preparation-v1`.
At admission root/Docker/containerd had 43,566,120,960 bytes free, below the
43,620,761,600-byte startup reserve; no Node, test, typecheck or build was
invoked. No floor was lowered, cleanup performed or failed command retried.
The capacity hold and exact source import receipts remain at
`/root/constellation-editor-images-local-capacity-hold-v1.json` and
`/root/constellation-editor-images-root-import-v1.json`. Exact-head hosted
qualification remains pending. Main stays Helm87/schema180 with the older
frontend; no worker activation, deployment or parent acceptance closes.

A subsequent test-only correction explicitly sets image_digest on the three
new inventory records to match their reference and disclosure/CSV assertions.
The inherited fixture otherwise supplied sha256:0. No product behavior, case
identity, timeout or expected suite total changes; the sealed private proposal
remains unchanged and does not qualify the corrected source.


### Evidence-table exports and remaining editor lifetimes (2026-10-19)

The exact ea20f7d attempt records 2,417 frontend passes / two failures out of
2,419, with no skipped/todo cases. All eight expected full-file identity Counters
match; 290 of 291 focused cases pass. The new package/file-risk case fails at an
absent Export CSV control. The other failure is the unchanged compliance evidence
test clicking a temporarily absent sort button after Back. Unit records 3,469
passes / 750 skips; all fourteen SMTP nodes pass once. Integration completion is
not claimed here. Lint 1,449, gosec 136 and history 11 remain unchanged with zero
count-aware additions/removals against029. Partial results do not qualify this
attempt or the following source.

The actual browser build artifact reports TS2352 at RegistryFormPage.test.tsx81:
its directly asserted RegistryDTO fixture omits required fields. The frontend
build fails before Playwright starts; there is no browser-case acceptance.
The exact 6,172-byte artifact supplies only the selected 8,664-byte frontend
build log, SHA256
`9a86b1e4d253ab58460528ff9f6cde737c79ed14b7afa8dbf314241c03ee5ed1`.
Two earlier bounded frontend-log requests stop at their 1 MiB retention and
4 MiB response limits; their failures and owned-process cleanup remain retained.
No video, trace, screenshot or browser HTML was extracted.

Three finite reviewed proposals compose eight frontend paths. Package and
file-risk evidence now expose the shared table CSV control. React-rendered
package, path and risk cells provide explicit values; layer digests/indexes,
paths, versions/ecosystems, reasons, risk types and zero UID/GID values are
covered by complete filename/header/row assertions in the existing case.
Compliance evidence waits for the same empty-status value, 100 rendered rows and
the actual enabled descending Observed control before the original ascending
sort click. Registry fixtures return a complete RegistryDTO without assertions
or relaxed types; existing credentials, payload and lifetime checks remain.

Response Catalog and Deployment Action editors also reuse useEditorVisit,
including owner/target scope keys and inner mounted lifetime checks. Only late
navigation is conditional; safe invalidation, response preview, deployment
revision/current-cache checks, duplicate submission guards and payloads remain.
All 58 existing cases are retained, with six held-save roundtrip/unmount cases
added. The four-path proposal based ona4 has exact unchanged preimages onea20;
root verified all fifteen checksum records and all four Git/current bytes.
The two CSV paths have ten verified records; the two test-repair paths have
eight. Source/import receipt is
`/root/constellation-console-followup-root-import-v2.json`, SHA256
`2249aba2d9877fd7248b1f2d74726b596ca21518c8d5940c9a883384f2eef47f`.
No local application test, compiler or build is invoked below the retained startup
reserve. Forecasts are 2,425 global frontend cases, 371 cases in eleven affected
files, unchanged Timeline30 and 285 browser cases. Hosted qualification is
required; none of these forecasts receives pass credit. No Go source, deployed
payload, scheduler state or canonical acceptance count changes.


### Helm 88 and schedule concurrency protection (2026-10-19)

API and frontend source ace2a49 are deployed after fresh completed CNPG backup
`constellation-pre-console-c9fcd11-20261019`, backup ID `20261019T024500`, stopped
2026-10-19T02:52:33Z. Helm 88 is deployed and schema stays 180. Seven Deployments,
the runtime DaemonSet and intended StatefulSet replicas are ready. The public
login page loads the new branding without page errors; all 200 frontend file
hashes and the running API binary match the artifacts. Health/readiness return
200; anonymous auth/me and schedule-list requests return 401. The normal Helm
upgrade retains the previous chart values except API/frontend image tags.
Scheduler/enforcement remain unchanged. Existing base-image packages are inherited;
this rollout does not claim an OS vulnerability reduction.

The new schedule patch precondition rejects an outdated editor timestamp, and
its UPDATE predicate rejects changes committed after the handler read. PostgreSQL
regressions cover stale versions, no overwrite, one successful-update audit,
foreign-organization rejection, and an actual blocked UPDATE behind a concurrent
transaction. Four schedule patch/request cases pass twice in shuffled order;
all 80 schedule UI cases and eight production-build browser cases pass. The UI
retains failed drafts and gives conflict-specific guidance. TypeScript and Vite
pass. Initial c9fcd11 typechecking hit an explicitly imposed 768 MiB heap limit;
the 1536 MiB attempt passed. New full hosted CI remains pending.

Evidence and logs: `/tmp/constellation-release-c9fcd11/`, including
`deployment-verification.json`, `schedule-conflict-go-tests-final.log`,
`schedule-conflict-ui-tests.log`, `conflict-browser.log`, and `helm-upgrade.log`.
The directory also contains private Helm values and must not be published wholesale.
The T3 browser remained unavailable after setup, with the AppArmor sandbox error;
bootstrap login returned 401. The user's reported sign-in did not expose a tab to
the tool. No authenticated main-browser acceptance is claimed.

Read-only image triage is recorded in the canonical plan. Historical pods and
image findings must be separated from exact running digests before stating current
critical/high totals. Image hardening adds one open acceptance row (66 checked /
88 open). Existing lint/gosec/history debt remains unwaived.


### Minimal API runtime qualification and Helm 89 (2026-10-19)

Source 670f3b9 replaces the API's general Debian runtime with a signature-verified
Distroless static-debian13 base pinned at
`sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3`.
CA roots, UID/GID 10001, account/home, API/CLI and timezone compatibility remain.
Both actual binaries embed timetzdata and have no ELF interpreter. The runtime
probe runs without network, with read-only root/all capabilities dropped; it is
now included in the existing browser CI workflow. Shellcheck passes.

Trivy 0.69.3 uses one DB updated 2026-10-19T00:45:30Z for both images: previous
API 4 critical, 63 high, 103 medium, 87 low, 2 unknown; release API 0 critical,
1 high, 2 medium, 0 low, 1 unknown. All 255 OS-package findings disappear; remaining
Go-package findings are unchanged. OS package inventory changes 91 → 6; Go module
inventories remain API 139 / CLI 56. Before/after CycloneDX SBOMs and raw reports
are retained. These package findings do not prove exploitability or all-image
security. Docker-reported size changes 1.98 GB → 136 MB.

Both candidate and release start against fresh, isolated schema-180 PostgreSQL
and pass schema-check, health/readiness 200 and protected anonymous 401 checks.
The release's API-only upgrade completes as Helm 89, reusing the same-day completed
Helm 88 backup and retaining the prior image for rollback. No schema, worker or
enforcement configuration changes. All seven Deployments, runtime DaemonSet and
intended StatefulSet replicas are ready. Live health/readiness and anonymous
rejection pass. Running config digest 45cf86b1c8c9f58b8ce6669124eb5810c8163c3ecc19b7c860d432ae698de2e6
matches the amd64 manifest reached from the built OCI index
678bd8174dc95f0282b73d13c796ac997ce171a1cfc5239f460fe8ad29fe054a.
An initial direct index-vs-config comparison failed because these identify different
OCI objects; the corrected graph verification passes. Full hosted CI and authenticated
main-browser acceptance remain pending/unverified respectively.

Evidence root: `/root/constellation-image-hardening-20261019/`, with hashed
`evidence-manifest.json`. The first DB download failed when the separate /tmp
filesystem filled; the task's artifacts were moved to /root with symlinks retaining
old paths, and a separate disk-backed download completed. Failed partial data/logs
remain. This operation did not remove prior evidence or alter production scanner
cache files. The original Helm 88 evidence now resolves through its /tmp symlink.


## Current exposure reporting (Helm 92, 2026-10-19)

Latest deployment: **Helm 92 / schema 181**. API source **b7c72f6**;
discoverer, frontend and migration source **ab83212**. Scanner remains 1d94b2d
and runtime ef0ca39. Fresh CNPG backup `20261019T034312` completed before rollout.
All seven Deployments and the runtime DaemonSet are ready. API, discoverer and
frontend running configuration digests match their built OCI graphs.

The reported constellation-system totals **583 critical / 3,804 high** were open
vulnerability occurrences across assets, including retired pods and repeated
vulnerability IDs. The cluster tile now separates distinct current critical/high
vulnerability IDs from historical pod occurrences and unverified occurrences.
A complete cluster-wide pod LIST supplies an expiring inventory snapshot. Failed
or partial LISTs do not replace it; stale/missing inventory displays an unknown
current total. Newer findings than a snapshot remain unverified rather than being
classified historical. Findings remain open; this does not resolve vulnerabilities.

Authenticated live acceptance shows **34 current critical / 166 current high**.
The original 4,387 occurrences reconcile as **810 current + 1,898 historical +
1,679 unverified**. Current counts are explicitly incomplete while unverified
findings remain. Exact runtime image digest matches can establish current image
presence; unmatched images remain unverified. Workload matching uses namespace
and pod name because legacy assets lack pod UID, so replacement generations with
the same name can overstate current exposure. Inventory presence also does not
prove that a fresh scan of every current container has completed.

Validation: isolated PostgreSQL classification/tenant/freshness tests, discoverer
failed/partial inventory tests, API/schema checks, four frontend tests, TypeScript
and production build pass. Production browser fixtures cover fresh and stale
inventory. A fresh database migrates through 181 and the API starts read-only with
all capabilities dropped; health/readiness return 200 and protected anonymous
requests 401. Authenticated live browser validation confirms the new card, API
counts and reconciliation with no JavaScript errors. T3 preview is unavailable
because of the host browser sandbox; Playwright was used after that explicit error.
The exact rebuilt API still scans at **0 critical/high/medium/low and 1 unknown**
with the earlier Trivy database. This reporting change does not claim an additional
vulnerability reduction. Discoverer platform-facts reporting still logs a cluster
scope 403 and remains a separate validation gap.

Evidence: `/root/constellation-presence-20261019/` (selected test logs,
`live-result.json`, `live-exposure.png`, `live-digests.json`, API scan and migration
smoke results). Private browser session state is excluded from published evidence.
No parent acceptance row closes: **66 checked / 88 open**. Remaining image,
registry-resolution and scanner-cache work below stays open.

## Scanner database verification and recovery acceptance (2026-10-19)

Source `1a8fae7` addresses a live failure where Grype's updater exited successfully
but its reused database failed checksum validation. The former five-second status
deadline also expired against a healthy live database whose validation took about
eight seconds. Validation now permits one minute, respects cancellation, and
reports unavailable when it cannot complete. Refresh success requires a valid
installed revision; disabled engines are skipped and concurrent refreshes serialize.

Online Grype recovery imports the recorded HTTPS archive only when it contains a
valid SHA-256 checksum. The old database is not deleted before import. Post-import
validation must pass before the downloaded revision or success log changes. Offline
mode remains a no-op. Missing or unsafe archive provenance still requires operator
repair. This does not add a full SQLite integrity check to Trivy's metadata probe.

Validation evidence in `/root/constellation-db-recovery-20261019/`:
- Full scanner command tests pass, including slow checksums, cancellation, disabled
  engines, invalid metadata after exit zero, failed import, unsafe URLs and invalid
  post-import databases. The refresh/snapshot race test passes.
- Opt-in real-tool acceptance uses Grype 0.120.1 with deliberately invalid import
  metadata in an isolated cache. The updater is forced to reproduce the observed
  no-op; status and import use the real executable. Recovery completed in 85 seconds,
  then verified revision `2026-10-18T06:27:17Z` with ready/applied/download agreement.
- The release image starts with a read-only filesystem, no network and all
  capabilities dropped. Its same-database Trivy scan remains **0 critical / 31 high /
  45 medium / 3 low / 5 unknown**. No additional vulnerability reduction is claimed.

During acceptance, compilation and database staging crossed the shared development
node's disk threshold, causing pod evictions. Disposable test/compiler caches were
removed. Catalog inspection then identified 162 unreferenced anonymous PostgreSQL
16 volumes containing only `constellation_test`, `postgres` and template databases;
removing those reclaimed 30.34 GiB. A manifest and per-volume removal results were
retained. Application data and backups were not removed. Kubelet uses a 5% eviction
threshold, 10% minimum reclaim and five-minute pressure-transition interval. Future
heavy validation needs storage headroom above that recovery margin, not just above
the initial eviction threshold.

Helm 93 deployed scanner source `1a8fae7` without a schema change. After disk
pressure cleared, local release images removed by image GC were reimported from
exact retained builds, including the Barman plugin required for CNPG reconciliation.
CNPG returned healthy, all seven application Deployments and the runtime DaemonSet
became ready. The rebuilt scanner image/configuration digest matches, and
health/readiness return 200. Heartbeat metadata reports both engines ready with
matching download/applied revisions. A live CLI scan of `registry.k8s.io/pause:3.10`
with offline databases and signature verification disabled completed with zero
detected packages/findings and no engine errors. The authenticated cluster page
passes with no JavaScript errors and reconciled occurrence totals. Free disk space
after image restoration is approximately 57 GiB. Registry-backed releases remain
necessary to remove the manual reimport dependency exposed by image GC.


## Runtime policy delivery reverification (2026-10-23)

Main source `241e096752396c54e4c7c47ae4801cf8a26b9e74` already includes the
agent policy-sync startup path and the workload-scoped transport introduced by
`bf91eadcb8b91f86364e0c555f27b096a23e623c`. H6's missing-caller finding is closed
without a new production change. The worker fetches protocol-v2 bundles and sends
modify/delete commands through `Supervisor.PushEndpointPolicy`, which checks the
current endpoint registration and native process generation before transfer.

Fresh evidence is retained in `/root/constellation-h6-20261023/`:

- `bundle.json`: `TestAgentPolicyBundle*` and `TestRuntimePolicy*Binding*` passed
  twice with race detection and shuffle against disposable real PostgreSQL:
  24 test/subtest executions, no skips. Coverage includes wire fields, disabled
  policies, tenant/cluster ownership, exact pod bindings, and protocol validation.
- `native/`: `ARTIFACT_DIR=/root/constellation-h6-20261023/native bash
  scripts/test-native-policy.sh` built the vendored C sources from this checkout,
  verified source and binary manifests, generated fixtures through the real sync
  worker, and passed the native acceptance test twice without skips. Each run
  checks 70 matcher/packet-wrapper assertions through the production Go datagram
  encoder, including independent MAC scopes, deny/monitor/default actions,
  direction, ICMP, incomplete replacement, scoped deletion and restart replay.
  Wrong expected actions and malformed/unknown controls were rejected as expected.
- The same script passed both native connection-report variants (97 aggregation
  and 66 wall-clock assertions each). Both unpatched negative controls failed for
  their expected reasons. Build logs, image identity, fixtures, JSON results and
  source/object/binary provenance are retained beside these results.
- `check.log`, `unit.json` and `unit.xml`: the full `make check` gate passed,
  including lint/vet/format/shell checks, frontend lint/type-check/build and the
  race-enabled unit suite. GitHub Actions remains disabled for this repository;
  these are local results.

The native containers use no network, run as a nonroot user with capabilities
removed, and do not attach to a workload interface. This proves the missing
policy-delivery path and native parsing/staging/matching behavior. It does not
establish live CNI interception, DNS-derived FQDN enforcement, application
classification, session re-evaluation, or production packet drops. No live policy
or deployment was changed during this reverification.


## Admission database Secret reverification (2026-10-23)

Main source `54326342af24b90f964d4a404cbf2aa6cc3e9b67` already routes quarantine,
policy and audit DSNs through the shared database Secret helpers. H7's historical
`<fullname>-postgres` / `dsn` reference is absent. No deployment-template behavior
changed in this follow-up. Configuration comments now describe shared external
DSNs and the explicit quarantine cluster ID requirement.

The new `scripts/test-helm-admission.sh` runs as part of `make helm-template-smoke`.
Using Helm 4.3.1, it parses seven complete rendered configurations: CNPG, renamed
release resources, external inline DSN, existing Secret with default key, existing
Secret with custom key, per-feature DSN overrides, and disabled database features.
For generated Secrets it checks that each admission reference resolves to the
expected DSN value. For customer-owned Secrets it checks the configured name/key
and that the chart does not overwrite the Secret. All three DSN references remain
required, and enabled features carry the expected cluster arguments.

Evidence is retained in `/root/constellation-h7-20261023/`:

- `admission-chart.log`: all seven rendered configurations pass.
- `historical-negative.log`: a disposable chart copy restores the historical
  quarantine reference to `<fullname>-postgres` / `dsn`; the test rejects that
  reference in the CNPG case. The source checkout is unchanged by this control.
- `helm.log`: `make helm-lint helm-template-smoke` passes, including the existing
  HA and identity checks and the new admission cases.
- `check.log`, `unit.json` and `unit.xml`: full `make check` passes, including
  shellcheck, lint/vet/format, frontend lint/type-check/build and the race-enabled
  unit suite (3,135 tests reported, 8 opt-in skips). GitHub Actions remains disabled;
  these are local validation results.

This is rendered-chart acceptance. It does not connect to an external database,
create customer Secrets, start admission pods, or establish live webhook readiness
or quarantine enforcement. No live deployment or policy was changed.


## Operator policy RBAC reverification (2026-10-23)

Main source `3e3447372f11e767aa2f75a02cabe4c4bf2acbff` already includes H8's missing
admission/response policy CR permissions. The controllers read/watch policy CRs,
update their objects to manage finalizers, and update status; the chart grants
those operations and binds them to the deployed operator ServiceAccount. The CRDs
are cluster-scoped even when `namespaced=true` limits the namespaced workload
cache. Policy-controller startup still requires a configured database DSN.

The new `scripts/test-helm-operator.sh` is part of `make helm-template-smoke`.
Helm 4.3.1 renders both workload scopes with default/custom resource names in a
nondefault release namespace, plus an operator-disabled case. Assertions follow
the Deployment account, ServiceAccount, ClusterRoleBinding subject/role reference,
and ClusterRole rules. They verify the shipped admission/response CRDs and status
subresources, required verbs, unrestricted resource names, absence of wildcard
grants, watch namespace configuration, and disabled-resource omission.

Evidence is retained in `/root/constellation-h8-20261023/`:

- `operator-chart.log`: all five rendered configurations pass.
- `historical-missing-rbac.log`: deleting the admission/response policy grants in
  a disposable chart copy fails on missing admission-rule permissions.
- `missing-object-update.log`: removing the object `update` verb fails even when
  `patch` and finalizer/status grants remain present.
- `wrong-subject.log`: changing the policy binding's subject namespace fails.
  These controls do not modify the source checkout.
- `helm.log`: `make helm-lint helm-template-smoke` passes, including the new
  operator cases and existing HA, identity and admission checks.
- `check.log`, `unit.json` and `unit.xml`: full `make check` passes, including
  shellcheck, lint/vet/format, frontend lint/type-check/build and the race-enabled
  unit suite (3,135 tests reported, 8 opt-in skips). GitHub Actions remains disabled;
  these are local validation results.

This is rendered-chart acceptance, not an API-server authorization decision or an
end-to-end GitOps reconciliation run. No controller startup, database write, live
RBAC change or deployment was performed. The follow-up adds tests and evidence;
production permissions remain unchanged.


## Ten-item security and lifecycle continuation (2026-10-23)

Baseline `f63b06072f09424660f1a456f3adae3882cb4e9f` was reviewed for ten explicit
items: H9, H10, H11, H12, DB-01, DB-02, DB-03, DB-04, DB-16 and DB-18. The remaining
security findings are already fixed in production source; this follow-up makes
their regression coverage current and records the verified closure. Database
rollout, capacity, alarms and recovery gates remain open; local tests do not
establish those operational outcomes.

| Item | Result of this continuation |
| --- | --- |
| H9 | Removed the manual `DATABASE_URL` prerequisite and shared-chain truncation from three audit tests. Each uses its own migrated Postgres database. Sixteen writers mix `Log`/`LogInTx` across two organizations, append exactly 400 rows and verify the full chain. Caller rollback and tamper protection also pass. |
| H10 | Added a real-Postgres first-OIDC-session regression: immediate authentication, stale epoch rejection without persisting a session, old-session revocation, and successful fresh login after revocation. |
| H11 | Extended HTTP/database replay coverage to both clusters twice, changed FAIL to PASS with stable row identity, and proved repeat ingestion for another node retains separate statuses without duplicates. |
| H12 | Re-ran real-Postgres generated-policy coverage for bare external peers: FQDN, IP-only CIDR and missing-address exclusion. |
| DB-01 | Re-ran partition-collision pruning and lock/batch preservation tests for events and network flows. |
| DB-02 | Re-ran failed/lagging fold, late-arrival, refold-after-prune and fold-gated partition-expiry tests. |
| DB-03 | Added persisted first-boot seeding and restart/idempotence coverage preserving zero holds and custom windows; default/legacy-hold checks also pass. |
| DB-04 | Added three-family, two-organization coverage for longest-window selection and independent event/flow holds; existing invalid-config and read-error protections pass. |
| DB-16 | Added current-schema cleanup acceptance for all four families: bounded batches, locked rows, reused session IDs across nodes/clusters/organizations, live-row and audit preservation, and partial failure. Fixed stale metric/log names from the identity cutover. |
| DB-18 | Re-ran feed content/cursor atomicity, identical-repeat write avoidance, correction, rollback, replica-lock, restart, catch-up and mirror-change tests. |

Evidence is retained in `/root/constellation-next10-20261023/`. Focused race/shuffle
runs passed twice; `focused-existing.json` retains an initial unused-import build
failure in the audit package, corrected before the passing `audit-identity.json`.
Other focused results are in `focused-new.json` and `retention-families.json`.
`session-before.json` captures the reporting regression: cleanup succeeds, but the
current `oidc_login_attempts` metric remains zero before the label correction.

Compiler overlays avoid editing the production checkout for negative controls:
`audit-negative.log` restores the historical moving-row lock and detects a chain
break; `external-negative.log` restores prefix-only external detection and rejects
the resulting policy preview. Both fail for their expected assertion, rather than
for setup or compilation errors.

The cleanup metric family values changed from `refresh_tokens` / `user_sessions`
to `oidc_login_attempts` / `identity_sessions`, matching the tables actually reaped.
The cleanup log fields and Go result fields follow the same correction. Custom
metric queries using the retired family values must be updated. Deletion SQL,
retention windows and production audit hashes were not changed.

All database mutations were confined to disposable fixtures. This is not a new
live-issuer/browser login proof, live Cilium enforcement test, repair of historical
audit corruption, deployment, or live retention run.

Full gates passed: `make check` reports 3,135 tests with 8 opt-in skips, and
`make test-integration` reports 4,932 tests with 14 opt-in skips. The three audit
tests previously skipped for lack of `DATABASE_URL` now execute in the standard
integration gate. JSON/JUnit results and logs are retained as `unit.*`,
`integration.*` and `check.log` in the evidence directory. GitHub Actions remains
disabled for the repository; these are local results. No Helm templates changed.

## Audit archive continuation — ten implementation items (2026-10-23)

This batch implements ten concrete audit-archive improvements under DB-07/08/09;
it does not close ten entire database-lifecycle policy entries. The detailed
publication, upgrade and replay contract is in [audit-archive.md](audit-archive.md).

| Item | Implementation and local proof |
| --- | --- |
| 1. Durable catch-up | Destination-specific PostgreSQL progress selects by ID, not event time. Missed-run, backdated-event and restart acceptance uses fully migrated disposable databases. |
| 2. Bounded batches | Configurable 1–10,000 row batches, 256 MiB compressed/uncompressed limits and a CLI deadline; invalid batch settings are rejected by CLI/service and Helm. |
| 3. Concurrent workers | Progress-row locking serializes replica publication. A real-PostgreSQL test appends another audit event during upload and verifies two workers publish disjoint successive batches. |
| 4. Chain boundaries | Signed manifests include ID bounds, first previous hash, first/last chain hashes, count and predecessor manifest. Sequence rollback gaps remain valid; missing/changed chain rows fail. |
| 5. Independent replay | Downloaded archives replay with the canonical database writer algorithm, including IP addresses and nested JSON. A CLI acceptance test succeeds with an invalid DATABASE_URL and AWS endpoint, then rejects a corrupted signature. |
| 6. Signing trust | Durable runs require trusted static keys or explicit keyless identity; wrong-key acceptance fails before publication. Unsigned local previews remain diagnostic only. |
| 7. Object read-back | Every published artifact is downloaded and checked before progress. A local HTTP S3 fixture exercises the actual AWS SDK, conditional PUTs, SHA-256 headers and gzip-preserving GETs. |
| 8. Safe retry | Unique attempt keys and conditional creation preserve partial attempts. Injected data/manifest/signature PUT/GET/corruption and deferred-commit failures retain the old checkpoint; retry safely republishes the pending range. |
| 9. Dry-run isolation | Local runs read progress but never create or advance it; changed bucket, prefix or endpoint starts an independent catch-up. Cancellation also leaves progress unchanged. |
| 10. Ledger protection | Migration 191 blocks TRUNCATE, alongside existing UPDATE/DELETE guards; the seed command preserves audit evidence. SQL acceptance verifies all forbidden operations leave the chain intact. |

Offline tamper tests re-sign modified manifests and recompute payload checksums
where appropriate, so changed/missing/reordered/duplicate rows must be rejected
by actual chain replay rather than only envelope verification. Chart acceptance
covers four rendered configurations and seven rejected trust/batch settings.
Existing artifact permission/symlink and signature/checksum tests moved from the
composition root into `internal/auditarchive` with the implementation.

Evidence is retained in `/root/constellation-audit-next10-20261023/`. Initial full
runs caught the missing `RequiredSchemaVersion` bump from 190 to 191; this was
corrected before the final gates. Those initial logs remain `initial-check.log`
and `initial-integration.log`. No live database, bucket or cluster was changed.
Keyless provider behavior, actual object-store retention/access/hold settings,
fresh-host recovery, live throughput and hot/cold query/pruning support remain
operational or follow-up implementation gates.

Final gates passed: `make check` reports 3,147 tests with 8 opt-in skips;
`make test-integration` reports 4,983 tests with 14 opt-in skips. Helm 4 lint
and the full template-smoke suite pass, including archive trust/batch checks.
The image-contract profile also renders successfully in list-only mode. JSON
and JUnit results are retained as `unit.*` and `integration.*` beside `check.log`,
`integration.log`, `helm.log` and `s3-sdk.log`. GitHub Actions remains disabled;
these are local acceptance results, not hosted CI or live object-store proof.

## Storage visibility continuation — ten implementation items (2026-10-23)

This batch implements ten concrete observability items under DB-23. It does not
close ten whole retention-policy decisions. See [storage-health.md](storage-health.md)
for the metric contract, installation settings and response runbook.

| Item | Implementation and acceptance evidence |
| --- | --- |
| 1. Relation allocation | Fixed-root table/index/total and database byte metrics. Real PostgreSQL checks physical partition leaves once, including nested children and TOAST/index accounting. |
| 2. Dead-row estimates | Live/dead statistics per fixed root, with a nonzero dead-tuple fixture and a tested ratio/minimum-population warning. These remain PostgreSQL estimates. |
| 3. DEFAULT occupancy | Byte and estimated-row metrics use catalog ancestry; renamed and nested DEFAULT children remain visible. |
| 4. Rollup lag | Committed watermark timestamp and a stale-progress warning, without changing fold-gated raw expiry. Healthy/stalled fixtures exercise the rendered expression. |
| 5. Active archive progress | The same destination hash as publication, exact BIGINT subtraction before float conversion, missing-checkpoint visibility and stalled/backlog rules. Retired destinations, empty endpoint Secrets, disabled and idle archives are covered. |
| 6. Backup health | Aggregate each enabled organization's latest successful catalog row; report missing successes, failed attempts and overdue/uninitialized schedules. Other tenants, disabled schedules and pg-dump rows cannot mask failures. Migration 192 provides the indexed latest-success lookup, verified with EXPLAIN. |
| 7. WAL generation | Instance-wide generated-byte counter and reset timestamp, with a tested rate warning. This does not claim retained WAL disk occupancy. |
| 8. Collector health | One-minute cache, concurrent scrape reuse, read-only transaction, bounded SQL/lock/overall deadlines, invalidation on failure and recovery. Read-only role acceptance requires neither superuser nor write grants. Old DB-health query failures also gain an alert. |
| 9. Executable alerts | Twelve release-scoped rules evaluated by promtool in 23 scenarios, including positive, negative, absent-data and same-replica health matching cases. Native and digest-pinned Docker promtool execution both pass. |
| 10. Dashboard/runbook | Optional 14-panel Grafana ConfigMap with 15 parsed PromQL expressions, appropriate replica aggregation, warning-budget configuration and safe investigation/rollback guidance. Live Grafana rendering is a deployment gate. |

Evidence is retained in `/root/constellation-storage-next10-20261023/`.
`monitoring-fixtures/` contains rendered chart cases, extracted rules, dashboard
expressions and portable Prometheus test cases. Helm, actionlint, PostgreSQL
fixtures and the actual Prometheus evaluator run locally; GitHub Actions remains
disabled. The workflow now preloads the pinned Prometheus test image if CI is
later enabled, while local tests never pull images implicitly.

Compiler overlays restore stale-cache reuse and premature floating-point ID
subtraction without editing the production checkout. Both fail at their expected
assertions in `collector-negative.log`. A rendered-rule mutation that makes the
database warning unreachable fails the expected alert fixture in
`prometheus-negative.log`; changing a threshold therefore cannot pass merely
because the YAML parses. An initial mutation matched no text because Helm emitted
the threshold in scientific notation; the corrected mutation is the failing
negative control. The first full suites passed before the final ID-precision
correction; final gates were rerun afterward.

No live alert, volume, cluster, retention rule or data cleanup was changed.
Capacity budgets, actual scrape/notification delivery, retained WAL occupancy,
scanner-cache filesystem headroom, raw-retention/drop lag and recovery drills
remain open. Organization backup catalog health is not PITR or recoverability
proof, and archive ID distance is not an exact backlog row count.

The full integration rerun also exposed an unrelated pre-existing fixture error:
`TestBaselineInventoryReadOnlyFullCohortAndBundle` inferred an expected 400 from
any query ending in `bad`. A random valid UUID ended in those three characters,
so the correct 404 response failed the test. Explicit expected-status cases now
include a deterministic valid UUID ending in `bad`; the focused test passes ten
consecutive race-enabled runs. Production authorization/handler behavior was
unchanged. The original failure is retained in
`integration-uuid-suffix-failure.log`, with focused results in `baseline-fixture.log`.

Final gates passed: `make check` reports 3,152 tests with 8 opt-in skips, and
`make test-integration` reports 4,996 tests with 14 opt-in skips. Helm 4 lint and
the complete template-smoke suite pass, including all 23 Prometheus scenarios.
Actionlint passes for the updated CI workflow. JSON/JUnit reports are retained
as `unit.*` and `integration.*` with the final `check.log`, `integration.log`,
`helm.log`, `docker-promtool.log` and `actionlint.log` in the evidence directory.
Repository Actions permissions were checked and remain disabled.

## Scanner-cache diagnostics continuation (2026-10-23)

The [ten-item cache diagnostics contract](scanner-cache-diagnostics.md) covers
exclusive write probes, lifecycle error handling, path classification, byte
capacity, inode headroom, bounded enumeration, root confinement, partial usage,
stable/checked totals and API propagation. These are DB-21/23 implementation
prerequisites; topology, refresh capacity, alerts and live rollout remain open.

Real filesystem tests exercise the old predictable-name symlink trap, 32
concurrent probes, missing/unavailable/non-directory paths, counter overflow and
inconsistency, inode exhaustion/unknown totals, exactly 2,000 and over-limit
entries, nested largest-file ordering, symlinks, FIFOs and enumeration failure.
The API unit test retains zero, false and absent values distinctly. The existing
PostgreSQL heartbeat-to-cache-stat integration test now asserts those fields
survive JSONB storage and the HTTP response.

A Go overlay restored the unsafe predictable-name probe without editing the
checkout. `TestCacheProbePreservesPreexistingSymlink` failed as intended because
the external fixture changed from `preserve` to `ok`. The fixed implementation
passes; the negative-control log is
`/root/constellation-cache-next10-20261023/negative-probe.log`. No real cache,
cluster configuration, scanner image or database retention policy was changed.

Final gates passed: `make check` reports 3,163 tests with 8 opt-in skips;
`make test-integration` reports 5,007 tests with 14 opt-in skips. Lint, vet,
formatting, shell checks and the frontend type/build/bundle checks all pass.
Final logs and JSON/JUnit reports are retained under
`/root/constellation-cache-next10-20261023/`. The initial passing runs predated
final root-confinement/counter hardening and the extended database HTTP assertion;
the final runs above include all changes. GitHub Actions remains disabled. Chart
and deployment resources were unchanged, so Helm/live deployment checks were
not part of this batch.

## Scanner-cache monitoring continuation (2026-10-23)

Ten [monitoring implementation items](scanner-cache-monitoring.md) add scanner-local
byte/inode capacity, explicit path states, serialized TTL snapshots, failed-sample
invalidation, bounded private labels and pressure/configuration/collection alerts.
Collection is read-only and does not enumerate or evict cache files. This is a
separate path from the existing heartbeat's bounded usage walk; the previous
statement that ordinary heartbeats omitted enumeration has been corrected.

Tests gather a pedantic Prometheus registry against real temporary directories,
check HTTP exposition, configuration copying and path/label privacy, and exercise
missing/disabled/unconfigured paths. Failure/recovery tests replace a real directory
with a file, verify old capacity disappears and the last-success timestamp stays,
and perform 32 concurrent gathers without bypassing retry backoff. Independent
cache failures do not remove healthy sibling data. Counter fixtures cover reserved
blocks, inconsistent/overflowing counters, zero totals and inode exhaustion.

Helm 4 lint and the full template smoke suite pass. The new suite validates
ServiceMonitor-to-Service-to-Deployment selectors, disabled/default toggles,
scanner disablement, separate rule namespace and rejected threshold values.
All eight scanner-cache alerts pass 33 actual Prometheus scenarios using both
the native binary and preloaded digest-pinned Docker fallback. Existing storage
rules/dashboard queries and their 23 scenarios also pass unchanged.

A negative control replaced the low-byte rule with an always-false expression;
its expected-alert fixture failed as intended. Evidence is under
`/root/constellation-cache-monitoring-next10-20261023/` (`monitoring.log`,
`helm.log`, `docker-promtool.log`, `negative-alert.log` and rendered fixtures).
The initial quality run rejected excessive nesting in the new refresh function;
metric encoding was extracted and the gate restarted. The original lint failure
is preserved as `check-nesting-failure.log`.

No SQL, migrations, cache topology, live scraping or notification routing changed.
DB-21/23 live acceptance, refresh/offline/restart qualification and capacity budgets
remain open. GitHub Actions permissions were checked and remain disabled.

Final `make check` passed with 3,168 reported tests and 8 opt-in skips, including
lint, vet, formatting, shell checks and frontend type/build/bundle checks. No SQL
or migration changed, so the PostgreSQL integration suite was not repeated.
Final Helm lint/template-smoke and all 33 scanner-cache scenarios pass. The two
additional cases verify isolation across optional cluster labels; restoring the
restricted label join makes the cross-cluster negative control fail as expected
(`negative-cluster.log`). Native and Docker promtool both pass the final rules.
Final logs plus unit JSON/JUnit reports are retained in the evidence directory.

## Ten storage-alert isolation fixes (2026-10-23)

Nine data alerts and the missing-exporter alert now use the isolation contract in
[storage health](storage-health.md#ten-storage-alert-isolation-fixes-2026-10-23).
Data alerts retain all target labels across collector/scrape-health joins, ignoring
only reserved application dimensions where needed. Failed scrapes suppress stale
warnings. Missing exporter/scrape health is reported per discovered target instead
of being hidden by another replica's successful collection.

The storage suite now evaluates 75 real PromQL scenarios, including each data
alert with matching extra labels, mismatched cluster/Prometheus/instance health,
and failed local scrapes alongside healthy remote-cluster scrapes. Archive-enabled
and progress signals are isolated too. Discovery cases distinguish absent targets,
missing exporters, failed scrapes and an exporter that is present but reports a
failed database query. Existing 12 rule definitions, 15 dashboard expressions and
33 scanner-cache scenarios remain valid.

An isolated negative control restores the restricted health joins and global
absence expression. All ten selected regression cases fail as expected; the real
rules pass. Logs and rendered fixtures are retained in
`/root/constellation-storage-isolation-next10-20261023/`, including
`negative-controls.log`, `monitoring.log`, `helm.log` and `docker-promtool.log`.
No SQL, migration, Go runtime, alert thresholds, retention policy or live resources
changed. Monitoring activation and DB-23 capacity/recovery gates remain open.

Final `make check` passed: 3,168 reported tests, 8 opt-in skips, with lint, vet,
formatting, shell and frontend type/build/bundle checks green. Helm 4 lint and the
full smoke suite passed; native and Docker promtool both pass the final 75 storage
scenarios. Unit JSON/JUnit reports are retained with `check.log`. No database
integration rerun was needed for this chart/test/documentation-only change.
Repository Actions permissions were verified disabled.
