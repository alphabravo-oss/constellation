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
follow-ups now pass the isolated eight-file qualification recorded below. They
remain undeployed; no binary/image qualification or live smoke is claimed for
these files. The federation correction retains trusted private endpoints,
implicit-token destination binding and redirect refusal. Credential/state
transaction semantics remain unchanged. This source evidence is separate from
the deployed c5428cc evidence.

The separate runtime source audit identified cumulative DP counters satisfying
readiness after process exit or while a replacement awaits its first reply.
The source correction is qualified below and remains undeployed; this was not
an observed live outage. Original audit:
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
recorded below; its deployment remains pending. These eight files are
**source-qualified, not deployed**:
main remains Helm 85/schema 180 with c5428cc API/scanner/runtime-agent images.
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

The import is onto b5e4200, where the three original file hashes still match
the frozen base. The preceding eight notifier/backup/federation files retain their
separate qualification; no combined eleven-file run, binaries/images, deployment
or live readiness acceptance is claimed here. Main remains Helm 85/schema 180
with c5428cc API/scanner/runtime-agent images. Native/Flannel, fresh tap, broader
enforcement/CNI/HA and recovery acceptance remain open. No parent checklist item
is closed; the plan remains 66 checked / 87 open.
