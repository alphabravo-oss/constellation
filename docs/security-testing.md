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
passes 2,336 tests on Node24.21.0, plus typecheck and production build. Exact
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
and wrong-key checks. Main schema180 deployment remains pending; isolated
namespace graceful cleanup was requested. This does not qualify HA, off-host
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
