# Efficiency measurements and guardrails

Run `GOWORK=off GOFLAGS=-p=4 make bench` for all 25 hot HTTP handlers with a
10,000-row real-Postgres fixture and the shared identity RP verifier. The fixture
uses the normal disposable pgtest database and is deleted by the test harness.
`EFFICIENCY_ROUTE_FILTER` selects one route family. For repeatable allocation
comparisons, pass `-benchtime=3s -count=3` to `go test`; CPU and memory profiles can
be collected with its standard `-cpuprofile` and `-memprofile` flags. Long
benchmarks issue fresh valid fixture sessions outside timed loops so the normal
per-token rate ceiling remains enforced. Startup
password-hash allocation is not a request-time optimization target.

`make test-integration` includes `TestEfficiencyQueryBudgets`: authenticated
requests through the full router at page sizes 1 and 50. A context-scoped pgx
tracer counts every query hook, including BEGIN/COMMIT and ownership checks,
while independent background refreshes are excluded. Each route has an explicit
maximum, with one query of headroom for a cold role-cache lookup. The fixture
contains 10,000 rows in each inventory source; grouped/summary endpoints return
their natural aggregates. API latency is measured separately from the race test.

The live comparison runs the same harness as a disposable Job on the live node,
through the normal public HTTPS ingress under an isolated path, using a dedicated
`efficiency_probe` database copied from the production schema. It never seeds
production tables. Each route warms its page shape, then collects 20 full-body,
keep-alive HTTPS observations at limit 50; page size 1 checks query scaling.
Very slow warmups reduce observations to three and failed requests retain status
and elapsed time instead of being represented as successful percentiles. Raw
samples/counts and any exceptions belong in the execution handoff. Compare the
same dataset and CPU quota before and after, and remove the Job, ingress,
service, network policy, Secret and database after proof.

Cluster, group, policy and runtime-policy browser inventories now accept bounded
pages (default 100, maximum 500). Existing frontend pickers/tables retrieve all
continuations so they retain complete choices. Agent policy distribution and
portable exports use their existing complete-set reads. Node inventory joins
unique snapshots in sets, and expensive node/container/network-rule summaries
share one SQL statement with the page. Compliance evidence similarly normalizes
once per request. These statement snapshots preserve matching totals and empty
pages. Transactional pgx pools disable JIT compilation because compilation cannot
be reused between executions; the baseline node plan spent 1.52 seconds in JIT.

`make check` builds the frontend and enforces 250,000 gzip bytes across the entire
static entry import graph. `frontend/dist/bundle-report.json` records entry and
lazy chunk gzip sizes. Existing lazy route boundaries keep chart, editor and
graph dependencies out of the initial graph.

`scripts/check-image-size.sh ROLE IMAGE` checks compressed registry layer bytes
for linux/amd64. Release promotion and published-release verification both call
it. `scripts/image-size-budgets.json` caps static Go services at 40,000,000 bytes
and documents bounded tooling exceptions. Compliance scheduling requires cosign;
scanner, toolbox, native runtime agent, benchmark runner and PostgreSQL retain
their required tools/libraries. This is a registry transfer budget, not a claim
that extracted filesystems or mapped executable pages are below 40 MB.

`values-efficiency-dev.yaml` records this installation's measured resource
profile. Main-process RSS is reported separately from cgroup anonymous/file
memory and CPU (which include scanner/signing children). Idle measurements use
30-second deltas. Load sampling uses 60 one-second observations during four
parallel browser readers at one request per second each, 50 admitted server dry runs, one existing-image rescan,
a signed local compliance report without delivery, and controller events on
existing objects. This represents the installed development workload, not
maximum ingestion capacity. Scanner memory retains 2 GiB requested / 6 GiB limit:
a small cached-image scan does not supersede the known larger-image OOM history.
Runtime-agent CPU requests increase to cover its observed steady workload.
