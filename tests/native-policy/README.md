# Native runtime-policy acceptance

Run from the repository root:

```sh
ARTIFACT_DIR=/tmp/native-policy-proof bash scripts/test-native-policy.sh
```

Requires the local Docker engine and the normal Go toolchain. The script builds
vendored NeuVector C sources plus the declared local correctness patch, then links a test-only executable from
copied objects. `objcopy` exposes native control/parser, endpoint-map and matcher
functions and renames the unused daemon `main`; the source checkout is never edited by the test runner. The test build retains the native `-Os` optimization and disables inlining
and interprocedural cloning to preserve these local symbols. Source/object/binary hashes, image ID, compiler commands,
Go fixtures and structured results are retained in the artifact directory.

The connection reporter entry point first calls actual `dp_ctrl_connect_report`
and RCU comparison with deterministic test clock globals exposed on copied
objects. Its 97 assertions cover application-specific folding, counters,
first/latest observation semantics, original tuple dimensions and batch isolation.
A standard-flags binary and an identical pattern-initialized binary must pass.
Reversing only the declared lookup patch and initializing otherwise indeterminate
stack values produces a deterministic failure (two HTTP1001 buckets instead of
one). The negative compiler option is not used by the standard binary. It does
not explain or waive the separate Protect packet-evidence failure.

The first Go test runs the production runtime-policy sync worker against an
owned HTTP fixture. The second uses the production Go IPC encoder over a
private Unix datagram socket and feeds those exact datagrams to the native
Jansson/control functions. Queries call the actual native policy wrapper and
key/range/application/default matcher. A deliberately incorrect expectation must
fail in C; malformed/unsupported commands must also fail.

The native processes are disposable nonroot containers with no network,
capabilities, host namespaces or mounts, and a read-only filesystem. Their MACs
are in-memory endpoint records; no TAP/NFQUEUE ports, daemon control sockets,
shared memory, iptables or host network resources are created.

Coverage includes two workload MACs, protect versus monitor, nested application
rule attribution, independent defaults/directions, port/IP wildcard translation,
ICMP off/on/off isolation, incomplete fragments, retry, and scoped/shared-handle
removal. This proves native parser/staging/matching behavior. It does **not** prove
CNI interception, physical packet drops, session re-evaluation, DNS resolution,
parser application identification, or live cluster enforcement.

Builds discard copied objects/dependency files and force recompilation. Reuse
checks the entire vendor source manifest plus the C harness and Dockerfile
against the current checkout; a mismatch fails before generating proof. All
recorded native harness binary hashes are verified before dispatch. The runner
selects only fixed entry points, explicit UID65534, no network/capabilities/mounts,
and no-new-privileges. Existing policy matcher assertions and negative controls
remain unchanged.

To reuse an already built matching test image:

```sh
NATIVE_POLICY_SKIP_BUILD=1 \
CONSTELLATION_NATIVE_POLICY_IMAGE=constellation/native-policy-test:<qualified-tag> \
ARTIFACT_DIR=/tmp/native-policy-proof bash scripts/test-native-policy.sh
```
