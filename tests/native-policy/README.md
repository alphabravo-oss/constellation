# Native runtime-policy acceptance

Run from the repository root:

```sh
ARTIFACT_DIR=/tmp/native-policy-proof bash scripts/test-native-policy.sh
```

Requires the local Docker engine and the normal Go toolchain. The script builds
unchanged vendored NeuVector C sources, then links a test-only executable from
copied objects. `objcopy` exposes native control/parser, endpoint-map and matcher
functions and renames the unused daemon `main`; no production or vendored source
is modified. The test build retains the native `-Os` optimization and disables inlining
and interprocedural cloning to preserve these local symbols. Source/object/binary hashes, image ID, compiler commands,
Go fixtures and structured results are retained in the artifact directory.

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
against the current checkout; a mismatch fails before generating proof.

To reuse an already built matching test image:

```sh
NATIVE_POLICY_SKIP_BUILD=1 \
CONSTELLATION_NATIVE_POLICY_IMAGE=constellation/native-policy-test:<qualified-tag> \
ARTIFACT_DIR=/tmp/native-policy-proof bash scripts/test-native-policy.sh
```
