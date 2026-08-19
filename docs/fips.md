# FIPS 140-3 Mode

Constellation supports a FIPS-validated build mode for customers with FedRAMP Moderate,
DoD STIG, or similar government baselines.

## Build

```bash
# Native Go 1.26+ FIPS mode (uses Go's bundled FIPS 140-3 module via GOFIPS140=v1.0.0).
GOFIPS140=v1.0.0 go build -tags fips ./cmd/constellation-api
GOFIPS140=v1.0.0 go build -tags fips ./cmd/constellation-scanner
GOFIPS140=v1.0.0 go build -tags fips ./cmd/constellation-operator
```

The `fips` build tag is consumed by `pkg/observability` to switch slog's hash function
to FIPS-approved SHA-256 only (the default SHA-3 path is non-FIPS at v1.0.0). When the tag
is set, `pkg/audit.computeChainHash` also asserts the runtime is in FIPS mode at startup —
a non-FIPS runtime with the tag set causes the process to refuse to boot.

## Verifying at runtime

```bash
GODEBUG=fips140=on
constellationctl version --fips     # prints "FIPS 140-3: enabled" when the runtime is in FIPS mode
```

## Container image

`deploy/docker/Dockerfile.fips` builds against the Wolfi-FIPS base image
(`cgr.dev/chainguard/wolfi-base:fips-latest`) which carries the validated OpenSSL FIPS
provider. Customers running on an HSM-backed control plane can additionally point cosign at
the HSM via `COSIGN_KEY_REF=pkcs11:object=constellation;type=private`.

## Cryptographic primitives

In FIPS mode Constellation restricts itself to:

| Primitive | Algorithm |
|-----------|-----------|
| Hash | SHA-256, SHA-512 (HMAC-SHA-256 for chain) |
| Symmetric | AES-256-GCM (audit envelope encryption) |
| Asymmetric signatures | RSA-3072, ECDSA P-256/P-384 (no Ed25519 in 140-3) |
| KDF | HKDF-SHA-256 |
| TLS | TLS 1.2 + 1.3 with FIPS-approved ciphers only |

Anything outside this set is rejected at startup with a clear error.

## Runtime-agent

The runtime-agent (DaemonSet) is a mixed-binary deployment: a Go supervisor + ingest
process and a vendored C data-plane (`third_party/neuvector/dp`). The two halves have
*different* FIPS postures and customers under FedRAMP / DoD STIG need to know which
crypto sits where.

### What IS FIPS-validated when built with `FIPS=true`

The Go agent itself (`/usr/local/bin/constellation-runtime-agent`):

| Crypto consumer | FIPS path |
|-----------------|-----------|
| Outbound TLS to control plane | Go 1.26 FIPS 140-3 module (validated AES-GCM, ECDSA P-256/P-384, RSA-3072) |
| Heartbeat / event-ingest gRPC | Same — uses the same `tls.Config` factory |
| Audit chain hash | HMAC-SHA-256 (FIPS-approved; see `pkg/audit/computeChainHash`) |
| PCAP upload envelope encryption | AES-256-GCM via Go stdlib (FIPS path) |
| Cluster join token signing | ECDSA P-256 via Go stdlib (FIPS path) |

Build with:

```bash
make image-runtime-agent FIPS=true
# produces ghcr.io/alphabravocompany/constellation-runtime-agent:<version>-fips
#          ghcr.io/alphabravocompany/constellation-runtime-agent:fips-latest
```

Verify the running binary is FIPS-mode:

```bash
go version -m /usr/local/bin/constellation-runtime-agent | grep fips
# Should show: build GOFIPS140=v1.0.0  and  build -tags=fips
```

`GODEBUG=fips140=on` is baked into the image ENV when built with `FIPS=true`, so a
non-FIPS binary accidentally pushed under a `-fips` tag would refuse to boot.

### What is NOT FIPS-validated (and why we ship it under that label)

The C data-plane (`/usr/local/bin/dp`) and its DPI signature library are
**explicitly not FIPS-validated**. The C side links against:

- **hyperscan** (Intel / vectorscan fork) — regex matcher for DPI signatures. No FIPS
  cert. Replacing it would require swapping in libpcre2-FIPS or RE2, which would
  re-open the WAF rule corpus that's tuned for hyperscan's NFA semantics.
- **PCRE2** — used by L7 parsers for legacy regex grammar. No FIPS-validated build.
- **jemalloc**, **liburcu**, **libnetfilter_queue** — non-crypto, but link into the
  same binary so the binary as a whole can't claim 140-3.

This is **not a security regression** for FIPS-bound customers because:

1. **dp is a packet matcher, not a cryptographic consumer.** It inspects plaintext
   wire bytes (after CNI decap) to detect L7 protocol anomalies, DLP terms, and
   threat signatures. No keys, no certificates, no signing.
2. **TLS termination happens in the Go agent.** Outbound TLS to constellation-api
   travels through the Go agent's FIPS path — dp never holds key material.
3. **The boundary is recorded in the OCI labels.** `docker inspect` surfaces:
   ```
   org.alphabravo.constellation.fips.go = "true"
   org.alphabravo.constellation.fips.dp = "false"
   org.alphabravo.constellation.fips.scope = "see docs/fips.md#runtime-agent"
   ```
   Procurement and ATO reviewers can verify the scoping claim at the image level.

### eBPF probes

`runtime.bpf.o` (exec / file event probes) ships unchanged in FIPS mode. CO-RE BPF
programs don't perform cryptographic operations — they emit perf events that the
Go side timestamps and signs.

### Acceptance checks for `FIPS=true`

```bash
# 1. Build succeeds with the FIPS toggle.
make image-runtime-agent FIPS=true

# 2. The Go binary reports FIPS in its build metadata.
docker run --rm --entrypoint go ghcr.io/alphabravocompany/constellation-runtime-agent:fips-latest \
    version -m /usr/local/bin/constellation-runtime-agent | grep -E 'GOFIPS140|tags=fips'

# 3. Inspect labels confirm scope.
docker inspect ghcr.io/alphabravocompany/constellation-runtime-agent:fips-latest \
    | jq '.[0].Config.Labels | with_entries(select(.key | startswith("org.alphabravo.constellation.fips")))'

# 4. Helm chart accepts the FIPS image tag.
helm template constellation deploy/charts/constellation \
    --set runtimeAgent.image.tag=fips-latest > /dev/null
```

## Out-of-scope at v1

- A FIPS-validated DPI engine. Would require either a custom build of hyperscan
  against a FIPS-validated PCRE, or a port of our WAF corpus onto RE2. Tracked
  separately; not blocking ATO because dp does no crypto.
- BoringCrypto on legacy Go versions (1.25 and earlier). v1 requires Go 1.26+.
- FIPS mode for the host's iptables / TC tooling — these are stock Debian binaries,
  inherited from the base image. Operators wanting a fully-FIPS host can run the
  agent on RHEL/UBI with the FIPS kernel module; the image still works because the
  agent doesn't directly invoke libcrypto from its iptables call path.
