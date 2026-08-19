# Built-in admission hardening profiles

Constellation ships a small set of curated, built-in admission profiles. Importing
a profile materializes its rules as rows in the existing policies table; the
`constellation-admission` webhook then evaluates them.

This document describes the two general-purpose **hardening** profiles and is
explicit about which Pod Security controls they do and do not cover.

## Naming: why not "baseline" / "restricted"?

These profiles were originally named `baseline` and `restricted` — the official
names of the upstream [Kubernetes Pod Security Standards (PSS)](https://kubernetes.io/docs/concepts/security/pod-security-standards/).
That was misleading: they enforce only a small subset (~3–5) of the ~15 controls
in those standards. Reusing the PSS names implied a conformance guarantee
Constellation does not yet provide.

They have been renamed to honest names:

| Old (deprecated) ID | New ID            | Display name              |
| ------------------- | ----------------- | ------------------------- |
| `baseline`          | `basic-hardening` | Basic hardening admission |
| `restricted`        | `strict-hardening`| Strict hardening admission|

The old IDs still resolve as **deprecated aliases**. Any lookup by an old ID
(API import/export, profile fetch) returns the renamed profile and emits a
deprecation warning to the server log, for example:

```
level=WARN msg="admission profile name is deprecated" requested=restricted use=strict-hardening reason="the old name implied full Pod Security Standards conformance; see docs/admission-profiles.md"
```

Update any automation that imports/exports profiles by ID to use the new names.
A real, full PSS engine is tracked separately (parity plan task C1); when it
lands, dedicated PSS-conformant profiles can adopt the official names.

## `basic-hardening`

- **Failure policy:** `Ignore` (webhook failures do not block admission).
- **Namespace selector:** `constellation.alphabravo.io/admission: basic-hardening`.
- **Intent:** block the pod settings that most directly break node isolation,
  and surface image-provenance / read-only-root-filesystem gaps in monitor mode.

| Rule                    | Mode    | What it checks                                            |
| ----------------------- | ------- | -------------------------------------------------------- |
| `block-privileged`      | enforce | Denies privileged regular/init/ephemeral containers      |
| `block-host-network`    | enforce | Denies pods that join the node network namespace         |
| `block-host-pid`        | enforce | Denies pods that join the node PID namespace             |
| `require-image-signature` | monitor | Reports pods lacking Constellation image-provenance evidence |
| `require-read-only-rootfs` | monitor | Reports containers without `readOnlyRootFilesystem: true` |

## `strict-hardening`

- **Failure policy:** `Fail` (webhook failures block admission).
- **Namespace selector:** `constellation.alphabravo.io/enforce: "true"`.
- **Intent:** enforce the `basic-hardening` isolation controls plus non-root
  execution, read-only root filesystems, and immutable image references.

| Rule                     | Mode    | What it checks                                       |
| ------------------------ | ------- | --------------------------------------------------- |
| `block-privileged`       | enforce | Denies privileged regular/init/ephemeral containers |
| `block-host-network`     | enforce | Denies pods that join the node network namespace    |
| `block-host-pid`         | enforce | Denies pods that join the node PID namespace         |
| `require-read-only-rootfs` | enforce | Requires `readOnlyRootFilesystem: true` on every container |
| `require-non-root`       | enforce | Requires pod/container security contexts to avoid UID 0 |
| `disallow-latest-tag`    | enforce | Requires immutable image references (no `latest` / implicit tags) |

## Pod Security Standards coverage

The hardening profiles cover only the controls listed below. **They are not a
substitute for the Kubernetes Pod Security Standards.**

### Controls covered (fully or partially)

| PSS control            | `basic-hardening`        | `strict-hardening` |
| ---------------------- | ------------------------ | ------------------ |
| Privileged containers  | enforced                 | enforced           |
| Host network           | enforced                 | enforced           |
| Host PID               | enforced                 | enforced           |
| Read-only root filesystem (not a PSS control, hardening extra) | monitor | enforced |
| Running as non-root    | not checked              | enforced           |
| Immutable image tags (not a PSS control, hardening extra) | not checked | enforced |

### PSS controls NOT covered by either profile

None of the following baseline/restricted PSS controls are evaluated by these
profiles:

- Host ports (`hostPort`)
- HostPath volumes
- Host IPC (`hostIPC`)
- Capabilities — adding capabilities beyond the default set (e.g. blocking
  `NET_RAW`, requiring `drop: ["ALL"]`)
- `allowPrivilegeEscalation: false`
- Seccomp profile (`RuntimeDefault` / `Localhost`)
- AppArmor profile
- SELinux options (`seLinuxOptions`)
- `/proc` mount type (`procMount`)
- Sysctls allow-list
- `runAsUser` / `runAsGroup` / `fsGroup` ranges (beyond the binary non-root check)
- Volume types allow-list (restricted profile)
- Privilege escalation via setuid binaries / file capabilities

For the full control set, see the upstream
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).
A complete PSS admission engine is planned (see
`docs/neuvector-parity-implementation-plan.md`, task C1); until it lands, treat
these profiles as targeted hardening, not PSS conformance.
