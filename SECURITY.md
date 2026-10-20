# Security policy

## Supported versions

Constellation is pre-release software. Only the `main` branch and the most recent tagged
release receive fixes.

## Reporting a vulnerability

Email **security@alphabravo.io** with a description, reproduction steps and the affected
component/version. Do not open a public issue for security reports. You will receive an
acknowledgement within three business days.

Please give us a reasonable window to ship a fix before public disclosure.

## Known backlog

Open security findings that have not yet been verified or fixed are tracked in
[`docs/SECURITY-BACKLOG.md`](docs/SECURITY-BACKLOG.md).

## Security tooling in this repository

- `make security` runs `gosec`, `govulncheck` and `gitleaks` (full history) and writes
  SARIF under `artifacts/`.
- Release images are signed with cosign and gated by an unsuppressed Grype scan
  (`cmd/tools/release-gate`).
- FIPS 140-3 builds use the Go-native crypto module (`make fips-build`, ADR 0004).
