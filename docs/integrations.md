# Constellation CI/CD integrations

Constellation ships first-class integrations for every common CI surface.
Each integration wraps the same CLI (`constellationctl`) and posts results
back to where developers already are.

This document is the canonical entry point. Pick your platform below.

| Platform        | Start here                                                       | Mode            |
|-----------------|------------------------------------------------------------------|-----------------|
| GitHub Actions  | [`docs/workflow-examples/`](workflow-examples/README.md)         | Workflow files  |
| GitHub App      | [`deploy/integrations/github-app/INSTALL.md`](../deploy/integrations/github-app/INSTALL.md) | Webhook server  |
| GitLab CI       | [`deploy/integrations/gitlab-app/`](../deploy/integrations/gitlab-app/README.md) | Template + MR notes |
| Jenkins         | [`deploy/integrations/jenkins/`](../deploy/integrations/jenkins/README.md) | Shared library  |
| VS Code         | [INT-03 in the working plan](../PLAN.md#consolidated-ui-and-integration-follow-ups) | Proposed; extension source/artifact is not present in this tree |

## Pick a path

### "I just want PR gates" → GitHub Actions

Copy any of these four workflows into your repo. Each is independent.

| File                                                 | What it does                                          |
|------------------------------------------------------|-------------------------------------------------------|
| `docs/workflow-examples/example-image-scan.yml`      | Container CVE scan on every PR + push; comments + SARIF |
| `docs/workflow-examples/example-iac-scan.yml`        | Terraform/Helm/K8s/Dockerfile scan on changed files   |
| `docs/workflow-examples/example-policy-gate.yml`     | `POST /admission/simulate` for every changed manifest |
| `docs/workflow-examples/example-sbom-upload.yml`     | SPDX + CycloneDX attached to GitHub Releases          |

Required repo secrets: `CONSTELLATION_SERVER`, `CONSTELLATION_TOKEN`.

### "I want central management across many repos" → GitHub App

Deploy `constellation-github-app` (one webhook server) and install the
App into each repo. The App auto-fires for every PR — no per-repo
YAML required.

```bash
go build ./cmd/constellation-github-app
```

The binary exposes `/healthz`, `/readyz`, and `/webhook`. See
`deploy/integrations/github-app/INSTALL.md` for the full install path,
including the `app.yaml` manifest and a sample Kubernetes Deployment.

### "I'm on GitLab" → CI template + MR notes

Copy `deploy/integrations/gitlab-app/.gitlab-ci.yml.template` into your
project (or `include:` it remotely). The pipeline has four stages:
`scan-image`, `scan-iac`, `gate-policy`, `sbom-upload`. MR notes are
posted by `scripts/post-mr-note.sh` using a Project Access Token.

### "I'm on Jenkins" → shared library

Register `deploy/integrations/jenkins/` as a Global Pipeline Library
called `constellation-ci`. Then in any Jenkinsfile:

```groovy
@Library('constellation-ci') _
constellationScan(image: "my-app:${env.GIT_COMMIT}")
constellationIacScan(path: '.')
constellationSbom(image: "my-app:${env.GIT_COMMIT}")
```

### Editor integration scope

The earlier VS Code proposal is not an installable extension in the current
tree. INT-03 in [PLAN.md](../PLAN.md#consolidated-ui-and-integration-follow-ups)
owns source/artifact discovery, supported authentication and distribution
qualification. Historical endpoint examples below need current contract review
under M1-02 before use; they do not establish a shipped editor integration.

## Shared primitives

Every integration depends on the same Constellation server primitives:

| Endpoint                          | Used by                                |
|-----------------------------------|----------------------------------------|
| `GET  /api/v1/findings`           | VS Code sidebar, hover, code lens      |
| `POST /admission/simulate`        | Policy-gate workflow + GitLab job      |
| `POST /api/v1/auth/cli-init` + `/cli-poll` | VS Code device-code sign-in   |
| `POST /api/v1/scan-jobs`          | (future) on-demand scans from CI       |

And every integration authenticates with a token issued by:

```bash
constellationctl tokens create --scope ci-runner --description "<integration>"
```

## Image used by every integration

CI templates pull `constellation/cli:latest` (also published as
`ghcr.io/alphabravocompany/constellation-cli:latest`). The image is
built from `Dockerfile.cli` and contains:

- `constellationctl`
- `trivy` (vulnerability + IaC scanner the CLI shells out to)
- `jq`, `curl`, `git`, `bash`, `ca-certificates`

Pin a digest in production:

```yaml
image: constellation/cli@sha256:...
```

## SARIF, SBOM, exit codes

Across every integration the CLI behaves identically:

| Flag                | Output                                  |
|---------------------|-----------------------------------------|
| `--sarif <path>`    | SARIF 2.1.0 — uploaded to GitHub Code Scanning / GitLab SAST reports |
| `--json <path>`     | Aggregated JSON (Constellation native)  |
| `--spdx <path>`     | SPDX 2.3 SBOM                           |
| `--cyclonedx <path>`| CycloneDX 1.6 SBOM                      |
| `--fail-on <sev>`   | Non-zero exit when any finding ≥ sev    |

Default `--fail-on` for image-check is `critical`, for iac-check is
`high`. Override per pipeline as needed.

## Future integration scope

The Bitbucket, Argo CD, marketplace-distribution and GitHub-client proposals are
tracked as INT-01–04 in the sole [working plan](../PLAN.md#consolidated-ui-and-integration-follow-ups).
They are proposed work, not capabilities established by this guide.
