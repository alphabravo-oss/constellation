# Constellation example GitHub Actions workflows

Copy any of these YAML files into your downstream repository under
`.github/workflows/` and adjust the image refs / paths to match your build
pipeline.

| Workflow                  | Trigger                  | Gate                          |
|---------------------------|--------------------------|-------------------------------|
| `example-image-scan.yml`  | PR + push to `main`      | Critical CVEs in the image    |
| `example-iac-scan.yml`    | PR + push to `main`      | High+ findings in changed IaC |
| `example-policy-gate.yml` | PR to `main`             | Admission denial in `/admission/simulate` |
| `example-sbom-upload.yml` | Release / manual dispatch| n/a — attaches SBOM artifact  |

## Setup (one-time)

1. **Get a token**

   ```bash
   constellationctl login --server https://constellation.yourco.com
   constellationctl tokens create --scope ci-runner --description "github-actions"
   ```

2. **Add the values as GitHub Actions secrets** (repo Settings → Secrets and
   variables → Actions):

   | Name                   | Value                                              |
   |------------------------|----------------------------------------------------|
   | `CONSTELLATION_SERVER` | `https://constellation.yourco.com`                 |
   | `CONSTELLATION_TOKEN`  | the token printed by `tokens create`               |

3. **Copy the workflow file(s)** you want into `.github/workflows/`. The image
   the jobs run in (`constellation/cli:latest`) ships `constellationctl`, `jq`,
   `curl`, and `git` so no extra `setup-*` steps are needed.

## Notes

- All workflows run inside the `constellation/cli` image. Pin a digest in
  production (e.g. `constellation/cli@sha256:…`).
- The PR-comment step uses the default `GITHUB_TOKEN` and requires
  `pull-requests: write` (already declared in each workflow).
- SARIF uploads land under the repo's **Security → Code scanning** tab and
  show up next to native CodeQL alerts.
- The admission gate workflow expects the Constellation API to expose
  `POST /admission/simulate` (server-side admission engine). If the endpoint
  isn't reachable, the workflow fails closed.

## Reference

- Token issuance and scopes: `docs/specs/auth-tokens.md`
- SARIF / SBOM formats:        `pkg/sarif/`, `pkg/sbom/`
- Top-level integration index: `docs/integrations.md`
