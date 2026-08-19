# Constellation GitLab integration

GitLab has no native equivalent to GitHub Apps, so this integration is a
**CI template** plus a thin helper script that posts MR notes via the
GitLab API using a Project Access Token.

## What's here

| File                          | Purpose                                       |
|-------------------------------|-----------------------------------------------|
| `.gitlab-ci.yml.template`     | Copy-paste pipeline with 4 stages             |
| `scripts/post-mr-note.sh`     | Posts a Constellation scan summary as an MR note |

## Configure (one-time)

1. **Issue a Constellation token**

   ```bash
   constellationctl tokens create --scope ci-runner --description "gitlab-ci"
   ```

2. **Issue a GitLab Project Access Token** (Settings → Access Tokens) with
   the `api` scope. The CI uses this to post MR notes — it must be separate
   from `$CONSTELLATION_TOKEN`.

3. **Add CI/CD variables** (Settings → CI/CD → Variables, mark each masked
   and protected):

   | Variable                       | Value                                   |
   |--------------------------------|-----------------------------------------|
   | `CONSTELLATION_SERVER`         | `https://constellation.yourco.com`      |
   | `CONSTELLATION_TOKEN`          | Constellation API token                 |
   | `CONSTELLATION_GITLAB_TOKEN`   | GitLab Project Access Token             |

4. **Wire the template** into `.gitlab-ci.yml`:

   ```yaml
   include:
     - remote: https://raw.githubusercontent.com/alphabravocompany/constellation/main/deploy/integrations/gitlab-app/.gitlab-ci.yml.template
   ```

   Or copy the file into the repo root.

## Pipeline stages

```
[ scan-image ] → [ scan-iac ] → [ gate-policy ] → [ sbom-upload ]
```

- **scan-image** — runs `constellationctl image-check` against
  `$IMAGE_REF` (defaults to `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA`).
  Fails on critical CVEs and uploads SARIF as a GitLab SAST report.
- **scan-iac** — runs `constellationctl iac-check .` over the working
  tree. Fails on high+ findings.
- **gate-policy** — for every K8s manifest changed in the MR, POSTs to
  `${CONSTELLATION_SERVER}/admission/simulate` and fails the pipeline if
  any object would be denied.
- **sbom-upload** — generates SPDX + CycloneDX SBOMs. On tagged builds,
  uploads them as Generic Packages under
  `/projects/:id/packages/generic/sbom/<tag>/<file>`.

## Webhooks (optional)

If you want Constellation to receive MR events directly (without going
through CI), configure a System Hook → URL
`https://constellation.example.com/api/v1/integrations/gitlab/webhook` with
**Merge Request**, **Push**, and **Pipeline** events enabled. The MR-bot
mode and the CI template can coexist; pick whichever you prefer.

## Lint

```bash
yamllint -d '{extends: default, rules: {line-length: disable}}' \
  deploy/integrations/gitlab-app/.gitlab-ci.yml.template
```

Or use the built-in GitLab linter at `https://<gitlab>/-/ci/lint`.
