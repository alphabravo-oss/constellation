# Constellation Jenkins shared library

A minimal Jenkins shared library that wraps `constellationctl` so any
Jenkinsfile can scan images, IaC, and emit SBOMs in one line.

## Vars

| Step                    | Wraps                                |
|-------------------------|--------------------------------------|
| `constellationScan`     | `constellationctl image-check`       |
| `constellationIacScan`  | `constellationctl iac-check`         |
| `constellationSbom`     | `constellationctl image-check --spdx --cyclonedx` |

## Install

1. **Add the library** to Jenkins: *Manage Jenkins → System → Global
   Pipeline Libraries*. Configure:
   - **Name** `constellation-ci`
   - **Default version** `main`
   - **Source code management** point at this repo (a sparse checkout of
     `deploy/integrations/jenkins/` is enough).

2. **Register credentials** (Manage Jenkins → Credentials → System →
   Global) as `Secret text`:
   - `constellation-server` → `https://constellation.yourco.com`
   - `constellation-token`  → token from `constellationctl tokens create`

3. **Use in a Jenkinsfile**:

   ```groovy
   @Library('constellation-ci') _

   pipeline {
     agent {
       docker { image 'ghcr.io/alphabravocompany/constellation/constellationctl:v0.2.0' }
     }
     stages {
       stage('Scan image')  { steps { constellationScan(image: "my-app:${env.GIT_COMMIT}") } }
       stage('Scan IaC')    { steps { constellationIacScan(path: '.') } }
       stage('Emit SBOM')   { steps { constellationSbom(image: "my-app:${env.GIT_COMMIT}") } }
     }
   }
   ```

## Failure semantics

Each step uses `set -o pipefail` and inherits the CLI's exit code, so a
critical CVE (image-check) or high+ misconfiguration (iac-check) marks the
stage RED. Override via `failOn:` to tune the threshold:

```groovy
constellationScan(image: '...', failOn: 'high')  // fail on high+ as well
```

## Scope

- This shared library is intentionally a Jenkins gate. Inline PR-comment
  posting belongs in the GitHub App or GitLab CI template, while Jenkins
  inherits the CLI exit code and fails the stage on policy violations.
- `recordIssues` (warnings-ng) is invoked opportunistically; if the plugin
  isn't installed, the step logs and continues.
