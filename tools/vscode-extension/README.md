# Constellation VS Code extension

Inline container + IaC security findings inside VS Code.

## Features

- **Findings sidebar** (Explorer → "Constellation Findings") grouped by
  severity, with one-click open in the web UI. Filter to a single repo
  via the `constellation.repoScope` setting.
- **Code lens** above every `image:` ref in YAML/Helm/Compose files and
  every `FROM` line in Dockerfiles, showing the current scan summary for
  that image.
- **Hover** on an `image:` ref shows the top 10 CVEs with package,
  severity, and fix version.
- **Quick-fix** action: when a finding has a known fixed version, offer
  *"Upgrade to <name>:<fixed-version>"* directly on the line.
- **Inline diagnostics** via *Constellation: Scan current file*.
- **Sign-in** with device-code flow (`/api/v1/auth/cli-init` +
  `cli-poll`), falling back to "paste a token" if the server has not
  enabled it.

## Configure

| Setting                    | Default                  | Notes                                              |
|----------------------------|--------------------------|----------------------------------------------------|
| `constellation.serverUrl`  | `http://localhost:8080`  | Base URL of your Constellation API                 |
| `constellation.token`      | empty                    | Issued by *Constellation: Sign in* or `constellationctl tokens create` |
| `constellation.repoScope`  | empty                    | Filter sidebar findings to this repo               |

## Development

```bash
cd tools/vscode-extension
npm install
npm run build      # esbuild bundle to out/extension.js
npm run compile    # tsc type-check only
npm run package    # produce .vsix via vsce
```

The build target is Node 18 / VS Code 1.92. The extension ships as a
single CommonJS bundle so activation stays fast.

## Install locally

1. `npm run package` produces `constellation-security-<version>.vsix`.
2. In VS Code: *Extensions → … → Install from VSIX*, pick the file.
3. Or hit `F5` from this folder to launch an Extension Host window.

## Architecture

```
extension.ts          activation, command wiring
├─ client.ts          fetch wrapper around the Constellation API
├─ findingsView.ts    tree provider for the sidebar
├─ codelens.ts        image: line scanner -> CodeLens
├─ hover.ts           hover provider for image refs
├─ codeAction.ts      "upgrade to fixed version" quick-fix
└─ auth.ts            device-code sign-in
```
