# Constellation GitHub App

This directory contains the GitHub App manifest + setup notes for the Constellation
developer-experience layer (spec FR-28).

## What it does

- Installs into a customer GitHub org with read on contents/metadata + write on PRs +
  write on checks + write on security_events (SARIF upload).
- On `pull_request.opened` and `pull_request.synchronize`, walks the diff for IaC files
  (`*.tf`, `*.tfvars`, `*.yaml`, `*.json`, `Dockerfile`) and image references in K8s
  manifests, kicks off a Constellation scan against each.
- Posts findings as inline review comments with severity + CVSS + a one-click "suppress
  in Constellation" link.
- Uploads SARIF to GitHub Code Scanning so findings appear in the repo's Security tab too.

## Setup

1. Create the app from the manifest:
   `gh app create-from-manifest --slug constellation-security < manifest.json`
2. Download the private key + Webhook secret; store them in Kubernetes Secret
   `constellation/github-app`.
3. Deploy the `constellation-github-app` webhook server and set
   `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`, and
   `CONSTELLATIONCTL_BIN`.
4. The webhook handler lives in `deploy/integrations/github-app/webhook/server.go`
   and exposes `/healthz`, `/readyz`, and `/webhook`.

## Required Constellation RBAC

The integration service principal needs `read-findings` + `triage-findings` so the
"suppress from this PR comment" link works.

## Status at v1

Manifest, install notes, and webhook server are present. The server verifies
`X-Hub-Signature-256`, handles `ping` and pull-request events, runs
`constellationctl image-check`, posts a PR comment, and sets commit status.
Remaining depth is a live GitHub App e2e test that walks a real PR through the
flow against a disposable repository.
