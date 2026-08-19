# Constellation GitHub App — install guide

The Constellation GitHub App posts container + IaC scan results back to
pull requests as comments, and writes a `constellation/security` commit
status that blocks merge on critical findings.

This guide covers:

1. Create the GitHub App
2. Install on the target repo(s)
3. Generate the App's private key
4. Deploy the `constellation-github-app` webhook server
5. Verify

> A faster path with no webhook server to operate is to copy the workflows
> under `.github/workflows/example-*.yml` directly. Use the App when you
> want central control across many repos.

---

## 1. Create the GitHub App

In your GitHub org, go to **Settings → Developer settings → GitHub Apps →
New GitHub App**, or use the manifest flow:

1. Open `https://github.com/organizations/<your-org>/settings/apps/new`.
2. Paste the contents of `app.yaml` into the form, OR submit it via the
   manifest endpoint with `state=<random>` (any string).
3. Replace `https://constellation.example.com` with the real public hostname
   of your webhook server before submitting.

GitHub will create the App and show you:

- the numeric **App ID**, and
- a **Webhook secret** (set this yourself in the form — choose a strong
  random string, e.g. `openssl rand -hex 32`).

## 2. Install on a repo

From the App's settings page, click **Install App** and pick the repos to
scan. You only need to do this once per repo; the App auto-fires for
every PR after that.

## 3. Generate the private key

On the App settings page, scroll to **Private keys → Generate a private
key**. GitHub downloads a `.pem` file once — store it securely; you cannot
download it again.

## 4. Deploy the webhook server

The binary `constellation-github-app` is shipped in the
`constellation/cli:latest` image (entrypoint override) and as a separate
binary in releases.

### Required environment

| Env var                       | Value                                       |
|-------------------------------|---------------------------------------------|
| `GITHUB_APP_ID`               | numeric App ID                              |
| `GITHUB_APP_PRIVATE_KEY_PATH` | path to the `.pem` mounted into the pod     |
| `GITHUB_WEBHOOK_SECRET`       | the secret you set when creating the App    |
| `CONSTELLATION_SERVER`        | `https://constellation.yourco.com`          |
| `CONSTELLATION_TOKEN`         | `constellationctl tokens create --scope ci-runner` |
| `LISTEN_ADDR` *(optional)*    | default `:8088`                             |

### Run with Docker

```bash
docker run --rm -p 8088:8088 \
  -e GITHUB_APP_ID=123456 \
  -e GITHUB_APP_PRIVATE_KEY_PATH=/keys/app.pem \
  -e GITHUB_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
  -e CONSTELLATION_SERVER=https://constellation.yourco.com \
  -e CONSTELLATION_TOKEN="$CTL_TOKEN" \
  -v "$PWD/keys:/keys:ro" \
  ghcr.io/alphabravocompany/constellation-github-app:latest
```

### Deploy to Kubernetes

A minimal Deployment (mount the PEM as a Secret):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: constellation-github-app
  namespace: constellation
type: Opaque
stringData:
  app.pem: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
  webhook_secret: REPLACE_ME
  constellation_token: REPLACE_ME
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: constellation-github-app
  namespace: constellation
spec:
  replicas: 1
  selector: { matchLabels: { app: constellation-github-app } }
  template:
    metadata: { labels: { app: constellation-github-app } }
    spec:
      containers:
        - name: app
          image: ghcr.io/alphabravocompany/constellation-github-app:latest
          ports: [{ containerPort: 8088 }]
          env:
            - { name: GITHUB_APP_ID, value: "123456" }
            - { name: GITHUB_APP_PRIVATE_KEY_PATH, value: "/keys/app.pem" }
            - name: GITHUB_WEBHOOK_SECRET
              valueFrom: { secretKeyRef: { name: constellation-github-app, key: webhook_secret } }
            - { name: CONSTELLATION_SERVER, value: "https://constellation.svc.cluster.local" }
            - name: CONSTELLATION_TOKEN
              valueFrom: { secretKeyRef: { name: constellation-github-app, key: constellation_token } }
          volumeMounts:
            - { name: key, mountPath: /keys, readOnly: true }
          readinessProbe:
            httpGet: { path: /readyz, port: 8088 }
          livenessProbe:
            httpGet: { path: /healthz, port: 8088 }
      volumes:
        - name: key
          secret:
            secretName: constellation-github-app
            items: [{ key: app.pem, path: app.pem }]
---
apiVersion: v1
kind: Service
metadata:
  name: constellation-github-app
  namespace: constellation
spec:
  selector: { app: constellation-github-app }
  ports: [{ port: 80, targetPort: 8088 }]
```

Expose via Ingress at the URL you set as the **webhook URL** on the App.

## 5. Verify

1. Run a quick health probe:

   ```bash
   curl -sS https://constellation.example.com/healthz
   # → {"status":"ok","service":"constellation-github-app"}
   ```

2. Re-deliver any past webhook from the GitHub App's "Advanced" tab. You
   should see the HMAC pass and a `200/202` response.

3. Open a draft PR with an obviously broken container image
   (`alpine:3.4`) — the App should comment within a couple of minutes and
   the commit status should turn red.

## Troubleshooting

- **`signature mismatch` in logs** — the webhook secret in the App config
  doesn't match `GITHUB_WEBHOOK_SECRET`. Recreate the secret in both places.
- **`installation_token: http 401`** — the private key was rotated; re-upload
  the new `.pem` and restart.
- **No comment appears** — confirm `pull_requests:write` and `statuses:write`
  are set in the App's permissions, then re-install on the repo (a perm change
  requires re-install).
