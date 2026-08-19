# constellation-discoverer (Wave I3)

`cmd/constellation-discoverer` watches a single Kubernetes API server, projects every
Deployment / StatefulSet / DaemonSet into the `deployments` table, and links each row to
the matching `clusters` row by name. It also creates / refreshes a paired `assets` row
(`kind='deployment'`, `name='<namespace>/<workload>'`) so any scanner finding that lands
later can attach to the workload by `asset_id`.

After every reconcile pass the discoverer joins `findings` against the paired asset row and
writes `finding_count` / `critical_count` / `high_count` / `risk_score` / `risk_factors` back
to the deployment row. The score formula (matches the spec):

    risk_score = min(100, 5*critical_count + 2*high_count + medium_count)

`risk_factors` is a `jsonb` blob keeping structural facts observed from the PodSpec
(`privileged`, `host_network`, `ai_workload`) together with measured `cvss`, `kev`, and
`net_exposure` subfactors. CVSS and KEV come from stored finding detail metadata, while
network exposure comes from recent external network flows for the workload.

## Configuration (env vars)

| Variable             | Required | Notes                                                              |
|----------------------|----------|--------------------------------------------------------------------|
| `DATABASE_URL`       | yes      | `postgres://constellation:constellation@localhost:5433/constellation` |
| `KUBECONFIG`         | yes*     | Path to a kubeconfig file (defaults to `~/.kube/config` if present) |
| `CLUSTER_NAME`       | yes      | Must match `clusters.name`; auto-creates the row if missing         |
| `ORG_ID`             | yes      | uuid of the org the cluster belongs to                              |
| `NAMESPACE_FILTER`   | no       | csv of globs to include; `kube-system` is always excluded. Default `*` |
| `RECONCILE_INTERVAL` | no       | default `30s`                                                       |
| `ONE_SHOT`           | no       | `true` runs a single reconcile pass then exits                      |

## Build

    go build -o /tmp/constellation-discoverer ./cmd/constellation-discoverer

## Run against all three dev clusters

The dev org uuid `2ebae049-35c7-464c-b4b0-50cf185e5975` already has the three cluster rows
(`prod-us-east-1`, `edge-eu-west-1`, `dev-local`) seeded.

```bash
export DATABASE_URL='postgres://constellation:constellation@localhost:5433/constellation'
export ORG_ID=2ebae049-35c7-464c-b4b0-50cf185e5975

# k3d "constellation" -> prod-us-east-1
KUBECONFIG=/tmp/kubeconfig-constellation.yaml CLUSTER_NAME=prod-us-east-1 \
  /tmp/constellation-discoverer &

# k3d "constellation-edge" -> edge-eu-west-1
KUBECONFIG=/tmp/kubeconfig-edge.yaml CLUSTER_NAME=edge-eu-west-1 \
  /tmp/constellation-discoverer &

# native k3s on this host -> dev-local
KUBECONFIG=/tmp/kubeconfig-k3s CLUSTER_NAME=dev-local \
  /tmp/constellation-discoverer &
```

For a one-shot backfill (used by tests):

```bash
ONE_SHOT=true KUBECONFIG=/tmp/kubeconfig-constellation.yaml \
  CLUSTER_NAME=prod-us-east-1 /tmp/constellation-discoverer
```

## Verify

```sql
SELECT cluster_id, count(*) FROM deployments GROUP BY cluster_id;
```

After the initial backfill of the three dev clusters the counts settle around:

| cluster_id (alias)              | rows |
|---------------------------------|-----:|
| 11111111... prod-us-east-1      |   16 |
| 22222222... edge-eu-west-1      |    7 |
| 33333333... dev-local           |    6 |
| 95a3589d... prod-east (seeded)  |    6 |

The API endpoint `GET /api/v1/deployments` returns the real workload list with
`{namespace, name, kind, labels, risk_score, risk_factors, finding_count, critical_count,
high_count}` and the Risk · Workloads page (`/risk` and `/workloads` in the UI) renders
them.

## Namespace filtering

* default (`NAMESPACE_FILTER` unset or `*`): every namespace except `kube-system`.
* csv globs: `payments,checkout,edge,platform` only those.
* negation: `*,!constellation-system` (every namespace except `kube-system` and
  `constellation-system`).
