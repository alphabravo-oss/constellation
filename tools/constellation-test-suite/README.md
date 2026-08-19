# constellation-test-suite

End-to-end test harness for Constellation. Validates the same surface area
documented in `docs/hardware-validation-plan.md` against a real cluster
(local or remote).

## What it tests

Backend tests (this iteration):

| Module | Validates |
|---|---|
| `test_install.py` | helm install succeeds, all expected pods Running, schema migrated to head, all required Secrets present |
| `test_login.py` | bootstrap admin Secret exists, `/api/v1/auth/login` returns a JWT carrying GlobalAdmin role |
| `test_audit.py` | `/api/v1/audit/verify` returns `status: verified` (hash chain intact) |
| `test_compliance.py` | `/api/v1/compliance/control-mappings` returns the 4 frameworks + ≥20 control mappings |
| `test_quarantine.py` | POST/GET/Lift round-trip on `/api/v1/quarantine`; entries surface in subsequent List |
| `test_admission.py` | privileged + hostNetwork pods denied with the right policy IDs; compliant pod admitted with monitor warning |
| `test_runtime_agent.py` | `dp` process alive, both BPF probes (`tracepoint:sched_exec`, `lsm:file_open`) attached, exec events flow through agent log |
| `test_cni_detect.py` | agent's CNI detector reports a name from the known set, and `nfqueue_safe` matches expectation per CNI |
| `test_perf.py` | short fortio sanity run (1k qps × 30s) with and without the agent — confirms agent doesn't cause errors and overhead is plausible |

Frontend browser coverage lives with the React app under `frontend/e2e` and is
run through the frontend toolchain. This Python harness stays focused on
cluster/API/runtime behavior; add `test_ui_*.py` modules here only for flows
that require a live Helm-installed cluster.

## Running

```bash
pip install -r requirements.txt

# Against an existing cluster (KUBECONFIG already set):
pytest

# Against a remote node — the harness installs k3s, runs all tests, tears down:
pytest \
  --remote=root@178.105.113.213 \
  --ssh-key=~/.ssh/testnode_key \
  --cluster=k3s \
  --teardown

# Same, but k3d (5-node cluster):
pytest --remote=... --cluster=k3d --teardown

# Specific module:
pytest tests/test_admission.py -v

# Don't tear down on failure (preserve the cluster for debugging):
pytest --remote=... --cluster=k3s --keep-on-fail
```

## Layout

```
tools/constellation-test-suite/
├── conftest.py            # pytest fixtures + CLI options
├── requirements.txt
├── lib/
│   ├── remote.py          # SSH wrapper (subprocess; no paramiko dep)
│   ├── kubectl.py         # JSON-aware kubectl helper
│   ├── helm.py
│   ├── api.py             # constellation-api HTTP client (login/audit/quarantine)
│   ├── cluster.py         # cluster abstraction (k3s/k3d/kind/external)
│   └── installer.py       # cluster installer factory
└── tests/                 # one module per concern
```

## Design choices

- **subprocess over paramiko**: keeps deps tiny (just pytest + requests +
  pyyaml), avoids a C extension build, easier to debug — the SSH command
  appears verbatim in pytest's verbose output.
- **One cluster per test session**: bring-up is the slow step (~3 min for
  k3s), so we cluster-up once and run all tests against it.
- **Pre-existing cluster path**: when no `--remote` is given, the harness
  uses the current `KUBECONFIG` directly. Useful for local kind/k3d/minikube.
- **Honest passes**: every test that depends on a chart-installed feature
  actively exercises it. No inert stand-ins, no "skipped because XYZ" — if a feature
  isn't testable in this env, the module isn't included in the default
  collection.
