"""pytest fixtures + CLI options for constellation-test-suite.

Use:
  pytest                                              # against $KUBECONFIG
  pytest --remote=root@host --ssh-key=~/.ssh/foo \
         --cluster=k3s --teardown                     # bring up/run/tear down
  pytest --keep-on-fail                               # leave cluster on failure
"""
from __future__ import annotations

import os
import sys
import json
from pathlib import Path

import pytest

# Make `lib` importable.
sys.path.insert(0, str(Path(__file__).parent))

from lib.api import ApiClient                                          # noqa: E402
from lib.cluster import Cluster                                        # noqa: E402
from lib.deployer import (                                             # noqa: E402
    TEST_CLUSTER_ID, deploy, teardown_release,
)
from lib.installer import (                                            # noqa: E402
    attach_external, install_k3s, install_k3d, install_kind,
)
from lib.kubectl import Kubectl                                        # noqa: E402
from lib.remote import LocalShell, Remote                              # noqa: E402


# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------

def pytest_addoption(parser: pytest.Parser) -> None:
    g = parser.getgroup("constellation")
    g.addoption("--remote", default=None,
                help="user@host of the remote node (omit for local KUBECONFIG mode)")
    g.addoption("--ssh-key", default=None,
                help="Path to the SSH private key for --remote")
    g.addoption("--cluster", default="external",
                choices=["external", "k3s", "k3d", "kind"],
                help="Cluster type to provision (external = use $KUBECONFIG)")
    g.addoption("--cni", default="kindnet",
                choices=["kindnet", "calico", "cilium"],
                help="CNI for kind clusters (ignored for k3s/k3d/external)")
    g.addoption("--teardown", action="store_true", default=False,
                help="Tear down the cluster after the run (default: leave running)")
    g.addoption("--keep-on-fail", action="store_true", default=False,
                help="Skip teardown if any test failed (debugging aid)")
    g.addoption("--source-dir", default="/root/constellation",
                help="Path on the remote/local where the constellation source lives")
    g.addoption("--no-build", action="store_true", default=False,
                help="Skip `make images` (assumes images already built + loaded)")
    g.addoption("--no-deploy", action="store_true", default=False,
                help="Skip helm install (assumes constellation already installed)")


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def shell(request: pytest.FixtureRequest):
    """Either a Remote (when --remote given) or a LocalShell."""
    remote = request.config.getoption("--remote")
    if remote:
        ssh_key = request.config.getoption("--ssh-key")
        return Remote(host=remote, ssh_key=Path(ssh_key) if ssh_key else None)
    return LocalShell()


@pytest.fixture(scope="session")
def cluster(request: pytest.FixtureRequest, shell):
    """Provision (or attach to) a cluster. Tears down at session end if asked."""
    kind = request.config.getoption("--cluster")
    cni = request.config.getoption("--cni")

    if kind == "external":
        c = attach_external()
    elif kind == "k3s":
        c = install_k3s(shell)
    elif kind == "k3d":
        c = install_k3d(shell)
    elif kind == "kind":
        c = install_kind(shell, cni=cni)
    else:
        raise ValueError(f"unknown --cluster: {kind}")

    yield c

    # Teardown logic. --keep-on-fail wins over --teardown.
    failed = request.session.testsfailed > 0
    if failed and request.config.getoption("--keep-on-fail"):
        print(f"\n[{c.name}] keeping cluster — tests failed and --keep-on-fail set")
        return
    if request.config.getoption("--teardown"):
        print(f"\n[{c.name}] tearing down cluster…")
        try:
            teardown_release(c)
        except Exception as e:
            print(f"  release teardown failed (continuing): {e}")
        c.teardown()


@pytest.fixture(scope="session")
def deployed(request: pytest.FixtureRequest, cluster: Cluster):
    """Ensure constellation is helm-installed on the cluster."""
    if request.config.getoption("--no-deploy"):
        ensure_cluster_row_seeded(cluster)
        return cluster
    src = request.config.getoption("--source-dir")
    build = not request.config.getoption("--no-build")
    deploy(cluster, source_dir=src, build=build)
    ensure_cluster_row_seeded(cluster)
    return cluster


def ensure_cluster_row_seeded(cluster: Cluster) -> str:
    """Ensure the installed-cluster row exists for tests that need a
    cluster_id. The chart should create it during bootstrap; this fixture
    keeps external/no-deploy runs deterministic.

    Returns the cluster_id for callers that want it.
    """
    out = cluster.shell.run(
        "kubectl -n constellation-system exec constellation-postgres-0 -- "
        "psql -U constellation -d constellation -tAc "
        "\"SELECT id::text FROM clusters WHERE id = '" + TEST_CLUSTER_ID + "'\"",
        check=False, timeout=30,
    ).stdout.strip()
    if out:
        return out
    org_id = cluster.shell.run(
        "kubectl -n constellation-system exec constellation-postgres-0 -- "
        "psql -U constellation -d constellation -tAc "
        "\"SELECT id::text FROM orgs ORDER BY created_at LIMIT 1\"",
        timeout=30,
    ).stdout.strip()
    if not org_id:
        raise RuntimeError("no orgs row — bootstrap-job didn't run")
    seeded = cluster.shell.run(
        "kubectl -n constellation-system exec constellation-postgres-0 -- "
        "psql -U constellation -d constellation -tAc "
        "\"INSERT INTO clusters (id, org_id, name, distro, cloud_provider, region, "
        "  state, agent_version, last_heartbeat_at) "
        "VALUES ('" + TEST_CLUSTER_ID + "', '" + org_id + "', 'test-suite-cluster', 'k3s', '', '', "
        "  'connected', 'test-0.0.0', NOW()) "
        "ON CONFLICT (id) DO UPDATE SET org_id = EXCLUDED.org_id, "
        "name = EXCLUDED.name, state = 'connected', last_heartbeat_at = NOW() "
        "RETURNING id::text\"",
        timeout=30,
    ).stdout.strip()
    if not seeded:
        raise RuntimeError("INSERT into clusters returned empty")
    return seeded


# ---------------------------------------------------------------------------
# Common test fixtures (per-module)
# ---------------------------------------------------------------------------

@pytest.fixture
def kubectl(deployed: Cluster) -> Kubectl:
    return Kubectl(deployed.shell, binary=deployed.kubectl_binary)


@pytest.fixture
def cluster_id(deployed: Cluster) -> str:
    return ensure_cluster_row_seeded(deployed)


@pytest.fixture
def psql(kubectl: Kubectl):
    def run(sql: str, *, timeout: int = 60) -> str:
        return kubectl.exec_in_pod(
            "constellation-postgres-0",
            ["psql", "-U", "constellation", "-d", "constellation", "-tAc", sql],
            namespace="constellation-system",
            timeout=timeout,
        ).strip()
    return run


@pytest.fixture
def psql_json(psql):
    def run(sql: str, *, timeout: int = 60):
        inner = sql.strip().rstrip(";")
        raw = psql(
            "SELECT COALESCE(jsonb_agg(to_jsonb(q)), '[]'::jsonb)::text "
            f"FROM ({inner}) q",
            timeout=timeout,
        )
        return json.loads(raw or "[]")
    return run


@pytest.fixture
def api(deployed: Cluster, kubectl: Kubectl):
    """Returns a logged-in ApiClient. Opens a kubectl port-forward for
    the duration of the test (or until pytest unwinds the fixture).
    """
    # Port-forward constellation-api → 18080 on the shell host.
    pf = kubectl.port_forward("constellation-api", 18080, 8080,
                              namespace="constellation-system")
    pf.__enter__()
    try:
        # The port-forward runs on the shell host (remote or local). When
        # the harness is local-only we can talk to localhost; when remote,
        # we tunnel via SSH local-forward by issuing curl-on-remote calls.
        # Simplest: make HTTP requests on the shell host via curl, parsing
        # the response in the test. But for ergonomics, requests-on-laptop
        # is nicer — so we set up a second SSH-forwarded socket if needed.
        if isinstance(deployed.shell, Remote):
            client = _RemoteApiClient(deployed.shell, "http://localhost:18080")
        else:
            client = ApiClient("http://localhost:18080")

        # Auto-login with bootstrap admin.
        password = kubectl.get_secret("constellation-admin-credentials", "password",
                                      namespace="constellation-system")
        client.login(email="admin@constellation.local", password=password)
        yield client
    finally:
        pf.__exit__(None, None, None)


# ---------------------------------------------------------------------------
# Internal: when running against a remote, wrap requests so HTTP calls hit
# the remote's port-forward via curl-over-SSH instead of trying to open a
# socket from the laptop (which would need its own SSH local-forward).
# ---------------------------------------------------------------------------

class _RemoteApiClient(ApiClient):
    """ApiClient subclass that routes HTTP through `curl` on a remote shell.
    Slow but reliable: no SSH local-forward needed.
    """

    def __init__(self, shell: Remote, base_url: str):
        super().__init__(base_url)
        self._shell = shell

    def _curl(self, method: str, path: str, *,
              json_body: dict | None = None) -> tuple[int, str]:
        """HTTP via curl on the remote shell. JSON body goes through a
        tempfile (not bash process substitution) so this works reliably
        as a one-shot SSH command — no special shell features needed.
        """
        import base64, json, shlex
        url = f"{self.base_url}{path}"
        headers = " ".join(f"-H {shlex.quote(f'{k}: {v}')}"
                           for k, v in self.headers.items())
        if json_body is not None:
            body = json.dumps(json_body)
            encoded = base64.b64encode(body.encode()).decode()
            tmp = f"/tmp/req-{os.getpid()}-{__import__('time').time_ns()}.json"
            cmd = (
                f"echo {encoded} | base64 -d > {tmp} && "
                f"curl -sS -w '\\nHTTPSTATUS:%{{http_code}}' -X {method} "
                f"{headers} --data-binary @{tmp} {shlex.quote(url)}; "
                f"rm -f {tmp}"
            )
        else:
            cmd = (f"curl -sS -w '\\nHTTPSTATUS:%{{http_code}}' -X {method} "
                   f"{headers} {shlex.quote(url)}")
        result = self._shell.run(cmd, check=False, timeout=30)
        out = result.stdout
        status_line = ""
        if "HTTPSTATUS:" in out:
            body, _, status_line = out.rpartition("HTTPSTATUS:")
            out = body
        try:
            status = int(status_line.strip())
        except ValueError:
            status = 0
        return status, out

    # Override each ApiClient method to route through the curl tunnel.
    def healthz(self):
        status, body = self._curl("GET", "/healthz")
        if status >= 400:
            raise RuntimeError(f"healthz {status}: {body}")
        import json
        return json.loads(body)

    def login(self, *, email, password, org=None):
        from lib.api import LoginResult
        import json
        payload = {"email": email, "password": password}
        if org:
            payload["org"] = org
        status, body = self._curl(
            "POST", "/api/v1/auth/login",
            json_body=payload,
        )
        if status >= 400:
            raise RuntimeError(f"login {status}: {body}")
        d = json.loads(body)
        self._token = d["token"]
        return LoginResult(token=d["token"], expires_at=d.get("expires_at", ""))

    def audit_verify(self):
        import json
        status, body = self._curl("POST", "/api/v1/audit/verify")
        if status >= 400:
            raise RuntimeError(f"audit verify {status}: {body}")
        return json.loads(body)

    def audit_list(self, *, action=None, limit=100):
        import json
        from urllib.parse import urlencode
        params = {"limit": limit}
        if action: params["action"] = action
        path = "/api/v1/audit/events?" + urlencode(params)
        status, body = self._curl("GET", path)
        if status >= 400:
            raise RuntimeError(f"audit list {status}: {body}")
        return json.loads(body)

    def compliance_mappings(self, *, framework=None):
        import json
        from urllib.parse import urlencode
        params = {}
        if framework: params["framework"] = framework
        path = "/api/v1/compliance/control-mappings"
        if params: path += "?" + urlencode(params)
        status, body = self._curl("GET", path)
        if status >= 400:
            raise RuntimeError(f"mappings {status}: {body}")
        return json.loads(body)

    def quarantine_create(self, *, cluster_id, scope, match_key, reason,
                          expires_in_hours=None):
        import json
        body_d = {"cluster_id": cluster_id, "scope": scope,
                  "match_key": match_key, "reason": reason}
        if expires_in_hours is not None:
            body_d["expires_in_hours"] = expires_in_hours
        status, body = self._curl("POST", "/api/v1/quarantine", json_body=body_d)
        if status >= 400:
            raise RuntimeError(f"quarantine create {status}: {body}")
        return json.loads(body)

    def quarantine_list(self, *, cluster_id=None, scope=None,
                        include_lifted=False):
        import json
        from urllib.parse import urlencode
        params = {}
        if cluster_id: params["cluster_id"] = cluster_id
        if scope: params["scope"] = scope
        if include_lifted: params["include_lifted"] = "1"
        path = "/api/v1/quarantine"
        if params: path += "?" + urlencode(params)
        status, body = self._curl("GET", path)
        if status >= 400:
            raise RuntimeError(f"quarantine list {status}: {body}")
        return json.loads(body)

    def quarantine_lift(self, entry_id, *, reason):
        import json
        status, body = self._curl("POST", f"/api/v1/quarantine/{entry_id}/lift",
                                  json_body={"reason": reason})
        if status >= 400:
            raise RuntimeError(f"quarantine lift {status}: {body}")
        return json.loads(body)

    def post_json(self, path, *, body=None):
        import json
        status, response = self._curl("POST", path, json_body=body or {})
        if status >= 400:
            raise RuntimeError(f"POST {path} -> {status}: {response}")
        return json.loads(response)

    def get_json(self, path, *, params=None):
        import json
        from urllib.parse import urlencode
        if params:
            path = path + ("&" if "?" in path else "?") + urlencode(params)
        status, body = self._curl("GET", path)
        if status >= 400:
            raise RuntimeError(f"GET {path} -> {status}: {body}")
        return json.loads(body)
