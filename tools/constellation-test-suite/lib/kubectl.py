"""kubectl helper. All calls run via the Remote/LocalShell so the same
suite works locally or remotely. Methods that fetch JSON parse the output
into Python dicts so tests can `assert d["status"]["phase"] == "Running"`
naturally.
"""
from __future__ import annotations

import base64
import json
import shlex
import subprocess
import time
from typing import Any, Optional

from .remote import Remote, LocalShell


class Kubectl:
    """Thin wrapper. `binary` defaults to whatever's on PATH on the shell
    the harness runs in (kubectl or k3s kubectl).
    """

    def __init__(self, shell: Remote | LocalShell, *, binary: str = "kubectl",
                 namespace: str = "constellation-system"):
        self.shell = shell
        self.binary = binary
        self.ns = namespace

    def run(self, args: str, *, namespace: Optional[str] = None,
            timeout: int = 60, check: bool = True) -> str:
        """Run kubectl with the given args (string) and return stdout."""
        ns = namespace if namespace is not None else self.ns
        nsflag = f"-n {shlex.quote(ns)} " if ns else ""
        cmd = f"{self.binary} {nsflag}{args}"
        result = self.shell.run(cmd, timeout=timeout, check=check)
        return result.stdout

    def run_global(self, args: str, *, timeout: int = 60, check: bool = True) -> str:
        """Run kubectl without -n (cluster-scoped resources)."""
        return self.run(args, namespace="", timeout=timeout, check=check)

    def get_json(self, args: str, *, namespace: Optional[str] = None,
                 timeout: int = 60) -> dict[str, Any]:
        """kubectl get <args> -o json → dict."""
        out = self.run(f"get {args} -o json", namespace=namespace, timeout=timeout)
        return json.loads(out)

    def list_pods(self, *, namespace: Optional[str] = None,
                  selector: Optional[str] = None) -> list[dict]:
        sel = f" -l {shlex.quote(selector)}" if selector else ""
        d = self.get_json(f"pods{sel}", namespace=namespace)
        return d.get("items", [])

    def get_pod(self, selector: str, *, namespace: Optional[str] = None) -> Optional[dict]:
        """First pod matching the label selector, or None."""
        items = self.list_pods(selector=selector, namespace=namespace)
        return items[0] if items else None

    def wait_for_pods(self, selector: str, *, namespace: Optional[str] = None,
                      condition: str = "Ready", timeout: int = 300) -> None:
        ns = namespace if namespace is not None else self.ns
        sel = shlex.quote(selector)
        cmd = (f"{self.binary} -n {shlex.quote(ns)} wait --for=condition={condition} "
               f"pod -l {sel} --timeout={timeout}s")
        self.shell.run(cmd, timeout=timeout + 30)

    def exec_in_pod(self, pod: str, command: list[str], *,
                    namespace: Optional[str] = None,
                    container: Optional[str] = None,
                    timeout: int = 60) -> str:
        """kubectl exec the given command list in the named pod."""
        ns = namespace if namespace is not None else self.ns
        cflag = f"-c {shlex.quote(container)} " if container else ""
        joined = " ".join(shlex.quote(c) for c in command)
        return self.run(
            f"exec {pod} {cflag}-- {joined}",
            namespace=ns, timeout=timeout
        )

    def logs(self, pod: str, *, namespace: Optional[str] = None,
             tail: int = 200, since: Optional[str] = None,
             all_logs: bool = False) -> str:
        """Read logs from a pod. all_logs=True omits --tail, returning the
        full log buffer — needed when looking for one-shot startup lines
        on a long-running pod where the line has been pushed past --tail.
        """
        if all_logs:
            flags = ""
        else:
            flags = f"--tail={tail}"
            if since:
                flags += f" --since={since}"
        return self.run(f"logs {pod} {flags}".rstrip(),
                        namespace=namespace, check=False, timeout=120)

    def apply_yaml(self, yaml_text: str, *, namespace: Optional[str] = None,
                   timeout: int = 60, check: bool = True,
                   dry_run_server: bool = False) -> tuple[int, str]:
        """Pipe a YAML document into `kubectl apply -f -`. Returns
        (returncode, stderr_or_stdout). On admission denial the message
        lands on stderr — return both as one string for easy substring tests.
        """
        ns = namespace if namespace is not None else self.ns
        nsflag = f"-n {shlex.quote(ns)} " if ns else ""
        encoded = base64.b64encode(yaml_text.encode()).decode()
        dry_run = " --dry-run=server" if dry_run_server else ""
        cmd = f"echo {encoded} | base64 -d | {self.binary} {nsflag}apply -f -{dry_run}"
        result = self.shell.run(cmd, check=check, timeout=timeout)
        return result.returncode, ((result.stderr or "") + (result.stdout or ""))

    def delete(self, resource: str, name: str, *,
               namespace: Optional[str] = None, check: bool = False) -> None:
        self.run(f"delete {resource} {name} --ignore-not-found",
                 namespace=namespace, check=check)

    def get_secret(self, name: str, key: str, *,
                   namespace: Optional[str] = None) -> str:
        """Read a Secret's data[key] and base64-decode it."""
        d = self.get_json(f"secret {name}", namespace=namespace)
        return base64.b64decode(d["data"][key]).decode()

    def port_forward(self, service: str, local_port: int, remote_port: int,
                     *, namespace: Optional[str] = None) -> "PortForward":
        """Start kubectl port-forward in the background; returns a context
        manager that kills it on exit.
        """
        ns = namespace if namespace is not None else self.ns
        return PortForward(self.shell, self.binary, ns, service,
                           local_port, remote_port)


class PortForward:
    """Background kubectl port-forward whose lifetime is tied to a `with` block."""

    def __init__(self, shell, binary: str, ns: str, service: str,
                 local_port: int, remote_port: int):
        self.shell = shell
        self.binary = binary
        self.ns = ns
        self.service = service
        self.local_port = local_port
        self.remote_port = remote_port
        self._pid: Optional[int] = None

    def __enter__(self):
        cmd = (f"nohup {self.binary} -n {shlex.quote(self.ns)} port-forward "
               f"svc/{self.service} {self.local_port}:{self.remote_port} "
               f">/tmp/pf-{self.service}.log 2>&1 & echo $!")
        out = self.shell.run(cmd).stdout.strip()
        self._pid = int(out.splitlines()[-1])
        time.sleep(2)
        return self

    def __exit__(self, *exc):
        if self._pid:
            try:
                self.shell.run(f"kill {self._pid} 2>/dev/null || true", check=False)
            except subprocess.SubprocessError:
                pass
