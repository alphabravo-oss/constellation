"""helm helper. Just a thin wrapper around `helm install/upgrade/uninstall`.
"""
from __future__ import annotations

import shlex
from typing import Optional

from .remote import Remote, LocalShell


class Helm:
    def __init__(self, shell: Remote | LocalShell, *, binary: str = "helm"):
        self.shell = shell
        self.binary = binary

    def install(
        self,
        release: str,
        chart: str,
        *,
        namespace: str,
        create_namespace: bool = True,
        values_files: Optional[list[str]] = None,
        set_values: Optional[dict[str, str]] = None,
        wait: bool = True,
        timeout: str = "10m",
    ) -> None:
        flags = []
        if create_namespace:
            flags.append("--create-namespace")
        if wait:
            flags.append("--wait")
        flags += [f"--timeout={timeout}"]
        for f in values_files or []:
            flags += ["-f", f]
        for k, v in (set_values or {}).items():
            flags += ["--set", f"{k}={v}"]
        cmd = (f"{self.binary} install {shlex.quote(release)} {shlex.quote(chart)} "
               f"-n {shlex.quote(namespace)} {' '.join(flags)}")
        # 11 minutes — Helm's --timeout caps at 10m; give SSH 1 extra.
        self.shell.run(cmd, timeout=11 * 60)

    def upgrade(
        self,
        release: str,
        chart: str,
        *,
        namespace: str,
        values_files: Optional[list[str]] = None,
        set_values: Optional[dict[str, str]] = None,
        wait: bool = True,
        timeout: str = "10m",
    ) -> None:
        flags = []
        if wait:
            flags.append("--wait")
        flags += [f"--timeout={timeout}"]
        for f in values_files or []:
            flags += ["-f", f]
        for k, v in (set_values or {}).items():
            flags += ["--set", f"{k}={v}"]
        cmd = (f"{self.binary} upgrade {shlex.quote(release)} {shlex.quote(chart)} "
               f"-n {shlex.quote(namespace)} {' '.join(flags)}")
        self.shell.run(cmd, timeout=11 * 60)

    def uninstall(self, release: str, *, namespace: str) -> None:
        cmd = (f"{self.binary} uninstall {shlex.quote(release)} "
               f"-n {shlex.quote(namespace)} --ignore-not-found")
        self.shell.run(cmd, check=False, timeout=120)

    def list_releases(self, *, namespace: Optional[str] = None) -> list[str]:
        nsflag = f"-n {shlex.quote(namespace)}" if namespace else "-A"
        out = self.shell.run(f"{self.binary} list {nsflag} -q").stdout
        return [line.strip() for line in out.splitlines() if line.strip()]
