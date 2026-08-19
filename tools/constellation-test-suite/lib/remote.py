"""SSH wrapper using subprocess.

Why not paramiko? It's a C extension that needs cargo + libssl headers to
build on a fresh box, and the SSH plumbing here is shallow enough that
subprocess gives us the same coverage with zero deps. As a bonus, every
SSH command appears verbatim in pytest's -v output, which makes failures
trivial to reproduce by hand.
"""
from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Remote:
    """Represents a remote machine accessed via SSH."""
    host: str                               # user@hostname or just hostname
    ssh_key: Optional[Path] = None
    known_hosts: Optional[Path] = None
    connect_timeout: int = 10

    def __post_init__(self) -> None:
        if self.ssh_key is not None:
            self.ssh_key = Path(self.ssh_key).expanduser()
        if self.known_hosts is not None:
            self.known_hosts = Path(self.known_hosts).expanduser()

    @property
    def ssh_args(self) -> list[str]:
        args = [
            "ssh",
            f"-oConnectTimeout={self.connect_timeout}",
            "-oStrictHostKeyChecking=no",
        ]
        if self.ssh_key:
            args += ["-i", str(self.ssh_key)]
        if self.known_hosts:
            args += [f"-oUserKnownHostsFile={self.known_hosts}"]
        else:
            args += ["-oUserKnownHostsFile=/dev/null"]
        args.append(self.host)
        return args

    def run(
        self,
        cmd: str,
        *,
        check: bool = True,
        capture: bool = True,
        timeout: int = 120,
        env: Optional[dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """Run a shell command on the remote and return CompletedProcess.

        cmd is sent as a single-quoted string to the remote shell so that
        $vars and pipes work as expected on the far side.
        """
        # If env vars given, prefix the command with `K=v K2=v2 cmd...`.
        if env:
            prefix = " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())
            full = f"{prefix} {cmd}"
        else:
            full = cmd
        args = self.ssh_args + [full]
        return subprocess.run(
            args,
            check=check,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )

    def push(self, local: Path, remote: str, *, recursive: bool = False) -> None:
        """scp a file or dir from local to the remote."""
        args = ["scp"]
        if self.ssh_key:
            args += ["-i", str(self.ssh_key)]
        if self.known_hosts:
            args += [f"-oUserKnownHostsFile={self.known_hosts}"]
        else:
            args += ["-oUserKnownHostsFile=/dev/null"]
        args += ["-oStrictHostKeyChecking=no"]
        if recursive:
            args.append("-r")
        args += [str(local), f"{self.host}:{remote}"]
        subprocess.run(args, check=True, capture_output=True, text=True, timeout=600)

    def rsync(self, local: Path, remote: str, *, excludes: Optional[list[str]] = None) -> None:
        """rsync local dir → remote path. Faster than scp -r for repeated syncs."""
        ssh_arg = " ".join(self.ssh_args[:-1])  # exclude trailing host
        args = [
            "rsync", "-az", "--delete",
            "-e", ssh_arg,
        ]
        for ex in excludes or []:
            args += [f"--exclude={ex}"]
        args += [f"{local}/", f"{self.host}:{remote}/"]
        subprocess.run(args, check=True, capture_output=True, text=True, timeout=900)

    def fetch(self, remote: str, local: Path) -> None:
        """scp a file from remote to local."""
        args = ["scp"]
        if self.ssh_key:
            args += ["-i", str(self.ssh_key)]
        if self.known_hosts:
            args += [f"-oUserKnownHostsFile={self.known_hosts}"]
        else:
            args += ["-oUserKnownHostsFile=/dev/null"]
        args += ["-oStrictHostKeyChecking=no",
                 f"{self.host}:{remote}", str(local)]
        subprocess.run(args, check=True, capture_output=True, text=True, timeout=120)

    def ping(self) -> bool:
        """True if SSH responds within connect_timeout. Doesn't raise."""
        try:
            self.run("true", timeout=self.connect_timeout + 5)
            return True
        except subprocess.SubprocessError:
            return False


class LocalShell:
    """Drop-in for Remote that just runs locally. Used when KUBECONFIG is
    already set and we're testing against an already-provisioned cluster
    on the same machine running pytest.
    """

    host = "local"

    def run(
        self,
        cmd: str,
        *,
        check: bool = True,
        capture: bool = True,
        timeout: int = 120,
        env: Optional[dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        run_env = None
        if env:
            run_env = {**os.environ, **env}
        return subprocess.run(
            ["bash", "-c", cmd],
            check=check,
            capture_output=capture,
            text=True,
            timeout=timeout,
            env=run_env,
        )

    def push(self, local: Path, remote: str, *, recursive: bool = False) -> None:
        # Local "push" is a copy — used by tests when they want to drop a
        # file into a known path. Using shutil keeps cross-platform.
        import shutil
        if recursive:
            shutil.copytree(local, remote, dirs_exist_ok=True)
        else:
            shutil.copy(local, remote)

    def rsync(self, local: Path, remote: str, *, excludes: Optional[list[str]] = None) -> None:
        # Local rsync is just a sync — exec rsync if available, else fall
        # back to recursive copy.
        try:
            args = ["rsync", "-az", "--delete"]
            for ex in excludes or []:
                args += [f"--exclude={ex}"]
            args += [f"{local}/", f"{remote}/"]
            subprocess.run(args, check=True, capture_output=True, text=True, timeout=300)
        except FileNotFoundError:
            self.push(local, remote, recursive=True)

    def fetch(self, remote: str, local: Path) -> None:
        import shutil
        shutil.copy(remote, local)

    def ping(self) -> bool:
        return True
