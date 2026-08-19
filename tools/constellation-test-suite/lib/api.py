"""Constellation HTTP API client. Used by tests to round-trip through
the actual REST surface — same path a UI or constellationctl would take.

The base URL points at a port-forwarded constellation-api Service. Tests
typically open a kubectl port-forward (via Kubectl.port_forward) for the
duration of the test.
"""
from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable, Optional

import requests


@dataclass
class LoginResult:
    token: str
    expires_at: str


class ApiClient:
    """Constellation API client. base_url like http://localhost:18080.

    Token is set after login(); subsequent calls auto-attach `Authorization: Bearer`.
    """

    def __init__(self, base_url: str, *, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._token: Optional[str] = None

    @property
    def headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def healthz(self) -> dict[str, Any]:
        r = requests.get(f"{self.base_url}/healthz", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_json(self, path: str, *, params: Optional[dict] = None) -> dict[str, Any]:
        """Generic authenticated GET that returns JSON. Used by tests that
        exercise endpoints without a dedicated client method."""
        r = requests.get(f"{self.base_url}{path}",
                         headers=self.headers, params=params, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def post_json(self, path: str, *, body: Optional[dict] = None) -> dict[str, Any]:
        """Generic authenticated POST that returns JSON."""
        r = requests.post(f"{self.base_url}{path}",
                          headers=self.headers, json=body or {},
                          timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def login(self, *, email: str, password: str, org: str | None = None) -> LoginResult:
        body = {"email": email, "password": password}
        if org:
            body["org"] = org
        r = requests.post(f"{self.base_url}/api/v1/auth/login",
                          json=body, timeout=self.timeout)
        r.raise_for_status()
        d = r.json()
        self._token = d["token"]
        return LoginResult(token=d["token"], expires_at=d.get("expires_at", ""))

    def audit_verify(self) -> dict[str, Any]:
        r = requests.post(f"{self.base_url}/api/v1/audit/verify",
                          headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def audit_list(self, *, action: Optional[str] = None,
                   limit: int = 100) -> dict[str, Any]:
        params = {"limit": limit}
        if action:
            params["action"] = action
        r = requests.get(f"{self.base_url}/api/v1/audit/events",
                         headers=self.headers, params=params, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def compliance_mappings(self, *, framework: Optional[str] = None) -> dict[str, Any]:
        params = {"framework": framework} if framework else {}
        r = requests.get(f"{self.base_url}/api/v1/compliance/control-mappings",
                         headers=self.headers, params=params, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def quarantine_create(self, *, cluster_id: str, scope: str,
                          match_key: str, reason: str,
                          expires_in_hours: Optional[int] = None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "cluster_id": cluster_id,
            "scope": scope,
            "match_key": match_key,
            "reason": reason,
        }
        if expires_in_hours is not None:
            body["expires_in_hours"] = expires_in_hours
        r = requests.post(f"{self.base_url}/api/v1/quarantine",
                          headers=self.headers, json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def quarantine_list(self, *, cluster_id: Optional[str] = None,
                        scope: Optional[str] = None,
                        include_lifted: bool = False) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if cluster_id:
            params["cluster_id"] = cluster_id
        if scope:
            params["scope"] = scope
        if include_lifted:
            params["include_lifted"] = "1"
        r = requests.get(f"{self.base_url}/api/v1/quarantine",
                         headers=self.headers, params=params, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def quarantine_lift(self, entry_id: str, *, reason: str) -> dict[str, Any]:
        r = requests.post(f"{self.base_url}/api/v1/quarantine/{entry_id}/lift",
                          headers=self.headers, json={"reason": reason},
                          timeout=self.timeout)
        r.raise_for_status()
        return r.json()


def wait_for_json(client: ApiClient, path: str, predicate: Callable[[dict[str, Any]], bool],
                  *, timeout: float = 120.0, poll: float = 5.0,
                  params: Optional[dict] = None) -> dict[str, Any]:
    """Poll a JSON endpoint until predicate(response) is true."""
    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        last = client.get_json(path, params=params)
        if predicate(last):
            return last
        time.sleep(poll)
    raise AssertionError(f"{path} did not satisfy predicate after {timeout:.0f}s: {last!r}")
