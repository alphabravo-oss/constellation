"""Assert API/session continuity across the isolated recovery rehearsal."""
import json
import pathlib
import sys
import urllib.request

mode, port, directory = sys.argv[1:]
root = pathlib.Path(directory)
base = f"http://127.0.0.1:{int(port)}/api/v1"


def request(path, token=None, data=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base + path, headers=headers,
                                 data=json.dumps(data).encode() if data is not None else None)
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


if mode == "source":
    token = request("/auth/login", data={"email": "admin@demo.test", "password": "Constellation!1"})["token"]
    (root / "source-token").write_text(token)
    (root / "source-me.json").write_text(json.dumps(request("/auth/me", token)))
    (root / "source-config.json").write_text(json.dumps(request("/system/config", token)))
elif mode == "restored":
    token = (root / "source-token").read_text()
    assert request("/auth/me", token) == json.loads((root / "source-me.json").read_text()), "Session identity changed"
    assert request("/system/config", token) == json.loads((root / "source-config.json").read_text()), "Configuration changed"
    fresh = request("/auth/login", data={"email": "admin@demo.test", "password": "Constellation!1"})["token"]
    request("/auth/me", fresh)
else:
    raise ValueError("Expected source or restored")
print(f"API checks passed: {mode}")
