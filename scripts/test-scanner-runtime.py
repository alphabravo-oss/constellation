#!/usr/bin/env python3
"""Exercise bundled tools in a scanner image as its normal user on a read-only root.

Requires a registry fixture with known vulnerabilities, a legacy Cosign signature
and SLSA v1 attestation, correct/wrong public keys, and preloaded Trivy/Grype DBs.
The Grype cache must be writable by image UID 10001. No Docker socket is mounted.
Use a disposable registry: --network=host makes loopback fixtures reachable.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
for name in ("image", "fixture", "public-key", "wrong-key", "trivy-db", "grype-cache"):
    parser.add_argument("--" + name, required=True)
parser.add_argument("--docker-config", help="Docker config directory for a private registry fixture")
args = parser.parse_args()
repo = Path(__file__).resolve().parent.parent


def bind(source, target, readonly=True):
    return ["--mount", f"type=bind,src={Path(source).resolve()},dst={target}" + (",readonly" if readonly else "")]


with tempfile.TemporaryDirectory(prefix="scanner-runtime-") as temporary:
    directory = Path(temporary)
    directory.chmod(0o755)
    common = ["docker", "run", "--rm", "--network", "host", "--read-only", "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
              "--tmpfs", "/home/constellation:rw,uid=10001,gid=10001,size=64m"]
    if args.docker_config:
        common += bind(args.docker_config, "/docker-auth") + ["-e", "DOCKER_CONFIG=/docker-auth"]
    for package, test, extra in [
        ("pkg/sigverify", "TestBundledCosign", bind(args.public_key, "/key.pub") + bind(args.wrong_key, "/wrong.pub") + [
            "-e", "CONSTELLATION_TEST_SIGNED_IMAGE=" + args.fixture,
            "-e", "CONSTELLATION_TEST_SIGNING_PUBLIC_KEY=/key.pub",
            "-e", "CONSTELLATION_TEST_WRONG_PUBLIC_KEY=/wrong.pub",
            "-e", "CONSTELLATION_TEST_KEYLESS_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3"]),
        ("internal/scanner", "TestBundledTools", bind(args.grype_cache, "/grype-cache", False) + [
            "--tmpfs", "/trivy-cache:rw,uid=10001,gid=10001,size=256m"] + bind(args.trivy_db, "/trivy-cache/db") + [
            "-e", "TRIVY_CACHE_DIR=/trivy-cache", "-e", "GRYPE_DB_CACHE_DIR=/grype-cache",
            "-e", "CONSTELLATION_TEST_SCANNER_IMAGE=" + args.fixture]),
    ]:
        binary = directory / "tests"
        subprocess.run(["go", "test", "-c", "-o", str(binary), "./" + package], cwd=repo,
                       env=dict(os.environ, CGO_ENABLED="0", GOWORK="off"), check=True)
        binary.chmod(0o755)
        subprocess.run(common + bind(binary, "/tests") + extra + ["--entrypoint", "/tests", args.image,
                       "-test.v", "-test.run=" + test, "-test.timeout=10m"], check=True)
