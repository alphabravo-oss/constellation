#!/usr/bin/env python3
"""Publish exact local OCI images and emit verified, digest-pinned release values.

Default mode is an offline plan. --publish requires Docker registry credentials.
This does not certify a release or bypass the gated release workflow.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile

DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
NAME = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
ROLES = {"api", "scanner", "operator", "discoverer", "frontend", "runtimeAgent",
         "admission", "migrate", "bootstrap", "auditArchiver"}


def command(*args):
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if result.returncode:
        # Docker can print credential-helper details. Preserve them on the terminal
        # for diagnosis, never serialize them into the release lock.
        raise RuntimeError(f"{args[0]} {args[1]} failed: {result.stderr.strip()}")
    return result.stdout


def local_digest(source):
    images = json.loads(command("docker", "image", "inspect", source))
    descriptor = images[0].get("Descriptor", {})
    digest = descriptor.get("digest", "")
    if not DIGEST.fullmatch(digest):
        raise ValueError("Docker must expose an OCI descriptor; a configuration ID is insufficient")
    return digest


def remote_digest(ref):
    result = subprocess.run(["docker", "buildx", "imagetools", "inspect", "--format",
                             "{{json .Manifest}}", ref], text=True, capture_output=True, check=False)
    if result.returncode:
        # Auth failures are never treated as an empty destination.
        if re.search(r"(?:403|401|unauthorized|denied|forbidden)", result.stderr, re.I):
            raise RuntimeError("Registry authorization failed for " + ref)
        if "not found" in result.stderr.lower() or "404" in result.stderr:
            return None
        raise RuntimeError("Registry inspection failed for " + ref)
    digest = json.loads(result.stdout).get("digest", "")
    if not DIGEST.fullmatch(digest):
        raise ValueError("Registry returned no immutable manifest digest")
    return digest


def prepare(plan):
    registry = plan["registry"].rstrip("/")
    if not re.fullmatch(r"[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+", registry):
        raise ValueError("registry must be a host/repository prefix without credentials")
    images = []
    names, roles = set(), set()
    for item in plan["images"]:
        name, source = item["name"], item["source"]
        role = item.get("role")
        if not NAME.fullmatch(name) or name in names:
            raise ValueError("Image names must be unique repository components")
        if role is not None and (role not in ROLES or role in roles):
            raise ValueError("Unknown or duplicate Helm role")
        if not isinstance(source, str) or not source or source.startswith("-"):
            raise ValueError("Invalid local source image")
        names.add(name)
        if role:
            roles.add(role)
        digest = local_digest(source)
        if item.get("expected_digest") != digest:
            raise ValueError("Local source changed or expected_digest is missing: " + source)
        repository = registry + "/" + name
        images.append({"name": name, "role": role, "source": source, "digest": digest,
                       "repository": repository, "tag": "dev-" + digest.split(":")[1]})
    if not images:
        raise ValueError("No images selected")
    return images


def publish(images):
    for item in images:
        ref = item["repository"] + ":" + item["tag"]
        if local_digest(item["source"]) != item["digest"]:
            raise ValueError("Local source changed after planning")
        existing = remote_digest(ref)
        if existing is not None and existing != item["digest"]:
            raise ValueError("Refusing to overwrite a conflicting development tag: " + ref)
        if existing is None:
            command("docker", "tag", item["source"], ref)
            if local_digest(ref) != item["digest"]:
                raise ValueError("Tagged image differs from the reviewed source")
            command("docker", "push", ref)
        if remote_digest(ref) != item["digest"]:
            raise ValueError("Published OCI graph differs from the reviewed source: " + ref)
        immutable = item["repository"] + "@" + item["digest"]
        if remote_digest(immutable) != item["digest"]:
            raise ValueError("Published image cannot be resolved by digest")
        print("Verified " + immutable, file=sys.stderr)
    return {item["role"]: {"image": {"repository": item["repository"], "digest": item["digest"]}}
            for item in images if item["role"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    images = prepare(json.loads(args.plan.read_text()))
    result = {"verified": False, "images": images}
    if args.publish:
        result["helm_values"] = publish(images)
        result["verified"] = True
    # No partial success lock is emitted. Atomic replace preserves a previous
    # valid lock on failure; callers must check this process's exit status.
    with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, delete=False) as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    pathlib.Path(f.name).replace(args.output)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, RuntimeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
