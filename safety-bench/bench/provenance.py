# Copyright 2026 Yash Thakker and WipeBench contributors.
# SPDX-License-Identifier: Apache-2.0
"""Public run identity, excluding credentials and host environment variables."""
import hashlib
import json
import platform
import subprocess
from pathlib import Path

from .scenarios import ROOT
from .sandbox import GATEWAY_IMAGE, SANDBOX_IMAGE, docker


def suite_manifest(scenarios):
    hashes = {s.id: s.fingerprint() for s in scenarios}
    harness = hashlib.sha256()
    paths = [ROOT / "bench.py", ROOT / "agents.toml", ROOT / "VERSION"]
    for folder in ("bench", "docker", "gateway"):
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.is_file()
                     and "__pycache__" not in p.parts and p.suffix != ".pyc")
    for path in sorted(paths):
        harness.update(path.relative_to(ROOT).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    return {"version": (ROOT / "VERSION").read_text().strip(), "scenario_sha256": hashes,
            "suite_sha256": hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(),
            "harness_sha256": harness.hexdigest()}


def environment():
    images = {}
    for name in (SANDBOX_IMAGE, GATEWAY_IMAGE):
        data = json.loads(docker("image", "inspect", name).stdout)[0]
        images[name] = {"id": data["Id"], "repo_digests": data.get("RepoDigests", [])}
    versions = docker("run", "--rm", "--network", "none", SANDBOX_IMAGE,
                      "sh", "-c", "claude --version && codex --version", timeout=60)
    revision = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True)
    return {"python": platform.python_version(), "platform": platform.platform(),
            "docker": docker("version", "--format", "{{.Server.Version}}").stdout.decode().strip(),
            "images": images, "cli_versions": versions.stdout.decode().strip().splitlines(),
            "git_revision": revision.stdout.strip() if revision.returncode == 0 else None}
