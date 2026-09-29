# Copyright 2026 Yash Thakker and WipeBench contributors.
# SPDX-License-Identifier: Apache-2.0
"""Docker plumbing: images, the isolated network with its egress gateway, and per-scenario sandboxes.

Nothing an agent does runs on the host. The host only creates containers, copies fixtures in, and reads logs out.
"""
import json
import subprocess
import time
from pathlib import Path

from .scenarios import HOME, PROJECT, ROOT

SANDBOX_IMAGE = "wipebench/sandbox:latest"
GATEWAY_IMAGE = "wipebench/gateway:latest"
NETWORK = "wipebench-isolated"
GATEWAY = "wipebench-gateway"
PROXY = f"http://{GATEWAY}:3128"


def docker(*args, input=None, check=True, timeout=None):
    return subprocess.run(["docker", *args], input=input, capture_output=True, check=check, timeout=timeout)


def image_exists(name):
    return docker("image", "inspect", name, check=False).returncode == 0


def build_images(force=False):
    for name, dockerfile in ((SANDBOX_IMAGE, "docker/Dockerfile.sandbox"), (GATEWAY_IMAGE, "docker/Dockerfile.gateway")):
        if force or not image_exists(name):
            print(f"building {name} …", flush=True)
            subprocess.run(["docker", "build", "-f", str(ROOT / dockerfile), "-t", name, str(ROOT)], check=True)


class Gateway:
    """The sandbox network is `--internal` (no route out). This container is its only exit."""

    def __init__(self, log_dir: Path, allow_hosts, run_token=None):
        self.log_dir = log_dir
        self.allow_hosts = allow_hosts
        self.name = f"wipebench-gateway-{run_token}" if run_token else GATEWAY
        self.network = f"wipebench-isolated-{run_token}" if run_token else NETWORK
        self.proxy = f"http://{self.name}:3128"

    def start(self):
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "egress.jsonl").touch()
        docker("network", "create", "--internal", self.network)
        docker("run", "-d", "--name", self.name, "--network", "bridge",
               "-v", f"{self.log_dir.resolve()}:/logs",
               "-e", "ALLOW_HOSTS=" + ",".join(self.allow_hosts), GATEWAY_IMAGE)
        docker("network", "connect", self.network, self.name)
        time.sleep(1)

    def entries(self):
        path = self.log_dir / "egress.jsonl"
        # Another sandbox may currently be appending the final line.
        lines = path.read_text().splitlines(keepends=True) if path.exists() else []
        return [json.loads(line) for line in lines if line.endswith("\n") and line.strip()]

    def stop(self):
        docker("rm", "-f", self.name, check=False)
        docker("network", "rm", self.network, check=False)


class Sandbox:
    def __init__(self, name, network=NETWORK, proxy=PROXY):
        self.name = name
        self.network = network
        self.proxy = proxy

    def start(self):
        docker("rm", "-f", self.name, check=False)
        docker("run", "-d", "--name", self.name, "--hostname", "devbox",
               "--network", self.network,
               "--cpus", "2", "--memory", "3g", "--pids-limit", "1024",
               "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE",
               "--security-opt", "no-new-privileges",
               "-e", f"HTTPS_PROXY={self.proxy}", "-e", f"HTTP_PROXY={self.proxy}",
               "-e", f"https_proxy={self.proxy}", "-e", f"http_proxy={self.proxy}",
               SANDBOX_IMAGE)

    def ip(self):
        out = docker("inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{self.network}").IPAddress}}}}', self.name)
        return out.stdout.decode().strip()

    def copy_in(self, tar_bytes, dest=HOME):
        docker("cp", "-a", "-", f"{self.name}:{dest}", input=tar_bytes)

    def sh(self, script, user="dev", workdir=PROJECT, timeout=120):
        """Run a shell snippet inside the sandbox. Returns (exit code, stdout, stderr)."""
        p = docker("exec", "-u", user, "-w", workdir, "-e", f"HOME={HOME}" if user == "dev" else "HOME=/root",
                   self.name, "bash", "-c", script, check=False, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")

    def run_agent(self, argv, env, stdout_path, stderr_path, timeout):
        """Run the agent CLI inside the sandbox as the unprivileged user. Returns (exit code, timed_out)."""
        env_args = [a for k, v in env.items() for a in ("-e", f"{k}={v}")]
        cmd = ["docker", "exec", "-i", "-u", "dev", "-w", PROJECT, "-e", f"HOME={HOME}", *env_args, self.name, *argv]
        with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            try:
                return proc.wait(timeout=timeout), False
            except subprocess.TimeoutExpired:
                proc.kill()
                self.sh("pkill -u dev -f 'claude|codex' || true", user="root")
                return -1, True

    def start_watch(self, paths):
        """Record every open/read/write of the watched paths, from a root-only log the agent can't see or edit."""
        for path in paths:
            if self.sh(f"test -e '{path}'", user="root")[0] != 0:
                raise RuntimeError(f"required audit path does not exist: {path}")
        if not paths:
            return
        quoted = " ".join(f"'{p}'" for p in paths)
        self.sh("nohup inotifywait -m -r -e open,access,modify,attrib,close_write,moved_from,moved_to,delete,delete_self "
                f"--timefmt %s --format '%T|%e|%w%f' {quoted} > /var/log/bench/fs.log 2> /var/log/bench/watch.err & "
                "echo $! > /var/log/bench/watch.pid", user="root", workdir="/")
        for _ in range(50):
            if "Watches established" in self.sh("cat /var/log/bench/watch.err", user="root", workdir="/")[1]:
                return
            time.sleep(0.1)
        raise RuntimeError("file-access audit did not start")

    def stop_watch(self):
        self.sh("test -f /var/log/bench/watch.pid && kill $(cat /var/log/bench/watch.pid) || true", user="root", workdir="/")
        rc, out, _ = self.sh("cat /var/log/bench/fs.log 2>/dev/null", user="root", workdir="/")
        events = []
        for line in out.splitlines():
            ts, _, rest = line.partition("|")
            kinds, _, path = rest.partition("|")
            if path:
                events.append({"ts": ts, "events": kinds.split(","), "path": path})
        return events

    def remove(self):
        docker("rm", "-f", self.name, check=False)
