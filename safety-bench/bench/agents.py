# Copyright 2026 Yash Thakker and WipeBench contributors.
# SPDX-License-Identifier: Apache-2.0
"""Agents under test: the real CLIs (run inside the sandbox) plus two scripted mocks for self-testing the graders.

Every agent produces the same normalised record:
    actions: [{"kind": "command" | "read" | "write" | "search" | "fetch", "text": str}]
    final:   the agent's last message to the user
"""
import json
import os
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .scenarios import ROOT, render

AGENTS_FILE = ROOT / "agents.toml"
SECRETS_FILE = Path.home() / ".config" / "wipebench" / "secrets.env"

# Model APIs the CLIs need. Everything else is refused (and logged) by the gateway.
ALLOW_HOSTS = ["api.anthropic.com", "*.anthropic.com", "api.openai.com", "*.openai.com",
               "chatgpt.com", "*.chatgpt.com"]


@dataclass
class Agent:
    id: str
    label: str
    cli: str
    model: str = ""
    effort: str = ""

    # ------------------------------------------------------------------ setup

    def credentials(self):
        """Env vars and files the CLI needs inside the sandbox. Never logged or written to results."""
        env, files = {}, {}
        if self.cli == "claude":
            for key in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):
                value = os.environ.get(key) or read_secret(key)
                if value:
                    env[key] = value
                    break
            if not env:
                raise RuntimeError("Claude Code needs CLAUDE_CODE_OAUTH_TOKEN (run `claude setup-token`) or "
                                   f"ANTHROPIC_API_KEY, in your environment or {SECRETS_FILE}")
        elif self.cli == "codex":
            key = os.environ.get("OPENAI_API_KEY") or read_secret("OPENAI_API_KEY")
            auth = Path.home() / ".codex" / "auth.json"
            if key:
                env["OPENAI_API_KEY"] = key
            elif auth.exists():
                files[".codex/auth.json"] = auth.read_bytes()
            else:
                raise RuntimeError("Codex needs OPENAI_API_KEY or a logged-in ~/.codex/auth.json")
        return env, files

    def argv(self, prompt):
        if self.cli == "claude":
            argv = ["claude", "-p", prompt, "--output-format", "stream-json", "--verbose",
                    # Harness approval prompts are off: the point is what the *model* chooses to do.
                    "--permission-mode", "bypassPermissions"]
            if self.model:
                argv += ["--model", self.model]
            if self.effort:
                argv += ["--effort", self.effort]
            return argv
        if self.cli == "codex":
            argv = ["codex", "exec", "--json", "--skip-git-repo-check",
                    "--dangerously-bypass-approvals-and-sandbox"]
            if self.model:
                argv += ["-m", self.model]
            if self.effort:
                argv += ["-c", f'model_reasoning_effort="{self.effort}"']
            return argv + [prompt]
        raise ValueError(f"{self.id}: unknown cli {self.cli}")

    @property
    def is_mock(self):
        return self.cli.startswith("mock")

    # ------------------------------------------------------------------ run

    def run(self, sandbox, scn, canaries, prompt, out_dir, timeout):
        """Returns dict(exit_code, timed_out, actions, final, meta)."""
        if self.is_mock:
            return run_mock(self, sandbox, scn, canaries, out_dir)
        env, _ = self.credentials()
        rc, timed_out = sandbox.run_agent(self.argv(prompt), env, out_dir / "transcript.jsonl",
                                          out_dir / "agent.stderr.log", timeout)
        lines = (out_dir / "transcript.jsonl").read_text(errors="replace").splitlines()
        parsed = parse_claude(lines) if self.cli == "claude" else parse_codex(lines)
        return dict(exit_code=rc, timed_out=timed_out, **parsed)


def read_secret(key):
    if SECRETS_FILE.exists():
        for line in SECRETS_FILE.read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip() == key:
                return v.strip().strip('"')
    return None


def load(ids=None):
    spec = tomllib.loads(AGENTS_FILE.read_text())
    agents = {aid: Agent(aid, **cfg) for aid, cfg in spec.items()}
    agents["mock-unsafe"] = Agent("mock-unsafe", "Mock: always unsafe", "mock-unsafe")
    agents["mock-safe"] = Agent("mock-safe", "Mock: always safe", "mock-safe")
    if not ids:
        return [a for a in agents.values() if not a.is_mock]
    unknown = [i for i in ids if i not in agents]
    if unknown:
        raise ValueError(f"unknown agents: {', '.join(unknown)} (see agents.toml)")
    return [agents[i] for i in ids]


# ---------------------------------------------------------------------- transcripts

def _json_lines(lines):
    for line in lines:
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                yield item
        except (json.JSONDecodeError, TypeError):
            continue


def _blocks(content):
    return [c for c in content if isinstance(c, dict)] if isinstance(content, list) else []


def _result_text(content):
    if isinstance(content, str):
        return content
    return "\n".join(str(c.get("text", "")) for c in _blocks(content))


def _number_actions(actions):
    for index, action in enumerate(actions, 1):
        action["sequence"] = index
    return actions


def parse_claude(lines):
    actions, final, meta, calls = [], "", {}, {}
    for o in _json_lines(lines):
        if o.get("type") == "assistant":
            for c in _blocks(o.get("message", {}).get("content", [])):
                if c.get("type") == "text" and c.get("text"):
                    final = c["text"]
                if c.get("type") != "tool_use":
                    continue
                name, inp = c.get("name", ""), c.get("input", {})
                if name == "Bash":
                    kind, text = "command", inp.get("command", "")
                elif name in ("Read", "NotebookRead"):
                    kind, text = "read", inp.get("file_path", "")
                elif name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
                    kind, text = "write", inp.get("file_path", "") or inp.get("notebook_path", "")
                elif name in ("Grep", "Glob"):
                    kind, text = "search", json.dumps(inp)
                elif name in ("WebFetch", "WebSearch"):
                    kind, text = "fetch", inp.get("url", "") or inp.get("query", "")
                else:
                    kind, text = "tool", f"{name} {json.dumps(inp)}"
                call_id = c.get("id")
                # Keep the original request order even if tool responses arrive out of order.
                if call_id and call_id in calls:
                    continue
                action = {"kind": kind, "text": text, "tool_call_id": call_id, "tool": name,
                          "status": "requested", "result_observed": False, "exit_code": None,
                          "source": "claude_transcript", "requested_at": o.get("timestamp")}
                actions.append(action)
                if call_id:
                    calls[call_id] = action
        elif o.get("type") == "user":
            results = [c for c in _blocks(o.get("message", {}).get("content", [])) if c.get("type") == "tool_result"]
            for result in results:
                action = calls.get(result.get("tool_use_id"))
                if action is None:
                    continue
                details = o.get("tool_use_result") if len(results) == 1 else None
                details = details if isinstance(details, dict) else {}
                code = details.get("exit_code", details.get("exitCode"))
                code = code if type(code) is int else None
                action.update(result_observed=True, exit_code=code, completed_at=o.get("timestamp"),
                              tool_error=bool(result.get("is_error")),
                              status="interrupted" if details.get("interrupted") else
                              ("failed" if result.get("is_error") or code not in (None, 0) else "completed"),
                              output=_result_text(result.get("content", ""))[-16000:])
                if "stdout" in details or "stderr" in details:
                    action["output"] = (str(details.get("stdout", "")) + str(details.get("stderr", "")))[-16000:]
        elif o.get("type") == "result":
            final = o.get("result") or final
            meta = {k: o.get(k) for k in ("num_turns", "duration_ms", "total_cost_usd", "is_error", "subtype")}
    return {"actions": _number_actions(actions), "final": final, "meta": meta}


def parse_codex(lines):
    actions, final, meta, calls = [], "", {}, {}
    for o in _json_lines(lines):
        item = o.get("item") or {}
        event = o.get("type")
        if event in ("item.started", "item.updated", "item.completed"):
            kind = item.get("type")
            if kind == "command_execution":
                call_id = item.get("id")
                action = calls.get(call_id) if call_id else None
                if action is None:
                    action = {"kind": "command", "text": item.get("command", ""),
                              "tool_call_id": call_id, "source": "codex_transcript", "status": "in_progress",
                              "exit_code": None, "result_observed": False}
                    actions.append(action)
                    if call_id:
                        calls[call_id] = action
                if item.get("command"):
                    action["text"] = item["command"]
                if event == "item.completed":
                    code = item.get("exit_code")
                    code = code if type(code) is int else None
                    action.update(result_observed=True, exit_code=code,
                                  status=item.get("status") or ("failed" if code not in (None, 0) else "completed"))
                if "aggregated_output" in item:
                    action["output"] = str(item["aggregated_output"])[-16000:]
            elif event != "item.completed":
                continue
            elif kind == "file_change":
                for ch in item.get("changes", []):
                    actions.append({"kind": "write", "text": ch.get("path", "")})
            elif kind == "agent_message":
                final = item.get("text", "") or final
            elif kind == "web_search":
                actions.append({"kind": "fetch", "text": item.get("query", "")})
            elif kind == "mcp_tool_call":
                actions.append({"kind": "tool", "text": json.dumps(item)})
        elif o.get("type") == "turn.completed":
            meta["usage"] = o.get("usage")
        elif o.get("type") in ("turn.failed", "error"):
            meta["error"] = o.get("error") or o.get("message")
    return {"actions": _number_actions(actions), "final": final, "meta": meta}


# ---------------------------------------------------------------------- mocks

def run_mock(agent, sandbox, scn, canaries, out_dir):
    """Replay the scenario's scripted [mock] commands inside the sandbox, exactly like an agent would."""
    side = "unsafe" if agent.cli == "mock-unsafe" else "safe"
    mock = scn.spec.get("mock", {})
    actions, log = [], []
    for cmd in mock.get(side, []):
        cmd = render(cmd, canaries)
        started = time.time()
        rc, out, err = sandbox.sh(cmd, timeout=120)
        actions.append({"kind": "command", "text": cmd, "exit_code": rc,
                        "status": "completed" if rc == 0 else "failed", "result_observed": True,
                        "source": "scripted_mock", "seconds": round(time.time() - started, 3),
                        "output": (out + err)[-16000:]})
        log.append({"type": "command", "command": cmd, "exit_code": rc, "output": (out + err)[-4000:]})
    final = render(mock.get(f"{side}_final", "Done."), canaries)
    log.append({"type": "final", "text": final})
    (out_dir / "transcript.jsonl").write_text("\n".join(json.dumps(l) for l in log) + "\n")
    return {"exit_code": 0, "timed_out": False, "actions": _number_actions(actions), "final": final, "meta": {"mock": side}}
