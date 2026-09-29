# Copyright 2026 Yash Thakker and WipeBench contributors.
# SPDX-License-Identifier: Apache-2.0
"""Inspectable objective -> chosen commands -> observed outcomes, without invented attribution."""
import json


def command_trace(record):
    return [{**action, "command": action["text"], "sequence": action.get("sequence", index)}
            for index, action in enumerate(record.get("actions", []), 1) if action["kind"] == "command"]


def fenced(value):
    text = str(value)
    # A command or model response can itself contain Markdown fences.
    fence = "`" * max(3, max((len(part) for part in text.split() if set(part) == {"`"}), default=0) + 1)
    while fence in text:
        fence += "`"
    return [fence + "text", text, fence]


def write_trace(out, record):
    actions = record.get("actions", [])
    commands = command_trace(record)
    record["command_count"] = len(commands)
    record["commands_with_results"] = sum(bool(c.get("result_observed")) for c in commands)
    record["unresolved_commands"] = sum(not c.get("result_observed", False) for c in commands)
    for name, entries in (("actions.jsonl", actions), ("commands.jsonl", commands)):
        (out / name).write_text("".join(json.dumps(entry) + "\n" for entry in entries))
    lines = ["# Objective and command trace", "", "## Objective given to the agent", "",
             *fenced(record["objective"]), "", "## Outcome", "",
             f"Evaluation: {record['status']}. Task completed: {record.get('task_completed', 'unknown')}.", ""]
    if record.get("meta", {}).get("mock"):
        lines += ["**Scripted self-test. These commands came from the mock fixture, not an autonomous model.**", ""]
    lines += ["## Commands in request order", "",
              "These are shell tool calls captured from the CLI transcript (or executed mock commands). "
              "A requested call is not proof of execution. An unknown exit code stays unknown. "
              "This is not an OS-level trace of every child process.", ""]
    if not commands:
        lines += ["No shell commands were captured. Inspect actions.jsonl and the raw transcript for other tools or errors.", ""]
    for command in commands:
        code = command.get("exit_code")
        lines += [f"### Action {command['sequence']}", "", *fenced(command["command"]), "",
                  f"Status: {command.get('status', 'unknown')}. Exit code: {code if code is not None else 'unknown'}. "
                  f"Tool result observed: {bool(command.get('result_observed'))}.", ""]
        if command.get("output"):
            lines += ["Output excerpt:", "", *fenced(command["output"]), ""]
    lines += ["## Failed safety checks", ""]
    failed = [c for c in record.get("checks", []) if not c["passed"]]
    if not failed:
        lines += ["No failed checks recorded." if record["status"] != "error" else "Evaluation was incomplete; this is not a safety pass.", ""]
    for check in failed:
        lines += [*fenced(check["name"]), *fenced("\n".join(check["evidence"])), ""]
    if record.get("error"):
        lines += ["Harness error:", "", *fenced(record["error"]), ""]
    lines += ["A changed file proves a state violation, but does not by itself attribute that change to one command. "
              "Use the full action trace and filesystem/network evidence for review.", "",
              "## Final response", "", *fenced(record.get("final", "")), ""]
    (out / "trace.md").write_text("\n".join(lines))
