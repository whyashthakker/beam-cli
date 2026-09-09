import { describe, expect, it } from "@jest/globals";
import { normalize } from "../src/core.js";
import { adaptHookPayload } from "../src/hook-adapters.js";
import { AGENTS, findAgent } from "../src/agents.js";

describe("hook payload adapters", () => {
  it("passes Claude Code's payload through unchanged and normalizes it as proposed", () => {
    const raw = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s1", cwd: "/repo" };
    const adapted = adaptHookPayload("claude-code", raw);
    expect(adapted).toEqual(raw);
    const event = normalize({ ...adapted, source_agent: "claude-code" });
    expect(event.phase).toBe("proposed"); expect(event.type).toBe("command.exec"); expect(event.project).toBe("/repo");
  });

  it("passes Codex's payload through unchanged (same shape as Claude Code)", () => {
    const raw = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls -la" }, session_id: "thr_1", cwd: "/workspace" };
    const event = normalize({ ...adaptHookPayload("codex", raw), source_agent: "codex" });
    expect(event.phase).toBe("proposed"); expect(event.summary).toContain("ls -la");
  });

  it("passes Cursor's lower-camel hook_event_name through via case-insensitive phase detection", () => {
    const raw = { hook_event_name: "preToolUse", tool_name: "Shell", tool_input: { command: "npm install" }, tool_use_id: "abc", cwd: "/project", model: "claude-opus" };
    const event = normalize({ ...adaptHookPayload("cursor", raw), source_agent: "cursor" });
    expect(event.phase).toBe("proposed"); expect(event.project).toBe("/project");
  });

  it("translates Copilot CLI's camelCase payload into beam's normalized field names", () => {
    const raw = { sessionId: "sess-1", cwd: "/repo", toolName: "shell", toolArgs: { command: "npm test" }, timestamp: 123 };
    const adapted = adaptHookPayload("copilot-cli", raw);
    expect(adapted.session_id).toBe("sess-1");
    expect(adapted.tool_name).toBe("shell");
    expect(adapted.tool_input).toEqual({ command: "npm test" });
    const event = normalize({ ...adapted, source_agent: "copilot-cli" });
    expect(event.session).toBe("sess-1"); expect(event.phase).toBe("proposed");
  });

  it("falls back to a generic best-effort adapter for agents without a verified schema", () => {
    const raw = { toolName: "write_file", cwd: "/repo", sessionId: "s9" };
    const adapted = adaptHookPayload("gemini", raw);
    expect(adapted.tool_name).toBe("write_file");
    expect(adapted.session_id).toBe("s9");
  });

  it("falls back to generic for a completely unknown agent id", () => {
    const raw = { tool: "curl", command: "curl https://x", session: "s2" };
    const adapted = adaptHookPayload("some-future-agent", raw);
    expect(adapted.tool_name).toBe("curl");
    expect(adapted.session_id).toBe("s2");
  });
});

describe("agent registry", () => {
  it("every agent id is unique", () => {
    const ids = AGENTS.map(a => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every agent claiming a verified payload has a real adapter, not the generic fallback", () => {
    for (const a of AGENTS) if (a.verifiedPayload) expect(a.adapter).not.toBe("generic");
  });

  it("finds a known agent and returns undefined for an unknown one", () => {
    expect(findAgent("cursor")?.name).toBe("Cursor");
    expect(findAgent("does-not-exist")).toBeUndefined();
  });
});
