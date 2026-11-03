import { afterAll, beforeAll, describe, expect, it } from "@jest/globals";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluate, type ActionContext, type PolicyBundle } from "../src/policy.js";
import { adaptHookPayload } from "../src/hook-adapters.js";

let root: string;
let protectedDir: string;
let outside: string;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "beam-policy-paths-"));
  protectedDir = join(root, "protected");
  outside = join(root, "outside");
  mkdirSync(protectedDir); mkdirSync(outside);
  writeFileSync(join(protectedDir, "secret.txt"), "fixture");
  symlinkSync(protectedDir, join(outside, "alias"), "dir");
});
afterAll(() => rmSync(root, { recursive: true, force: true }));
const policy = (agent = "claude-code", eventType: string | undefined = "file.read"): PolicyBundle => ({
  version: 1, notAfter: null,
  rules: {
    mode: "enforce", blockedTools: [], disabledAgents: [], blockedCommandPatterns: [],
    rules: [{ id: "protected-folder", agent, eventType, path: `${protectedDir}/**`, action: "BLOCK" }],
  },
});
const request = (extra: Partial<ActionContext> = {}): ActionContext => ({ agent: "claude-code", tool: "Read", command: "", cwd: outside, ...extra });
const denied = (extra: Partial<ActionContext>) => expect(evaluate(policy(), request(extra)).rule).toBe("protected-folder");

describe("agent-scoped folder restrictions across tools", () => {
  it.each(["Read", "read_file", "readFile", "view_file", "read_text_file"])("blocks %s with a relative path", (tool) => {
    denied({ tool, input: { file_path: "../protected/secret.txt" } });
  });
  it.each(["absolute_path", "absolutePath", "relative_path", "filePath", "target_file", "filePaths", "uri"])("extracts the %s argument alias", (key) => {
    const value = key === "uri" ? `file://${protectedDir}/secret.txt` : key === "relative_path" ? "../protected/secret.txt" : join(protectedDir, "secret.txt");
    denied({ tool: "read_file", input: { [key]: key === "filePaths" ? [value] : value } });
  });
  it("resolves symlinks and missing leaves below symlinked directories", () => {
    denied({ path: join(outside, "alias", "secret.txt") });
    denied({ path: join(outside, "alias", "new.txt") });
  });
  it("covers the protected directory itself", () => denied({ tool: "list_directory", input: { path: protectedDir }, eventType: "directory.read" }));
  it("covers search tools as file reads", () => denied({ tool: "Grep", eventType: "file.search", input: { path: protectedDir, pattern: "fixture" } }));
  it("preserves rules scoped to the original search event type", () => {
    expect(evaluate(policy("claude-code", "file.search"), request({ tool: "Grep", eventType: "file.search", input: { path: protectedDir } })).action).toBe("deny");
  });
  it("checks every file in a nested MCP request", () => denied({ tool: "mcp__fs__read_many", eventType: "tool.call", input: { request: { files: [join(outside, "ok.txt"), join(protectedDir, "secret.txt")] } } }));
  it.each([
    () => `cat ${protectedDir}/secret.txt`,
    () => "cat ../protected/secret.txt",
    () => `head -n 3 '${protectedDir}/secret.txt'`,
    () => `grep fixture '${protectedDir}'`,
    () => `cd '${protectedDir}' && cat secret.txt`,
    () => `bash -c 'cat ${protectedDir}/secret.txt'`,
    () => `python -c "print(open('${protectedDir}/secret.txt').read())"`,
    () => `node -e "require('fs').readFileSync('${protectedDir}/secret.txt')"`,
    () => `custom-uploader '${protectedDir}/secret.txt'`,
    () => `wc -l < ${protectedDir}/secret.txt`,
    () => "python -c \"print(open('../protected/secret.txt').read())\"",
    () => "unknown-reader ../protected/secret.txt",
  ])("checks shell file access %#", (command) => denied({ tool: "Bash", command: command(), eventType: "command.exec" }));
  it.each(["claude-code", "codex", "cursor", "copilot-cli", "gemini", "windsurf", "vscode", "kimi", "qwen", "cline", "auggie", "kiro", "goose", "openhands", "crush", "junie", "antigravity", "factory", "grok", "devin", "hermes"])("applies rules to %s using the common evaluator", (agent) => {
    const decision = evaluate(policy(agent), request({ agent, tool: "some_file_tool", input: { path: join(protectedDir, "secret.txt") }, eventType: "tool.call" }));
    expect(decision.action).toBe("deny");
    expect(decision.rule).toBe("protected-folder");
  });
  it("extracts cmd from a Codex shell tool payload", () => {
    const data = adaptHookPayload("codex", { tool_name: "exec_command", tool_input: { cmd: "cat ../protected/secret.txt" }, cwd: outside }, "PreToolUse");
    expect(data.command).toBe("cat ../protected/secret.txt");
    expect(evaluate(policy("codex"), request({ agent: "codex", tool: "exec_command", command: String(data.command), eventType: "command.exec" })).action).toBe("deny");
  });
  it("allows unrelated files and similarly prefixed directories", () => {
    for (const path of [join(outside, "ok.txt"), `${protectedDir}-other/secret.txt`]) {
      expect(evaluate(policy(), request({ path })).rule).not.toBe("protected-folder");
    }
  });
  it("leaves another agent outside the rule", () => {
    expect(evaluate(policy(), request({ agent: "codex", path: join(protectedDir, "secret.txt") })).rule).not.toBe("protected-folder");
  });
  it("supports a path rule across writes as well when no event type is specified", () => {
    const p = policy(); delete p.rules.rules![0].eventType;
    expect(evaluate(p, request({ tool: "editFiles", input: { edits: [{ filePath: join(protectedDir, "secret.txt") }] }, eventType: "file.write" })).action).toBe("deny");
    expect(evaluate(p, request({ tool: "apply_patch", input: { patch: `*** Update File: ${protectedDir}/secret.txt\n@@\n-old\n+new` }, eventType: "file.write" })).action).toBe("deny");
  });
  it("preserves observe mode", () => {
    const p = policy(); p.rules.mode = "observe";
    expect(evaluate(p, request({ path: join(protectedDir, "secret.txt") })).action).toBe("allow");
  });
});
