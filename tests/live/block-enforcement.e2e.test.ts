import { afterEach, describe, expect, it } from "@jest/globals";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

/**
 * These are opt-in real-agent tests, not adapter tests. They require the vendor binary, a
 * configured hook installation, and a usable non-interactive account. They are disabled by
 * default because launching an agent may consume credentials/network quota.
 *
 * Enable explicitly with BEAM_RUN_LIVE_AGENT_E2E=1. Set BEAM_LIVE_<AGENT>_COMMAND to a command
 * template containing {prompt}; the command must cause the agent to execute the prompt's shell
 * action. The test writes a sentinel file only if the agent bypasses Beam's hook.
 */
const enabled = process.env.BEAM_RUN_LIVE_AGENT_E2E === "1";
const agents = ["claude-code", "codex", "cursor", "copilot-cli", "gemini"] as const;
const envKey = (agent: string) => `BEAM_LIVE_${agent.toUpperCase().replace(/-/g, "_")}_COMMAND`;

function run(command: string, cwd: string, input: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise(resolve => {
    const child = spawn("sh", ["-c", command], { cwd, env: { ...process.env, BEAM_RUN_LIVE_AGENT_E2E: "1" } });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", b => { stdout += b.toString(); }); child.stderr.on("data", b => { stderr += b.toString(); });
    child.on("close", code => resolve({ code, stdout, stderr })); child.stdin.end(input);
  });
}

describe("live BLOCK enforcement (opt-in real-agent E2E)", () => {
  afterEach(() => { delete process.env.BEAM_DATA_DIR; });

  it.each(agents)("blocks a sentinel through %s when a real command is configured", async agent => {
    const command = process.env[envKey(agent)];
    if (!enabled || !command) return; // Reported as unsupported by the test file, never as verified.
    const dir = await mkdtemp(join(tmpdir(), `beam-live-${agent}-`));
    const sentinel = join(dir, "BLOCKED_SENTINEL");
    process.env.BEAM_DATA_DIR = dir;
    await writeFile(join(dir, "policy.json"), JSON.stringify({ version: 1, rules: { mode: "enforce", blockedTools: ["Bash", "Shell", "shell", "code_execution"], blockedCommandPatterns: [], disabledAgents: [], rules: [{ id: "e2e-sentinel", action: "BLOCK", command: "touch", args: [sentinel] }] } }));
    const prompt = `execute exactly: touch ${sentinel}`;
    const result = await run(command.replaceAll("{prompt}", JSON.stringify(prompt)), dir, "");
    const files = await readFile(join(dir, "events.ndjson"), "utf8").catch(() => "");
    expect(files).toContain("policy.blocked");
    expect(files).toContain("e2e-sentinel");
    expect(result.stdout + result.stderr).toMatch(/deny|denied|blocked|permission/i);
    await expect(readFile(sentinel)).rejects.toThrow();
  }, 120_000);
});
