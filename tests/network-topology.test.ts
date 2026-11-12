import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { captureHook } from "../src/client.js";
import { configureDetectors } from "../src/data-detectors.js";

const dirs: string[] = [];
const ADDR = ["10.0.0.5", "db.prod.internal", "10.20.0.0/16", "fd12:3456:789a::1"];
beforeEach(async () => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "beam-net-")); dirs.push(home);
  process.env.BEAM_DATA_DIR = home; process.env.BEAM_HOME = home; delete process.env.BEAM_NETWORK_TOPOLOGY; delete process.env.BEAM_PII_PROMPT;
  process.exitCode = 0;
});
afterEach(async () => { delete process.env.BEAM_NETWORK_TOPOLOGY; configureDetectors({}); process.exitCode = 0; await Promise.all(dirs.splice(0).map(d => fs.rm(d, { recursive: true, force: true }))); });

function run(payload: Record<string, unknown>) {
  Object.defineProperty(process, "stdin", { value: Readable.from([JSON.stringify(payload)]), configurable: true });
  const out = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
  return captureHook("claude-code").then(() => { const w = out.mock.calls.map(c => String(c[0])); out.mockRestore(); return w; });
}
const post = (stdout: string, session = "n1") => run({ hook_event_name: "PostToolUse", tool_name: "Bash", session_id: session, tool_input: { command: "x" }, tool_response: { stdout } });
const stop = async (session = "n1") => { const w = await run({ hook_event_name: "Stop", session_id: session }); return w.length ? JSON.parse(w[0]!) : null; };

describe("network topology modes", () => {
  it("report (default): the model sees tool output unchanged, and the user gets a count-only summary", async () => {
    expect(await post(`host ${ADDR[0]} ${ADDR[1]} range ${ADDR[2]} v6 ${ADDR[3]} dns 8.8.8.8`)).toEqual([]); // nothing rewritten
    const summary = (await stop())!.systemMessage as string;
    expect(summary).toContain("network addresses seen (tool output: 2× INTERNAL_IP, 1× INTERNAL_HOST, 1× NETWORK_RANGE, 1× PUBLIC_IP)");
    expect(summary).toContain("reported only");
    for (const a of [...ADDR, "8.8.8.8"]) expect(summary).not.toContain(a);
  });

  it("report: a prompt with internal addresses is not blocked, and the notice has kinds and counts only", async () => {
    const out = JSON.parse((await run({ hook_event_name: "UserPromptSubmit", prompt: `why can't ${ADDR[0]} reach ${ADDR[1]}?`, session_id: "p1" }))[0]!);
    expect(out.decision).toBeUndefined();
    expect(out.hookSpecificOutput?.permissionDecision).not.toBe("deny");
    expect(out.systemMessage).toContain("INTERNAL_IP");
    expect(out.systemMessage).not.toContain(ADDR[0]); expect(out.systemMessage).not.toContain(ADDR[1]);
    expect(JSON.stringify(out)).not.toContain(ADDR[0]!);
  });

  it("report: a public IP alone is reported but never touched or blocked", async () => {
    expect(await post("resolved to 93.184.216.34")).toEqual([]);
    const summary = (await stop())!.systemMessage as string;
    expect(summary).toContain("1× PUBLIC_IP");
    expect(summary).not.toContain("93.184.216.34");
  });

  it("redact: topology in tool output is replaced, a public IP is left alone, and the notice has no addresses", async () => {
    process.env.BEAM_NETWORK_TOPOLOGY = "redact";
    const out = JSON.parse((await post(`up ${ADDR[0]} on ${ADDR[1]} via 8.8.8.8`))[0]!);
    expect(out.hookSpecificOutput.updatedToolOutput.stdout).toBe("up [INTERNAL_IP_001] on [INTERNAL_HOST_001] via 8.8.8.8");
    expect(JSON.stringify(out.systemMessage)).not.toContain(ADDR[0]!);
    expect(out.systemMessage).toContain("2 values (1× INTERNAL_HOST, 1× INTERNAL_IP)");
  });

  it("block: a prompt containing topology is blocked and vaulted with placeholders", async () => {
    process.env.BEAM_NETWORK_TOPOLOGY = "block";
    const out = JSON.parse((await run({ hook_event_name: "UserPromptSubmit", prompt: `ssh to ${ADDR[0]} now`, session_id: "b1" }))[0]!);
    expect(out.decision).toBe("block");
    expect(out.reason).toContain("ssh to [INTERNAL_IP_001] now");
    expect(JSON.stringify(out)).not.toContain(ADDR[0]!);
  });

  it("block: a prompt with only a public IP is still allowed", async () => {
    process.env.BEAM_NETWORK_TOPOLOGY = "block";
    const out = JSON.parse((await run({ hook_event_name: "UserPromptSubmit", prompt: "ping 8.8.8.8", session_id: "b2" }))[0] ?? "{}");
    expect(out.decision).toBeUndefined();
  });

  it("off: nothing is detected, recorded or summarised", async () => {
    process.env.BEAM_NETWORK_TOPOLOGY = "off";
    expect(await post(`up ${ADDR[0]}`)).toEqual([]);
    expect(await stop()).toBeNull();
  });

  it("records the commands the agent runs too, by count only", async () => {
    await run({ hook_event_name: "PreToolUse", tool_name: "Bash", session_id: "c1", tool_input: { command: `ssh deploy@${ADDR[0]}` } });
    const summary = (await stop("c1"))!.systemMessage as string;
    expect(summary).toContain("a command: 1× INTERNAL_IP");
    expect(summary).not.toContain(ADDR[0]!);
  });

  it("reports each turn once, then stays quiet", async () => {
    await post(`up ${ADDR[0]}`);
    expect(await stop()).not.toBeNull();
    expect(await stop()).toBeNull();
  });
});
