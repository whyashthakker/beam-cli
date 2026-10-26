import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { hermesAddBeam, hermesHasBeam, hermesStripBeam } from "../src/agent-installers.js";
import { adaptHookPayload } from "../src/hook-adapters.js";
import { normalize } from "../src/core.js";
import { findAgent } from "../src/agents.js";
import { installAllDetectedHooks, installHook, isHookInstalled, uninstallHook } from "../src/install.js";

const dirs: string[] = [];
const savedEnv = { ...process.env };
async function temp(): Promise<string> { const d = await fs.mkdtemp(path.join(os.tmpdir(), "beam-custom-")); dirs.push(d); return d; }
beforeEach(() => { process.env.BEAM_HOME = path.join(os.tmpdir(), `beam-home-${Math.random().toString(36).slice(2)}`); process.env.BEAM_OPENCLAW_BIN = "/nonexistent/openclaw"; });
afterEach(async () => { process.env = { ...savedEnv }; await Promise.all(dirs.splice(0).map(d => fs.rm(d, { recursive: true, force: true }))); });

const CMD = "'/usr/bin/node' '/opt/beam/dist/cli.js' hook hermes";

describe("Hermes config.yaml editing", () => {
  it("adds a hooks block to a config without one and keeps the user's lines", () => {
    const out = hermesAddBeam("model: x # keep\nagent:\n  name: a\n", CMD);
    expect(out.startsWith("model: x # keep\nagent:\n  name: a\n")).toBe(true);
    expect(out).toContain("hooks:\n  pre_tool_call:\n    - command: ");
    expect(out).toContain(JSON.stringify(CMD));
    expect(hermesHasBeam(out)).toBe(true);
  });

  it("inserts under an existing hooks: block without touching other events", () => {
    const input = "hooks:\n  post_tool_call:\n    - command: \"fmt.sh\"\nmodel: x\n";
    const out = hermesAddBeam(input, CMD);
    expect(out).toContain("  post_tool_call:\n    - command: \"fmt.sh\"");
    expect(out.indexOf("pre_tool_call")).toBeGreaterThan(out.indexOf("hooks:"));
    expect(hermesStripBeam(out)).toBe(input);
  });

  it("is idempotent and strips back to the original", () => {
    const once = hermesAddBeam("model: x\n", CMD);
    expect(hermesAddBeam(once, CMD)).toBe(once);
    expect(hermesStripBeam(once).trim()).toBe("model: x");
  });

  it("refuses to guess when the user already has a pre_tool_call list", () => {
    expect(() => hermesAddBeam("hooks:\n  pre_tool_call:\n    - command: a.sh\n", CMD)).toThrow(/by hand/);
  });

  it("refuses an inline hooks value", () => {
    expect(() => hermesAddBeam("hooks: {}\n", CMD)).toThrow(/inline/);
  });
});

describe("Hermes and OpenClaw install", () => {
  it("installs, reports, and uninstalls Hermes", async () => {
    const home = await temp();
    await fs.mkdir(path.join(home, ".hermes"), { recursive: true });
    await fs.writeFile(path.join(home, ".hermes", "config.yaml"), "model: x\n");
    const result = await installHook("hermes", home);
    expect(result.alreadyInstalled).toBe(false);
    expect(result.note).toMatch(/approve/);
    expect(await isHookInstalled("hermes", home)).toBe(true);
    expect((await installHook("hermes", home)).alreadyInstalled).toBe(true);
    expect((await uninstallHook("hermes", home)).removed).toBe(true);
    expect(await fs.readFile(path.join(home, ".hermes", "config.yaml"), "utf8")).toBe("model: x\n");
    expect(await isHookInstalled("hermes", home)).toBe(false);
  });

  it("writes the OpenClaw plugin and explains the manual step when openclaw is missing", async () => {
    const home = await temp();
    const result = await installHook("openclaw", home);
    expect(result.note).toMatch(/not registered/);
    const index = await fs.readFile(path.join(result.path, "index.ts"), "utf8");
    expect(index).toContain('api.on("before_tool_call"');
    expect(index).toContain("blockReason");
    expect(JSON.parse(await fs.readFile(path.join(result.path, "openclaw.plugin.json"), "utf8")).id).toBe("beam");
    expect(await isHookInstalled("openclaw", home)).toBe(true);
    expect((await uninstallHook("openclaw", home)).removed).toBe(true);
    expect(await isHookInstalled("openclaw", home)).toBe(false);
  });

  it("registers with a working openclaw binary", async () => {
    const home = await temp();
    const bin = path.join(home, "openclaw");
    await fs.writeFile(bin, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    process.env.BEAM_OPENCLAW_BIN = bin;
    const result = await installHook("openclaw", home);
    expect(result.note).toMatch(/Restart the OpenClaw gateway/);
  });

  it("install-all picks them up only when their directories exist", async () => {
    const home = await temp();
    await fs.mkdir(path.join(home, ".hermes"), { recursive: true });
    const results = await installAllDetectedHooks(home);
    expect(results.find(r => r.agent === "hermes")?.status).toBe("installed");
    expect(results.find(r => r.agent === "openclaw")?.status).toBe("not-detected");
  });
});

describe("payloads", () => {
  it("treats Hermes' terminal tool as a command", () => {
    const raw = { hook_event_name: "pre_tool_call", tool_name: "terminal", tool_input: { command: "rm -rf /tmp/x" }, session_id: "s", cwd: "/w" };
    const event = normalize({ ...adaptHookPayload("hermes", raw), source_agent: "hermes" });
    expect(event.type).toBe("command.exec");
    expect(event.phase).toBe("proposed");
  });

  it("marks the verification level honestly", () => {
    expect(findAgent("hermes")?.verifiedPayload).toBe(true);
    expect(findAgent("openclaw")?.verifiedPayload).toBe(false);
  });
});
