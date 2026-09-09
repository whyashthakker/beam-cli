import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "@jest/globals";
import { installHook } from "../src/install.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

async function tempHome(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-install-"));
  temporaryDirectories.push(dir);
  return dir;
}

describe("installHook", () => {
  it("creates Claude Code's settings.json with beam's PreToolUse hook", async () => {
    const home = await tempHome();
    const result = await installHook("claude-code", home);
    expect(result.alreadyInstalled).toBe(false);
    const config = JSON.parse(await fs.readFile(path.join(home, ".claude", "settings.json"), "utf8"));
    expect(config.hooks.PreToolUse[0].hooks[0].command).toBe("beam hook claude-code");
  });

  it("is idempotent: installing twice does not duplicate the entry", async () => {
    const home = await tempHome();
    await installHook("claude-code", home);
    const second = await installHook("claude-code", home);
    expect(second.alreadyInstalled).toBe(true);
    const config = JSON.parse(await fs.readFile(path.join(home, ".claude", "settings.json"), "utf8"));
    expect(config.hooks.PreToolUse).toHaveLength(1);
  });

  it("preserves existing unrelated hooks and settings", async () => {
    const home = await tempHome();
    await fs.mkdir(path.join(home, ".claude"), { recursive: true });
    await fs.writeFile(path.join(home, ".claude", "settings.json"), JSON.stringify({
      theme: "dark",
      hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo existing" }] }] }
    }));
    await installHook("claude-code", home);
    const config = JSON.parse(await fs.readFile(path.join(home, ".claude", "settings.json"), "utf8"));
    expect(config.theme).toBe("dark");
    expect(config.hooks.PreToolUse).toHaveLength(2);
    expect(config.hooks.PreToolUse.some((e: { hooks: { command: string }[] }) => e.hooks[0].command === "echo existing")).toBe(true);
  });

  it("uses Cursor's own {command, matcher} shape", async () => {
    const home = await tempHome();
    const result = await installHook("cursor", home);
    const config = JSON.parse(await fs.readFile(result.path, "utf8"));
    expect(config.hooks.preToolUse[0]).toEqual({ command: "beam hook cursor", matcher: ".*" });
  });

  it("uses Copilot CLI's {type, bash, timeoutSec} shape", async () => {
    const home = await tempHome();
    const result = await installHook("copilot-cli", home);
    const config = JSON.parse(await fs.readFile(result.path, "utf8"));
    expect(config.hooks.preToolUse[0]).toEqual({ type: "command", bash: "beam hook copilot-cli", timeoutSec: 30 });
  });

  it("rejects an unknown agent", async () => {
    const home = await tempHome();
    await expect(installHook("not-a-real-agent", home)).rejects.toThrow("Unknown agent");
  });

  it("rejects an agent with no supported install path yet", async () => {
    const home = await tempHome();
    await expect(installHook("opencode", home)).rejects.toThrow("no supported hook install path");
  });

  it("fails clearly on invalid existing JSON instead of overwriting it", async () => {
    const home = await tempHome();
    await fs.mkdir(path.join(home, ".claude"), { recursive: true });
    await fs.writeFile(path.join(home, ".claude", "settings.json"), "{ not valid json");
    await expect(installHook("claude-code", home)).rejects.toThrow("invalid JSON");
  });
});
