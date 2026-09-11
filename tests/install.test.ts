import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "@jest/globals";
import { installAllDetectedHooks, installHook, uninstallAllHooks, uninstallHook } from "../src/install.js";

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

describe("installAllDetectedHooks", () => {
  it("only acts on agents whose real (non-circular) presence signal exists on disk", async () => {
    const home = await tempHome();
    // Simulate a machine with only Claude Code and Copilot CLI actually installed.
    await fs.mkdir(path.join(home, ".claude"), { recursive: true });
    await fs.writeFile(path.join(home, ".claude", "settings.json"), "{}");
    await fs.mkdir(path.join(home, ".copilot"), { recursive: true });
    await fs.writeFile(path.join(home, ".copilot", "config.json"), "{}");

    const results = await installAllDetectedHooks(home);
    const byAgent = Object.fromEntries(results.map(r => [r.agent, r.status]));
    expect(byAgent["claude-code"]).toBe("installed");
    expect(byAgent["copilot-cli"]).toBe("installed");
    expect(byAgent["cursor"]).toBe("not-detected");
    expect(byAgent["codex"]).toBe("not-detected");
    expect(byAgent["gemini"]).toBe("not-detected");

    const claudeConfig = JSON.parse(await fs.readFile(path.join(home, ".claude", "settings.json"), "utf8"));
    expect(claudeConfig.hooks.PreToolUse[0].hooks[0].command).toBe("beam hook claude-code");
  });

  it("is idempotent across repeated runs (e.g. re-running setup)", async () => {
    const home = await tempHome();
    await fs.mkdir(path.join(home, ".claude"), { recursive: true });
    await fs.writeFile(path.join(home, ".claude", "settings.json"), "{}");

    await installAllDetectedHooks(home);
    const second = await installAllDetectedHooks(home);
    expect(second.find(r => r.agent === "claude-code")?.status).toBe("already-installed");
  });

  it("reports 'not-detected' for every agent when none of their real config paths exist", async () => {
    const home = await tempHome();
    const results = await installAllDetectedHooks(home);
    expect(results.every(r => r.status === "not-detected")).toBe(true);
  });

  it("does not treat beam's own hook file as proof an agent is installed (no circular detection)", async () => {
    const home = await tempHome();
    // Only beam's own output files exist -- nothing a real Cursor/Copilot install would create.
    await fs.mkdir(path.join(home, ".cursor"), { recursive: true });
    await fs.rm(path.join(home, ".cursor"), { recursive: true, force: true });
    await fs.mkdir(path.join(home, ".copilot", "hooks"), { recursive: true });
    await fs.writeFile(path.join(home, ".copilot", "hooks", "beam.json"), "{}");

    const results = await installAllDetectedHooks(home);
    expect(results.find(r => r.agent === "copilot-cli")?.status).toBe("not-detected");
  });
});

describe("uninstallHook", () => {
  it("removes Claude Code's PreToolUse entry and leaves the rest of the file intact", async () => {
    const home = await tempHome();
    await fs.mkdir(path.join(home, ".claude"), { recursive: true });
    await fs.writeFile(path.join(home, ".claude", "settings.json"), JSON.stringify({
      theme: "dark",
      hooks: {
        PreToolUse: [
          { matcher: "Bash", hooks: [{ type: "command", command: "echo existing" }] },
          { matcher: "", hooks: [{ type: "command", command: "beam hook claude-code" }] },
        ],
      },
    }));

    const result = await uninstallHook("claude-code", home);
    expect(result.removed).toBe(true);
    const config = JSON.parse(await fs.readFile(path.join(home, ".claude", "settings.json"), "utf8"));
    expect(config.theme).toBe("dark");
    expect(config.hooks.PreToolUse).toHaveLength(1);
    expect(config.hooks.PreToolUse[0].hooks[0].command).toBe("echo existing");
  });

  it("removes Cursor's {command, matcher} entry", async () => {
    const home = await tempHome();
    await installHook("cursor", home);
    const result = await uninstallHook("cursor", home);
    expect(result.removed).toBe(true);
    const config = JSON.parse(await fs.readFile(result.path, "utf8"));
    expect(config.hooks.preToolUse).toHaveLength(0);
  });

  it("removes Copilot CLI's {type, bash, timeoutSec} entry", async () => {
    const home = await tempHome();
    await installHook("copilot-cli", home);
    const result = await uninstallHook("copilot-cli", home);
    expect(result.removed).toBe(true);
    const config = JSON.parse(await fs.readFile(result.path, "utf8"));
    expect(config.hooks.preToolUse).toHaveLength(0);
  });

  it("is a no-op when the config file doesn't exist", async () => {
    const home = await tempHome();
    const result = await uninstallHook("claude-code", home);
    expect(result.removed).toBe(false);
  });

  it("is a no-op when beam was never installed for that agent", async () => {
    const home = await tempHome();
    await fs.mkdir(path.join(home, ".claude"), { recursive: true });
    await fs.writeFile(path.join(home, ".claude", "settings.json"), JSON.stringify({ theme: "dark" }));
    const result = await uninstallHook("claude-code", home);
    expect(result.removed).toBe(false);
    const config = JSON.parse(await fs.readFile(path.join(home, ".claude", "settings.json"), "utf8"));
    expect(config.theme).toBe("dark");
  });

  it("is idempotent: uninstalling twice does not error", async () => {
    const home = await tempHome();
    await installHook("claude-code", home);
    await uninstallHook("claude-code", home);
    const second = await uninstallHook("claude-code", home);
    expect(second.removed).toBe(false);
  });

  it("rejects an unknown agent", async () => {
    const home = await tempHome();
    await expect(uninstallHook("not-a-real-agent", home)).rejects.toThrow("Unknown agent");
  });

  it("rejects an agent with no supported uninstall path yet", async () => {
    const home = await tempHome();
    await expect(uninstallHook("opencode", home)).rejects.toThrow("no supported hook install path");
  });
});

describe("uninstallAllHooks", () => {
  it("removes beam's hook from every agent it was installed into", async () => {
    const home = await tempHome();
    await installHook("claude-code", home);
    await installHook("cursor", home);

    const results = await uninstallAllHooks(home);
    const removed = results.filter(r => r.removed).map(r => r.agent);
    expect(removed).toEqual(expect.arrayContaining(["claude-code", "cursor"]));

    const claudeConfig = JSON.parse(await fs.readFile(path.join(home, ".claude", "settings.json"), "utf8"));
    expect(claudeConfig.hooks.PreToolUse).toHaveLength(0);
  });

  it("returns removed: false for every agent on a machine with nothing installed", async () => {
    const home = await tempHome();
    const results = await uninstallAllHooks(home);
    expect(results.every(r => !r.removed)).toBe(true);
  });
});
