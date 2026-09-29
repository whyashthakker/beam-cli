import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "@jest/globals";
import { installHook, uninstallHook } from "../src/install.js";
import { checkForTampering, readTamperState, recordExpectedHooks } from "../src/tamper.js";

const temporaryDirectories: string[] = [];
const originalDataDir = process.env.BEAM_DATA_DIR;

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
  if (originalDataDir === undefined) delete process.env.BEAM_DATA_DIR;
  else process.env.BEAM_DATA_DIR = originalDataDir;
});

async function tempHome(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-tamper-home-"));
  temporaryDirectories.push(dir);
  return dir;
}

// tamper.ts's state file lives under getDataDirectory(), separate from the agentHome its checks
// scan -- so each test gets its own BEAM_DATA_DIR too, independent of the agent home fixture.
async function useTempDataDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-tamper-data-"));
  temporaryDirectories.push(dir);
  process.env.BEAM_DATA_DIR = dir;
  return dir;
}

describe("checkForTampering", () => {
  it("establishes a baseline on first run without reporting anything", async () => {
    await useTempDataDir();
    const home = await tempHome();
    await installHook("claude-code", home);

    const events = await checkForTampering(home);
    expect(events).toEqual([]);
    const state = await readTamperState();
    expect(state?.expectedHooks).toEqual(["claude-code"]);
  });

  it("reports nothing when the installed hook set hasn't changed", async () => {
    await useTempDataDir();
    const home = await tempHome();
    await installHook("claude-code", home);
    await checkForTampering(home); // establishes baseline

    const events = await checkForTampering(home);
    expect(events).toEqual([]);
  });

  it("flags a hook removed by hand (not through uninstallHook) as a critical tamper finding", async () => {
    await useTempDataDir();
    const home = await tempHome();
    await installHook("claude-code", home);
    await checkForTampering(home); // establishes baseline with claude-code present

    // Simulate a hand edit / wiped config -- bypassing beam's own uninstallHook entirely.
    await fs.rm(path.join(home, ".claude", "settings.json"), { force: true });

    const events = await checkForTampering(home);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("beam.tamper");
    expect(events[0].findings[0].id).toBe("beam.tamper.hook_removed");
    expect(events[0].findings[0].severity).toBe("critical");
    expect(events[0].summary).toContain("Claude Code");
  });

  it("does not re-alert on the next poll once the removal has already been reported", async () => {
    await useTempDataDir();
    const home = await tempHome();
    await installHook("claude-code", home);
    await checkForTampering(home);
    await fs.rm(path.join(home, ".claude", "settings.json"), { force: true });

    const first = await checkForTampering(home);
    expect(first).toHaveLength(1);
    const second = await checkForTampering(home);
    expect(second).toEqual([]);
  });

  it("does not flag a hook removed through beam's own uninstallHook + recordExpectedHooks", async () => {
    await useTempDataDir();
    const home = await tempHome();
    await installHook("claude-code", home);
    await checkForTampering(home); // baseline: claude-code present

    await uninstallHook("claude-code", home);
    await recordExpectedHooks(home); // the authorized path always re-syncs the baseline

    const events = await checkForTampering(home);
    expect(events).toEqual([]);
  });
});
