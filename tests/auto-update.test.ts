import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { autoUpdateAllowed, autoUpdateTick, compareVersions, installKind, readUpdateState, runAutoUpdateWorker, writeUpdateState } from "../src/auto-update.js";

let dir: string;
let statePath: string;
const DAY = 24 * 60 * 60 * 1000;
const now = Date.parse("2026-10-23T12:00:00Z");
beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "beam-update-")); statePath = join(dir, "update-state.json"); });
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

describe("when auto-update may run", () => {
  it("only for interactive, user-facing commands, and never when an admin turned it off", () => {
    expect(autoUpdateAllowed("agent", {}, true)).toBe(true);
    expect(autoUpdateAllowed("setup", {}, true)).toBe(true);
    for (const command of ["hook", "run", "mcp", "start", "monitor", "update", "__auto-update"]) expect(autoUpdateAllowed(command, {}, true)).toBe(false);
    expect(autoUpdateAllowed("agent", {}, false)).toBe(false);
    expect(autoUpdateAllowed("agent", { CI: "true" }, true)).toBe(false);
    expect(autoUpdateAllowed("agent", { BEAM_DISABLE_AUTOUPDATE: "1" }, true)).toBe(false);
    expect(autoUpdateAllowed("agent", { BEAM_AUTO_UPDATE_WORKER: "1" }, true)).toBe(false);
  });
  it("knows npm installs from source checkouts", () => {
    expect(installKind("/usr/local/lib/node_modules/@agent-beam/beam/dist/auto-update.js")).toBe("npm");
    expect(installKind("C:\\Users\\a\\AppData\\Roaming\\npm\\node_modules\\@agent-beam\\beam\\dist\\auto-update.js")).toBe("npm");
    expect(installKind("/Users/dev/code/beam-cli/dist/auto-update.js")).toBe("source");
    expect(compareVersions("0.2.27", "0.2.26")).toBeGreaterThan(0);
    expect(compareVersions("0.2.26", "0.2.26")).toBe(0);
  });
});

describe("the per-command tick", () => {
  it("starts one background check a day and never waits for it", async () => {
    const startWorker = jest.fn();
    expect(await autoUpdateTick("0.2.26", { now, kind: "npm", statePath, startWorker })).toBeNull();
    expect(startWorker).toHaveBeenCalledTimes(1);
    expect(await autoUpdateTick("0.2.26", { now: now + 60_000, kind: "npm", statePath, startWorker })).toBeNull();
    expect(startWorker).toHaveBeenCalledTimes(1);
    await autoUpdateTick("0.2.26", { now: now + DAY + 1, kind: "npm", statePath, startWorker });
    expect(startWorker).toHaveBeenCalledTimes(2);
  });
  it("doesn't start a second install while one is running", async () => {
    await writeUpdateState({ checkedAt: new Date(now - 2 * DAY).toISOString(), installing: { version: "0.2.27", pid: process.pid, startedAt: new Date(now - 60_000).toISOString() } }, statePath);
    const startWorker = jest.fn();
    await autoUpdateTick("0.2.26", { now, kind: "npm", statePath, startWorker });
    expect(startWorker).not.toHaveBeenCalled();
  });
  it("announces a finished update once, with what to restart", async () => {
    await writeUpdateState({ checkedAt: new Date(now).toISOString(), installed: { version: "0.2.27", from: "0.2.26", at: new Date(now).toISOString() } }, statePath);
    const notice = await autoUpdateTick("0.2.27", { now, kind: "npm", statePath, startWorker: () => {} });
    expect(notice).toContain("Beam updated to v0.2.27 (from v0.2.26)");
    expect(notice).toContain("beam service stop && beam service start");
    expect(await autoUpdateTick("0.2.27", { now: now + 1000, kind: "npm", statePath, startWorker: () => {} })).toBeNull();
  });
  it("falls back to 'beam update' when the background install wasn't allowed", async () => {
    await writeUpdateState({ checkedAt: new Date(now - 2 * DAY).toISOString(), failed: { version: "0.2.27", at: new Date(now - 2 * DAY).toISOString(), reason: "EACCES" } }, statePath);
    expect(await autoUpdateTick("0.2.26", { now, kind: "npm", statePath, startWorker: () => {} })).toContain("Run 'beam update'");
  });
  it("stays silent when turned off, and for source checkouts", async () => {
    const startWorker = jest.fn();
    await writeUpdateState({ autoUpdate: false }, statePath);
    expect(await autoUpdateTick("0.2.26", { now, kind: "npm", statePath, startWorker })).toBeNull();
    await writeUpdateState({}, statePath);
    expect(await autoUpdateTick("0.2.26", { now, kind: "source", statePath, startWorker })).toBeNull();
    expect(startWorker).not.toHaveBeenCalled();
  });
  it("tells standalone binaries where to download, since they can't install themselves", async () => {
    const notice = await autoUpdateTick("0.2.26", { now, kind: "binary", statePath, fetchLatest: async () => "0.2.27" });
    expect(notice).toContain("Beam v0.2.27 is available");
    expect(await autoUpdateTick("0.2.26", { now: now + 1000, kind: "binary", statePath, fetchLatest: async () => "0.2.27" })).toBeNull();
  });
});

describe("the background worker", () => {
  it("installs a newer release and records it for the next command", async () => {
    const install = jest.fn(async () => {});
    await runAutoUpdateWorker({ current: "0.2.26", statePath, fetchLatest: async () => "0.2.27", install });
    expect(install).toHaveBeenCalledWith("0.2.27");
    expect(await readUpdateState(statePath)).toMatchObject({ installed: { version: "0.2.27", from: "0.2.26" } });
  });
  it("records a failure instead of escalating, and does nothing when up to date", async () => {
    await runAutoUpdateWorker({ current: "0.2.26", statePath, fetchLatest: async () => "0.2.27", install: async () => { throw new Error("EACCES: permission denied"); } });
    expect((await readUpdateState(statePath)).failed).toMatchObject({ version: "0.2.27", reason: expect.stringContaining("EACCES") });
    const install = jest.fn(async () => {});
    await runAutoUpdateWorker({ current: "0.2.27", statePath, fetchLatest: async () => "0.2.27", install });
    expect(install).not.toHaveBeenCalled();
  });
});
