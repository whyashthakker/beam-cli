import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { jest } from "@jest/globals";

// child_process.execFile is mocked before importing src/service.ts so installService()
// never shells out to the real launchctl/systemctl on the machine running these tests.
// util.promisify calls execFile(cmd, args, callback) — no options object — so the mock
// must accept a variadic tail and find the callback itself.
type ExecCallback = (err: Error | null, result: { stdout: string; stderr: string }) => void;
let nextResult: { stdout: string; stderr: string } = { stdout: "", stderr: "" };
const execFileMock = jest.fn((..._args: unknown[]) => {
  const callback = _args[_args.length - 1] as ExecCallback;
  callback(null, nextResult);
  return {} as unknown;
});

jest.unstable_mockModule("node:child_process", () => ({ execFile: execFileMock }));

const { installService, uninstallService, startService, stopService, serviceStatus, macPlist, macPlistPath, systemdUnit, systemdUnitPath } = await import("../src/service.js");

const temporaryDirectories: string[] = [];

afterEach(async () => {
  execFileMock.mockClear();
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

async function tempHome(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-service-"));
  temporaryDirectories.push(dir);
  // getDataDirectory() (used internally by install/uninstall) defaults to the real ~/.beam
  // unless overridden — point it at this same throwaway directory so nothing real is touched.
  process.env.BEAM_DATA_DIR = path.join(dir, "data");
  return dir;
}

const originalBeamDataDir = process.env.BEAM_DATA_DIR;
afterAll(() => { if (originalBeamDataDir === undefined) delete process.env.BEAM_DATA_DIR; else process.env.BEAM_DATA_DIR = originalBeamDataDir; });

function calledWithCommand(cmd: string, args: string[]): boolean {
  return execFileMock.mock.calls.some(call => call[0] === cmd && JSON.stringify(call[1]) === JSON.stringify(args));
}

describe("macOS launchd plist generation", () => {
  it("embeds the requested port and points at the built cli.js, not a bare 'beam' command", () => {
    const plist = macPlist(4400, "/tmp/beam-data");
    expect(plist).toContain("<string>4400</string>");
    expect(plist).toContain("cli.js");
    expect(plist).toContain("<key>RunAtLoad</key><true/>");
    expect(plist).toContain("<key>KeepAlive</key><true/>");
  });

  it("escapes XML special characters in paths", () => {
    expect(macPlist(4319, "/tmp/beam-data")).not.toContain(" & ");
  });
});

describe("systemd unit generation", () => {
  it("embeds the requested port and restart policy", () => {
    const unit = systemdUnit(4400, "/tmp/beam-data");
    expect(unit).toContain("--port 4400");
    expect(unit).toContain("Restart=always");
  });
});

describe("installService (darwin)", () => {
  const originalPlatform = process.platform;
  beforeEach(() => { Object.defineProperty(process, "platform", { value: "darwin" }); });
  afterEach(() => { Object.defineProperty(process, "platform", { value: originalPlatform }); });

  it("writes the plist file and calls launchctl load, never touching the real home directory", async () => {
    const home = await tempHome();
    const result = await installService({ port: 4400, home });
    expect(result.configPath).toBe(macPlistPath(home));
    const written = await fs.readFile(result.configPath, "utf8");
    expect(written).toContain("4400");
    expect(calledWithCommand("launchctl", ["load", "-w", macPlistPath(home)])).toBe(true);
  });

  it("uninstall removes the plist file", async () => {
    const home = await tempHome();
    const result = await installService({ port: 4319, home });
    await uninstallService(home);
    await expect(fs.readFile(result.configPath, "utf8")).rejects.toThrow();
  });

  it("start/stop call launchctl load/unload without touching the filesystem", async () => {
    const home = await tempHome();
    await installService({ port: 4319, home });
    execFileMock.mockClear();
    await startService(home);
    expect(calledWithCommand("launchctl", ["load", "-w", macPlistPath(home)])).toBe(true);
    await stopService(home);
    expect(calledWithCommand("launchctl", ["unload", "-w", macPlistPath(home)])).toBe(true);
  });

  it("status reports managed:false when launchctl list has no matching label", async () => {
    const home = await tempHome();
    const result = await serviceStatus(home);
    expect(result.managed).toBe(false);
    expect(result.running).toBe(false);
  });

  it("status reports running:true when launchctl list includes the label", async () => {
    nextResult = { stdout: "1234\t0\tai.beam.collector\n", stderr: "" };
    const home = await tempHome();
    const result = await serviceStatus(home);
    expect(result.running).toBe(true);
    nextResult = { stdout: "", stderr: "" };
  });
});

describe("installService (linux)", () => {
  const originalPlatform = process.platform;
  beforeEach(() => { Object.defineProperty(process, "platform", { value: "linux" }); });
  afterEach(() => { Object.defineProperty(process, "platform", { value: originalPlatform }); });

  it("writes the systemd unit file and enables it via systemctl --user", async () => {
    const home = await tempHome();
    const result = await installService({ port: 4400, home });
    expect(result.configPath).toBe(systemdUnitPath(home));
    const written = await fs.readFile(result.configPath, "utf8");
    expect(written).toContain("--port 4400");
    expect(calledWithCommand("systemctl", ["--user", "enable", "--now", "beam.service"])).toBe(true);
  });

  it("uninstall disables the unit and removes the file", async () => {
    const home = await tempHome();
    const result = await installService({ port: 4319, home });
    await uninstallService(home);
    expect(calledWithCommand("systemctl", ["--user", "disable", "--now", "beam.service"])).toBe(true);
    await expect(fs.readFile(result.configPath, "utf8")).rejects.toThrow();
  });
});
