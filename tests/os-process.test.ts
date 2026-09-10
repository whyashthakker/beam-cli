import { describe, expect, it } from "@jest/globals";
import { ProcessMonitor } from "../src/os-process.js";
import type { DetectedProcess } from "../src/os-detect.js";

function raw(pid: number, ppid: number, name: string, commandLine = name): DetectedProcess {
  return { pid, ppid, user: "test", name, executable: `/usr/local/bin/${name}`, commandLine };
}

function fakeMonitor(snapshots: DetectedProcess[][]): ProcessMonitor {
  let call = 0;
  return new ProcessMonitor(async () => snapshots[Math.min(call++, snapshots.length - 1)], true);
}

describe("ProcessMonitor", () => {
  it("reports no changes between two identical snapshots", async () => {
    const monitor = fakeMonitor([[raw(1, 0, "bash")], [raw(1, 0, "bash")]]);
    await monitor.baseline();
    expect(await monitor.changes()).toEqual({ started: [], exited: [] });
  });

  it("reports a new process as started, tagged by detection", async () => {
    const monitor = fakeMonitor([[raw(1, 0, "bash")], [raw(1, 0, "bash"), raw(2, 1, "codex")]]);
    await monitor.baseline();
    const changes = await monitor.changes();
    expect(changes.started).toHaveLength(1);
    expect(changes.started[0]).toMatchObject({ pid: 2, agent: "codex", isAIAgent: true });
  });

  it("reports a process that disappeared as exited", async () => {
    const monitor = fakeMonitor([[raw(1, 0, "bash"), raw(2, 1, "codex")], [raw(1, 0, "bash")]]);
    await monitor.baseline();
    const changes = await monitor.changes();
    expect(changes.exited).toHaveLength(1);
    expect(changes.exited[0]).toMatchObject({ pid: 2, agent: "codex" });
  });

  it("attaches the parent chain to a started process", async () => {
    const monitor = fakeMonitor([[raw(1, 0, "zsh")], [raw(1, 0, "zsh"), raw(2, 1, "codex")]]);
    await monitor.baseline();
    const changes = await monitor.changes();
    expect(changes.started[0].parentChain?.map(p => p.pid)).toEqual([1]);
  });

  it("known() reports every currently tracked process, agent-detected", async () => {
    const monitor = fakeMonitor([[raw(1, 0, "bash"), raw(2, 1, "claude")]]);
    await monitor.baseline();
    const known = monitor.known();
    expect(known.map(p => p.pid)).toEqual([1, 2]);
    expect(known.find(p => p.pid === 2)).toMatchObject({ agent: "claude-code" });
  });

  it("lookup() enriches a bare pid with the full tracked record", async () => {
    const monitor = fakeMonitor([[raw(1, 0, "bash"), raw(2, 1, "cursor")]]);
    await monitor.baseline();
    expect(monitor.lookup(2)).toMatchObject({ pid: 2, name: "cursor", agent: "cursor" });
    expect(monitor.lookup(999)).toBeUndefined();
  });

  it("is a no-op when the platform is unsupported", async () => {
    const monitor = new ProcessMonitor(async () => { throw new Error("should not be called"); }, false);
    await monitor.baseline();
    expect(await monitor.changes()).toEqual({ started: [], exited: [] });
    expect(monitor.isSupported).toBe(false);
  });
});
