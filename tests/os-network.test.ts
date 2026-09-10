import { describe, expect, it } from "@jest/globals";
import { NetworkMonitor, parseLSOFOutput, type NetworkConnection } from "../src/os-network.js";

describe("parseLSOFOutput", () => {
  it("parses a single established TCP connection", () => {
    const output = ["p1234", "ccodex", "PTCP", "n10.0.0.5:51000->1.2.3.4:443", "TST=ESTABLISHED"].join("\n");
    const events = parseLSOFOutput(output);
    expect(events).toEqual([
      { protocol: "tcp", localIP: "10.0.0.5", localPort: "51000", remoteIP: "1.2.3.4", remotePort: "443", state: "ESTABLISHED", pid: 1234, processName: "codex" },
    ]);
  });

  it("parses multiple file descriptors under the same process", () => {
    const output = [
      "p1234", "ccodex",
      "fTCP", "PTCP", "n10.0.0.5:51000->1.2.3.4:443", "TST=ESTABLISHED",
      "fTCP", "PTCP", "n10.0.0.5:51001->5.6.7.8:80", "TST=ESTABLISHED",
    ].join("\n");
    const events = parseLSOFOutput(output);
    expect(events).toHaveLength(2);
    expect(events[1]).toMatchObject({ remoteIP: "5.6.7.8", remotePort: "80" });
  });

  it("ignores a listening socket with no remote address without dropping the connection", () => {
    const output = ["p1234", "ccodex", "PTCP", "n*:8080", "TST=LISTEN"].join("\n");
    const events = parseLSOFOutput(output);
    expect(events).toEqual([{ protocol: "tcp", localIP: "*", localPort: "8080", remoteIP: "", remotePort: "", state: "LISTEN", pid: 1234, processName: "codex" }]);
  });

  it("returns nothing for empty output", () => {
    expect(parseLSOFOutput("")).toEqual([]);
  });
});

function conn(overrides: Partial<NetworkConnection>): NetworkConnection {
  return { protocol: "tcp", localIP: "10.0.0.5", localPort: "51000", remoteIP: "1.2.3.4", remotePort: "443", state: "ESTABLISHED", pid: 1234, processName: "codex", ...overrides };
}

function fakeMonitor(snapshots: NetworkConnection[][]): NetworkMonitor {
  let call = 0;
  return new NetworkMonitor(async () => snapshots[Math.min(call++, snapshots.length - 1)], true);
}

describe("NetworkMonitor", () => {
  it("reports no changes between two identical snapshots", async () => {
    const monitor = fakeMonitor([[conn({})], [conn({})]]);
    await monitor.baseline();
    expect(await monitor.changes()).toEqual({ started: [], closed: [] });
  });

  it("reports a new connection as started", async () => {
    const monitor = fakeMonitor([[], [conn({})]]);
    await monitor.baseline();
    const changes = await monitor.changes();
    expect(changes.started).toEqual([conn({})]);
  });

  it("reports a disappeared connection as closed", async () => {
    const monitor = fakeMonitor([[conn({})], []]);
    await monitor.baseline();
    const changes = await monitor.changes();
    expect(changes.closed).toEqual([conn({})]);
  });

  it("is a no-op when the platform is unsupported", async () => {
    const monitor = new NetworkMonitor(async () => { throw new Error("should not be called"); }, false);
    await monitor.baseline();
    expect(await monitor.changes()).toEqual({ started: [], closed: [] });
  });
});
