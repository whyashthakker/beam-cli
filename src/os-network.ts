// Ported from ex-check's internal/network/monitor.go. Polls `lsof` for TCP/UDP sockets (macOS
// only) and diffs successive snapshots by connection identity to report connections opening and
// closing. lsof only reports {pid, process name} for the owning process -- os-process.ts's
// ProcessMonitor.lookup() is used to enrich that into a full record before detection runs.
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const SCAN_TIMEOUT_MS = 2000;

export interface NetworkConnection {
  protocol: string; localIP: string; localPort: string; remoteIP: string; remotePort: string;
  state: string; pid: number; processName: string;
}

export interface NetworkChanges { started: NetworkConnection[]; closed: NetworkConnection[] }

function splitHostPort(value: string): [string, string] {
  const trimmed = value.trim();
  const index = trimmed.lastIndexOf(":");
  if (index < 0) return [trimmed, ""];
  return [trimmed.slice(0, index), trimmed.slice(index + 1)];
}

function parseAddressPair(value: string): [string, string, string, string] {
  const arrow = value.indexOf("->");
  if (arrow < 0) { const [ip, port] = splitHostPort(value); return [ip, port, "", ""]; }
  const [localIP, localPort] = splitHostPort(value.slice(0, arrow));
  const [remoteIP, remotePort] = splitHostPort(value.slice(arrow + 2));
  return [localIP, localPort, remoteIP, remotePort];
}

export function parseLSOFOutput(output: string): NetworkConnection[] {
  const events: NetworkConnection[] = [];
  let pid = 0;
  let processName = "";
  let current: Partial<NetworkConnection> = {};

  const flush = () => {
    if (!current.protocol || !current.localIP) return;
    events.push({ protocol: current.protocol, localIP: current.localIP, localPort: current.localPort ?? "", remoteIP: current.remoteIP ?? "", remotePort: current.remotePort ?? "", state: current.state ?? "", pid, processName });
  };

  for (const line of output.split("\n")) {
    if (!line) continue;
    const key = line[0];
    const value = line.slice(1);
    switch (key) {
      case "p": flush(); current = {}; pid = Number(value) || 0; break;
      case "c": processName = value; break;
      case "f": flush(); current = {}; break;
      case "P": current.protocol = value.toLowerCase(); break;
      case "n": { const [localIP, localPort, remoteIP, remotePort] = parseAddressPair(value); current.localIP = localIP; current.localPort = localPort; current.remoteIP = remoteIP; current.remotePort = remotePort; break; }
      case "T": if (value.startsWith("ST=")) current.state = value.slice(3); break;
    }
  }
  flush();
  return events;
}

async function snapshot(): Promise<NetworkConnection[]> {
  const { stdout } = await execFileAsync("lsof", ["-nP", "-iTCP", "-iUDP", "-F", "pcPTn"], { maxBuffer: 16 * 1024 * 1024, timeout: SCAN_TIMEOUT_MS });
  return parseLSOFOutput(stdout);
}

function connectionKey(c: NetworkConnection): string {
  return [c.protocol, c.localIP, c.localPort, c.remoteIP, c.remotePort, c.state, c.pid, c.processName].join("|");
}

function indexByConnection(events: NetworkConnection[]): Map<string, NetworkConnection> {
  const indexed = new Map<string, NetworkConnection>();
  for (const event of events) indexed.set(connectionKey(event), event);
  return indexed;
}

export class NetworkMonitor {
  private known = new Map<string, NetworkConnection>();
  private supported: boolean;

  constructor(private readonly snapshotFn: () => Promise<NetworkConnection[]> = snapshot, supported = process.platform === "darwin") {
    this.supported = supported;
  }

  get isSupported(): boolean { return this.supported; }

  async baseline(): Promise<void> {
    if (!this.supported) return;
    this.known = indexByConnection(await this.snapshotFn());
  }

  async changes(): Promise<NetworkChanges> {
    if (!this.supported) return { started: [], closed: [] };
    const next = indexByConnection(await this.snapshotFn());
    const started: NetworkConnection[] = [];
    const closed: NetworkConnection[] = [];
    for (const [key, event] of next) if (!this.known.has(key)) started.push(event);
    for (const [key, event] of this.known) if (!next.has(key)) closed.push(event);
    this.known = next;
    return { started, closed };
  }
}
