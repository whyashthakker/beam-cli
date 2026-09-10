// Orchestrates OS-level observation of AI agent activity (ported from ex-check's daemon.go),
// independent of any agent's own hook cooperation. os-process.ts polls `ps` for process
// start/exit; every process is tagged by os-detect.ts, and only records that resolve to a known
// AI agent are ever emitted -- this is what makes it safe to run continuously without flooding
// the event store with unrelated machine activity. macOS only (matches ex-check); a no-op
// elsewhere.
//
// os-network.ts (TCP/UDP connection open/close via `lsof`) exists and is unit-tested, but is not
// wired in here by default: a single chatty agent extension churns through dozens of short-lived
// TLS connections to the same handful of CDN IPs per poll tick, all HTTPS, none of it carrying
// any signal today's text-based rules can use -- and beam's store caps retention at 10,000
// events, so that volume would evict real hook/process history rather than just being ignorable
// noise the way it is in ex-check's unbounded NDJSON stream. Flip ENABLE_NETWORK_MONITOR on (and
// consider deduping by remote host instead of full connection tuple first) if you want it back.
import { randomUUID } from "node:crypto";
import { normalize, type Event } from "./core.js";
import { ProcessMonitor } from "./os-process.js";
import { NetworkMonitor } from "./os-network.js";
import { detectProcess, type DetectedProcess } from "./os-detect.js";

const POLL_INTERVAL_MS = 5000;
const ENABLE_NETWORK_MONITOR = false;

function shortLabel(process: DetectedProcess): string {
  return `${process.agent} (${process.name}, pid ${process.pid})`;
}

function ancestryLine(process: DetectedProcess): string {
  const chain = [process, ...(process.parentChain ?? [])].map(p => p.name || p.executable || String(p.pid));
  return chain.length > 1 ? `ancestry: ${chain.join(" ← ")}` : "";
}

const PROCESS_VERBS: Record<string, string> = { "process.start": "started", "process.exit": "exited", "process.observed": "is running" };

function processRecord(eventType: string, process: DetectedProcess): Record<string, unknown> | undefined {
  if (!process.isAIAgent || !process.agent) return undefined;
  const verb = PROCESS_VERBS[eventType] ?? eventType;
  // The first line is what studio's table shows (bolded, truncated to 140 chars) -- keep it a
  // short, scannable sentence. Full executable path, command line, and ancestry go on
  // subsequent lines, visible in the row's detail drawer but not cluttering the table.
  const lines = [`${shortLabel(process)} ${verb}.`, process.executable || process.name, process.commandLine, ancestryLine(process)].filter(Boolean);
  return {
    event_id: randomUUID(), source_agent: process.agent, session_id: `os:pid:${process.pid}`,
    event_type: eventType, tool_name: process.name, source_type: "os",
    content_preview: lines.join("\n"),
  };
}

const NETWORK_VERBS: Record<string, string> = { "network.connection_start": "connected to", "network.connection_close": "closed its connection to" };

function networkRecord(eventType: string, process: DetectedProcess, connection: { protocol: string; localIP: string; localPort: string; remoteIP: string; remotePort: string; state: string }): Record<string, unknown> | undefined {
  if (!process.isAIAgent || !process.agent) return undefined;
  const verb = NETWORK_VERBS[eventType] ?? eventType;
  return {
    event_id: randomUUID(), source_agent: process.agent, session_id: `os:pid:${process.pid}`,
    event_type: eventType, tool_name: process.name, source_type: "os",
    content_preview: `${shortLabel(process)} ${verb} ${connection.remoteIP}:${connection.remotePort} (${connection.protocol.toUpperCase()}${connection.state ? `, ${connection.state}` : ""}).`,
  };
}

export interface OsMonitorHandle { stop: () => void }

export async function startOsMonitor(sink: (events: Event[]) => void | Promise<void>): Promise<OsMonitorHandle> {
  const processMonitor = new ProcessMonitor();
  const networkMonitor = new NetworkMonitor();
  if (!processMonitor.isSupported) return { stop: () => {} };

  const selfPid = process.pid;
  const isSelf = (p: DetectedProcess) => p.pid === selfPid;

  await processMonitor.baseline();
  if (ENABLE_NETWORK_MONITOR) await networkMonitor.baseline();

  // Report agents already running before beam started -- Changes() below only ever reports
  // deltas against this baseline, so an agent left running in another terminal would otherwise
  // never be logged unless it happens to start a new process or connection.
  const initial: Record<string, unknown>[] = [];
  for (const proc of processMonitor.known()) {
    if (isSelf(proc)) continue;
    const record = processRecord("process.observed", proc);
    if (record) initial.push(record);
  }
  if (initial.length) await sink(initial.map(normalize));

  const tick = async () => {
    try {
      const events: Record<string, unknown>[] = [];

      const processChanges = await processMonitor.changes();
      for (const proc of processChanges.started) { if (!isSelf(proc)) { const r = processRecord("process.start", proc); if (r) events.push(r); } }
      for (const proc of processChanges.exited) { if (!isSelf(proc)) { const r = processRecord("process.exit", proc); if (r) events.push(r); } }

      if (ENABLE_NETWORK_MONITOR && networkMonitor.isSupported) {
        const networkChanges = await networkMonitor.changes();
        for (const conn of networkChanges.started) {
          const proc = detectProcess(processMonitor.lookup(conn.pid) ?? { pid: conn.pid, ppid: 0, user: "", name: conn.processName, executable: conn.processName, commandLine: "" });
          if (!isSelf(proc)) { const r = networkRecord("network.connection_start", proc, conn); if (r) events.push(r); }
        }
        for (const conn of networkChanges.closed) {
          const proc = detectProcess(processMonitor.lookup(conn.pid) ?? { pid: conn.pid, ppid: 0, user: "", name: conn.processName, executable: conn.processName, commandLine: "" });
          if (!isSelf(proc)) { const r = networkRecord("network.connection_close", proc, conn); if (r) events.push(r); }
        }
      }

      if (events.length) await sink(events.map(normalize));
    } catch {
      // A single failed `ps`/`lsof` poll (e.g. transient timeout) shouldn't take the monitor
      // down; the next tick just retries against whatever `known` state we still have.
    }
  };

  const timer = setInterval(() => { void tick(); }, POLL_INTERVAL_MS);
  timer.unref?.();
  return { stop: () => clearInterval(timer) };
}
