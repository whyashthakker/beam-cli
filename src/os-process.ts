// Ported from ex-check's internal/process/monitor.go. Polls `ps` (macOS only, like the Go
// original) and diffs successive snapshots by PID to report which processes started or exited,
// with each one tagged by os-detect.ts. This is what lets beam see an AI agent's own process
// (a Codex GUI panel, a Cursor helper, ...) regardless of whether that agent cooperates with any
// hook -- process monitoring never depends on the agent reporting anything about itself.
import { execFile } from "node:child_process";
import { detectProcess, type DetectedProcess } from "./os-detect.js";

const SCAN_TIMEOUT_MS = 2000;

export interface ProcessChanges { started: DetectedProcess[]; exited: DetectedProcess[] }

async function runPS(args: string[]): Promise<{ output: string; pid: number | undefined }> {
  const child = execFile("ps", args, { maxBuffer: 16 * 1024 * 1024, timeout: SCAN_TIMEOUT_MS });
  const pid = child.pid;
  let stdout = "";
  child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
  await new Promise<void>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => { if (code === 0 || code === null) resolve(); else reject(new Error(`ps exited with code ${code}`)); });
  });
  return { output: stdout, pid };
}

function parseExecutables(output: string): Map<number, string> {
  const executables = new Map<number, string>();
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const spaceIndex = trimmed.indexOf(" ");
    if (spaceIndex < 0) continue;
    const pid = Number(trimmed.slice(0, spaceIndex));
    const executable = trimmed.slice(spaceIndex + 1).trim();
    if (Number.isInteger(pid) && executable) executables.set(pid, executable);
  }
  return executables;
}

function normalizeExecutable(executable: string): string {
  return executable; // resolving through PATH isn't worth a sync lookup per row; comm= is already close to absolute on macOS.
}

function parseCommands(output: string, executables: Map<number, string>): DetectedProcess[] {
  const processes: DetectedProcess[] = [];
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const fields = trimmed.split(/\s+/);
    if (fields.length < 4) continue;
    const pid = Number(fields[0]);
    const ppid = Number(fields[1]);
    if (!Number.isInteger(pid) || !Number.isInteger(ppid)) continue;
    const user = fields[2];
    let commandLine = trimmed.slice(trimmed.indexOf(user) + user.length).trim();
    const executable = normalizeExecutable(executables.get(pid) ?? commandLine.split(/\s+/)[0] ?? "");
    const name = executable.split("/").pop() ?? executable;
    processes.push({ pid, ppid, user, name, executable, commandLine });
  }
  return processes;
}

async function snapshot(): Promise<DetectedProcess[]> {
  const [commands, executables] = await Promise.all([
    runPS(["-wwaxo", "pid=,ppid=,user=,command="]),
    runPS(["-wwaxo", "pid=,comm="]),
  ]);
  const executableMap = parseExecutables(executables.output);
  const processes = parseCommands(commands.output, executableMap);
  const excluded = new Set([commands.pid, executables.pid].filter((p): p is number => p !== undefined));
  return processes.filter(p => !excluded.has(p.pid));
}

function indexByPID(processes: DetectedProcess[]): Map<number, DetectedProcess> {
  const indexed = new Map<number, DetectedProcess>();
  for (const process of processes) indexed.set(process.pid, detectProcess({ ...process, parentChain: undefined }));
  return indexed;
}

function parentChain(process: DetectedProcess, processes: Map<number, DetectedProcess>): DetectedProcess[] {
  const chain: DetectedProcess[] = [];
  const seen = new Set<number>([process.pid]);
  let ppid = process.ppid;
  while (ppid > 0) {
    const parent = processes.get(ppid);
    if (!parent || seen.has(parent.pid)) break;
    chain.push({ ...parent, parentChain: undefined });
    seen.add(parent.pid);
    ppid = parent.ppid;
  }
  return chain;
}

export class ProcessMonitor {
  private knownProcesses = new Map<number, DetectedProcess>();
  private supported: boolean;

  // snapshotFn is injectable so tests can drive Baseline/Changes off fixed process lists instead
  // of the real `ps` (which would make tests machine-dependent and non-deterministic).
  constructor(private readonly snapshotFn: () => Promise<DetectedProcess[]> = snapshot, supported = process.platform === "darwin") {
    this.supported = supported;
  }

  get isSupported(): boolean { return this.supported; }

  async baseline(): Promise<void> {
    if (!this.supported) return;
    this.knownProcesses = indexByPID(await this.snapshotFn());
  }

  async changes(): Promise<ProcessChanges> {
    if (!this.supported) return { started: [], exited: [] };
    const next = indexByPID(await this.snapshotFn());
    const started: DetectedProcess[] = [];
    const exited: DetectedProcess[] = [];
    for (const [pid, proc] of next) {
      if (!this.knownProcesses.has(pid)) started.push({ ...proc, parentChain: parentChain(proc, next) });
    }
    for (const [pid, proc] of this.knownProcesses) {
      if (!next.has(pid)) exited.push({ ...proc, parentChain: parentChain(proc, this.knownProcesses) });
    }
    this.knownProcesses = next;
    return { started, exited };
  }

  // Every currently known process, agent-detected, for reporting agents that were already
  // running before the monitor started (Changes only ever reports deltas against the baseline).
  known(): DetectedProcess[] {
    return [...this.knownProcesses.values()]
      .map(p => ({ ...p, parentChain: parentChain(p, this.knownProcesses) }))
      .sort((a, b) => a.pid - b.pid);
  }

  // Enriches a bare {pid, name} (e.g. from lsof, which has no command line) with the full
  // process record this monitor already has, so detection has real evidence to work with.
  lookup(pid: number): DetectedProcess | undefined {
    const proc = this.knownProcesses.get(pid);
    if (!proc) return undefined;
    return { ...proc, parentChain: parentChain(proc, this.knownProcesses) };
  }
}
