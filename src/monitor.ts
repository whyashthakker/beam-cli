// `beam monitor`: 24x7 watch over a running application's logs and traffic. Lines are matched
// against monitor-rules.ts on this machine; only redacted, deduplicated findings are sent to the
// workspace, which stores them, meters them and delivers them to the workspace's webhooks.
//
// It never blocks or alters the application: it reads log files (or a pipe it echoes straight
// through) and does nothing else to the app. It is also inert until the workspace turns App
// monitoring on in the dashboard -- before that, and whenever it is turned off again or the
// monthly allowance runs out, lines are read and discarded.
import { createHash } from "node:crypto";
import { open, type FileHandle } from "node:fs/promises";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { StringDecoder } from "node:string_decoder";
import { readIdentity } from "./enroll.js";
import { readPolicy } from "./policy.js";
import { readInstalledPackages } from "./lockfiles.js";
import {
  checkPackages, fetchMonitorConfig, sendFindings,
  type MonitorConfig, type MonitorFinding, type MonitorLevel, type MonitorSeverity, type Vulnerability,
} from "./monitor-client.js";
import { clientIp, isAuthFailure, lineSource, matchLine, redactLine } from "./monitor-rules.js";
import { judgeWithOwnLlm, ownLlmConfig } from "./monitor-llm.js";
import type { CustomDetector } from "./data-detectors.js";

const RANK: Record<MonitorSeverity, number> = { critical: 3, high: 2, medium: 1, low: 0 };
const MIN_RANK: Record<MonitorLevel, number> = { light: 3, standard: 2, strict: 1 };
/** light: critical only · standard: high and up · strict: medium and up (same thresholds as the server). */
export const meetsLevel = (severity: MonitorSeverity, level: MonitorLevel) => RANK[severity] >= MIN_RANK[level];

// One finding absorbs repeats (its `count` goes up) for this long before a new one is raised.
export const DEDUPE_WINDOW_MS: Record<MonitorLevel, number> = { light: 60 * 60_000, standard: 15 * 60_000, strict: 5 * 60_000 };
// Failed sign-ins from one address within five minutes before it counts as brute forcing.
export const BRUTE_FORCE_THRESHOLD: Record<MonitorLevel, number> = { light: 50, standard: 20, strict: 10 };
const BRUTE_FORCE_WINDOW_MS = 5 * 60_000;
// A scan or a log loop can match thousands of distinct lines; past this many new findings in ten
// minutes the rest are folded into one summary finding so a flood can't spend the month's allowance.
export const MAX_NEW_FINDINGS_PER_10_MIN = 200;
const FLOOD_WINDOW_MS = 10 * 60_000;
const MAX_QUEUE = 1000;
const BATCH_SIZE = 100;

export type SendOutcome = "sent" | "retry" | "drop";

/** Groups lines that differ only in ids, numbers, addresses or timestamps. */
function normalizeForGrouping(line: string): string {
  return line.toLowerCase()
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "<ip>")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<id>")
    .replace(/\b[0-9a-f]{16,}\b/g, "<hex>")
    .replace(/\d+/g, "0")
    .replace(/\s+/g, " ")
    .slice(0, 300);
}

export interface PipelineOptions {
  /** The active level, or null while capture is off (not enabled, or the allowance is spent). */
  level: () => MonitorLevel | null;
  customDetectors?: () => CustomDetector[];
  now?: () => number;
}

export class MonitorPipeline {
  private seen = new Map<string, { bucket: number; finding: MonitorFinding; at: number }>();
  private queue: MonitorFinding[] = [];
  private queued = new Set<string>();
  private authFailures = new Map<string, number[]>();
  private floodBucket = -1;
  private floodCount = 0;
  private suppressed: { count: number; severity: MonitorSeverity } | null = null;

  constructor(private readonly opts: PipelineOptions) {}

  private now(): number { return this.opts.now?.() ?? Date.now(); }

  get pending(): MonitorFinding[] { return [...this.queue]; }

  /** Matches one line and queues any findings at or above the level. Returns the rule ids raised. */
  ingestLine(line: string, file?: string): string[] {
    const level = this.opts.level();
    if (!level || !line.trim()) return [];
    const custom = this.opts.customDetectors?.() ?? [];
    const source = lineSource(line);
    const ip = source === "http" ? clientIp(line) : undefined;
    const raised: string[] = [];
    for (const rule of matchLine(line, source)) {
      if (!meetsLevel(rule.severity, level)) continue;
      // Traffic groups by client address (one scan = one finding); app logs group by line shape.
      this.raise(level, ip ?? normalizeForGrouping(line), {
        ruleId: rule.id, title: ip ? `${rule.title} from ${ip}` : rule.title, severity: rule.severity,
        category: rule.category, source, file, evidence: redactLine(line, custom),
      });
      raised.push(rule.id);
    }
    if (isAuthFailure(line, source) && meetsLevel("high", level)) {
      const key = clientIp(line) ?? "unknown address";
      const now = this.now();
      const recent = (this.authFailures.get(key) ?? []).filter(t => now - t < BRUTE_FORCE_WINDOW_MS);
      recent.push(now);
      this.authFailures.set(key, recent);
      if (this.authFailures.size > 10_000) this.authFailures.delete(this.authFailures.keys().next().value!);
      if (recent.length >= BRUTE_FORCE_THRESHOLD[level]) {
        this.raise(level, key, {
          ruleId: "app.auth_bruteforce", title: `Repeated failed sign-ins from ${key}`, severity: "high", category: "recon",
          source, file, evidence: `${recent.length} failures in 5 minutes. Latest: ${redactLine(line, custom)}`.slice(0, 600),
        });
        raised.push("app.auth_bruteforce");
      }
    }
    return raised;
  }

  /** Queues a finding produced elsewhere (dependency checks) under its own stable id, once. */
  addFinding(finding: MonitorFinding): boolean {
    const level = this.opts.level();
    if (!level || !meetsLevel(finding.severity, level) || this.queued.has(finding.id)) return false;
    this.queued.add(finding.id);
    this.enqueue(finding);
    return true;
  }

  private raise(level: MonitorLevel, groupKey: string, partial: Omit<MonitorFinding, "id" | "count" | "firstSeen">): void {
    const now = this.now();
    const bucket = Math.floor(now / DEDUPE_WINDOW_MS[level]);
    const fp = createHash("sha256").update(`${partial.ruleId}\0${groupKey}`).digest("hex").slice(0, 24);
    const existing = this.seen.get(fp);
    if (existing && existing.bucket === bucket) {
      existing.finding.count++; // still queued: the batch carries the new count
      return;
    }
    const flood = Math.floor(now / FLOOD_WINDOW_MS);
    if (flood !== this.floodBucket) {
      this.emitSuppressed();
      this.floodBucket = flood;
      this.floodCount = 0;
    }
    if (this.floodCount >= MAX_NEW_FINDINGS_PER_10_MIN) {
      const worst = this.suppressed && RANK[this.suppressed.severity] >= RANK[partial.severity] ? this.suppressed.severity : partial.severity;
      this.suppressed = { count: (this.suppressed?.count ?? 0) + 1, severity: worst };
      return;
    }
    this.floodCount++;
    const finding: MonitorFinding = { id: `${fp}-${bucket}`, ...partial, count: 1, firstSeen: new Date(now).toISOString() };
    this.seen.set(fp, { bucket, finding, at: now });
    this.enqueue(finding);
  }

  private emitSuppressed(): void {
    if (!this.suppressed) return;
    const { count, severity } = this.suppressed;
    this.suppressed = null;
    this.enqueue({
      id: `flood-${this.floodBucket}`, ruleId: "beam.monitor.flood", title: "Too many findings to send individually", severity,
      category: "integrity", source: "log", count,
      evidence: `${count} more findings within 10 minutes were not sent one by one, to protect the monthly allowance. Check this server's logs.`,
      firstSeen: new Date(this.floodBucket * FLOOD_WINDOW_MS).toISOString(),
    });
  }

  private enqueue(finding: MonitorFinding): void {
    if (this.queue.length >= MAX_QUEUE) {
      // Full (usually: the workspace is unreachable). Make room by dropping the least severe, oldest.
      let drop = 0;
      for (let i = 1; i < this.queue.length; i++) if (RANK[this.queue[i]!.severity] < RANK[this.queue[drop]!.severity]) drop = i;
      this.queue.splice(drop, 1);
    }
    this.queue.push(finding);
  }

  /** Sends queued findings in batches; a "retry" outcome keeps the batch for the next flush. */
  async flush(send: (batch: MonitorFinding[]) => Promise<SendOutcome>): Promise<void> {
    if (this.suppressed && Math.floor(this.now() / FLOOD_WINDOW_MS) !== this.floodBucket) this.emitSuppressed();
    while (this.queue.length) {
      const batch = this.queue.splice(0, BATCH_SIZE);
      if ((await send(batch)) === "retry") {
        this.queue.unshift(...batch);
        break;
      }
    }
    const cutoff = this.now() - 2 * DEDUPE_WINDOW_MS.light;
    for (const [fp, entry] of this.seen) if (entry.at < cutoff) this.seen.delete(fp);
  }
}

/** Follows a log file like `tail -F`: survives rotation (new inode) and truncation (copytruncate). */
export class FileTailer {
  private offset = 0;
  private ino = -1;
  private tracking = false;
  private firstPoll = true;
  private partial = "";
  private decoder = new StringDecoder("utf8");
  // The last bytes read. If they're no longer at the same position, the file was truncated and
  // rewritten past our offset between polls (copytruncate under load), which size alone can't show.
  private signature: Buffer = Buffer.alloc(0);
  private timer: NodeJS.Timeout | undefined;
  private busy = false;

  constructor(private readonly path: string, private readonly onLine: (line: string) => void, private readonly fromStart = false) {}

  start(intervalMs = 1000): void {
    void this.poll();
    this.timer = setInterval(() => void this.poll(), intervalMs);
  }

  stop(): void { if (this.timer) clearInterval(this.timer); }

  private reset(offset: number, ino: number): void {
    this.offset = offset;
    this.ino = ino;
    this.partial = "";
    this.decoder = new StringDecoder("utf8");
    this.signature = Buffer.alloc(0);
  }

  async poll(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    let handle: FileHandle | undefined;
    try {
      try { handle = await open(this.path, "r"); } catch { this.firstPoll = false; return; } // not there (yet): keep waiting
      const info = await handle.stat();
      if (!this.tracking) {
        // Existing file at start: begin at the end, like tail. A file that appears later is read whole.
        this.reset(this.firstPoll && !this.fromStart ? info.size : 0, info.ino);
        this.tracking = true;
        const keep = Math.min(SIGNATURE_BYTES, this.offset);
        if (keep) this.signature = await readAt(handle, this.offset - keep, keep);
      } else if (info.ino !== this.ino || info.size < this.offset || !(await this.signatureHolds(handle))) {
        this.reset(0, info.ino);
      }
      this.firstPoll = false;
      while (info.size > this.offset) {
        const chunk = await readAt(handle, this.offset, Math.min(info.size - this.offset, 4 * 1024 * 1024));
        if (!chunk.length) break;
        this.offset += chunk.length;
        this.signature = Buffer.concat([this.signature, chunk.subarray(-SIGNATURE_BYTES)]).subarray(-SIGNATURE_BYTES);
        const lines = (this.partial + this.decoder.write(chunk)).split(/\r?\n/);
        this.partial = lines.pop() ?? "";
        if (this.partial.length > 65_536) { lines.push(this.partial.slice(0, 65_536)); this.partial = ""; }
        for (const line of lines) this.onLine(line);
      }
    } finally {
      await handle?.close();
      this.busy = false;
    }
  }

  private async signatureHolds(handle: FileHandle): Promise<boolean> {
    if (!this.signature.length) return true;
    return (await readAt(handle, this.offset - this.signature.length, this.signature.length)).equals(this.signature);
  }
}

const SIGNATURE_BYTES = 64;
async function readAt(handle: FileHandle, position: number, length: number): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, position);
  return buffer.subarray(0, bytesRead);
}

const SEVERITIES: MonitorSeverity[] = ["critical", "high", "medium", "low"];
/** A dependency vulnerability as a monitor finding. CISA KEV (exploited in the wild) is raised to critical. */
export function vulnerabilityFinding(v: Vulnerability): MonitorFinding {
  const severity: MonitorSeverity = v.kev ? "critical" : SEVERITIES.includes(v.severity as MonitorSeverity) ? (v.severity as MonitorSeverity) : "medium";
  const id = createHash("sha256").update(`${v.id}\0${v.ecosystem}\0${v.name}\0${v.version}`).digest("hex").slice(0, 24);
  return {
    id: `cve-${id}`, ruleId: v.id, title: `${v.id} in ${v.name} ${v.version}${v.kev ? " (actively exploited)" : ""}`, severity,
    category: "cve", source: "cve", file: v.files[0], count: 1, firstSeen: new Date().toISOString(),
    evidence: `${v.name} ${v.version} (${v.ecosystem}) is in the affected range ${v.vulnerable}; ${v.patched ? `fixed in ${v.patched}` : "no fixed version yet"}. ${v.title} ${v.url}`.slice(0, 600),
  };
}

export interface MonitorOptions {
  files?: string[];
  stdin?: boolean;
  /** Pass stdin lines through to stdout so piping an app into beam doesn't swallow its output. */
  echo?: boolean;
  /** App directory whose lockfiles are checked for known vulnerabilities at start and daily. */
  app?: string;
  fromStart?: boolean;
  /** Keep waiting while App monitoring is off in the dashboard (default) instead of exiting. */
  wait?: boolean;
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

export async function runMonitor(options: MonitorOptions, log: (message: string) => void = m => console.error(`[beam monitor] ${m}`)): Promise<void> {
  const files = (options.files ?? []).map(f => resolve(f));
  const appDir = options.app ? resolve(options.app) : undefined;
  if (!files.length && !options.stdin && !appDir)
    throw new Error("Tell beam monitor what to watch: --file <path> (repeatable) for log files, --stdin to read piped output, and/or --app <dir> for dependency checks.");
  const identity = await readIdentity();
  if (!identity) throw new Error("Connect this server to your Beam workspace first: run 'beam connect'. App monitoring is then turned on for the workspace in the dashboard.");
  const custom = (await readPolicy())?.rules.customDetectors ?? [];
  const ownLlm = ownLlmConfig();

  let config: MonitorConfig | null = null;
  let lastRefresh = 0;
  let pausedUntil = 0;
  let offNotice = false;
  let fatal: Error | null = null;

  const refresh = async (): Promise<void> => {
    lastRefresh = Date.now();
    const result = await fetchMonitorConfig(identity);
    if (result.ok) {
      if (!config) {
        log(`App monitoring is on (${result.config.level} level). Findings go to your workspace${result.config.webhooks ? ` and ${result.config.webhooks} webhook${result.config.webhooks === 1 ? "" : "s"}` : ""}.`);
        log(ownLlm
          ? `LLM checks: your own model, ${ownLlm.model} at ${new URL(ownLlm.baseUrl).host}.`
          : `LLM checks: ${result.config.llm ? "Beam's model (set in the dashboard)" : "off"}.`);
      }
      else if (config.level !== result.config.level) log(`Level changed to ${result.config.level}.`);
      config = result.config;
      offNotice = false;
      return;
    }
    if (result.status === "disabled") {
      if (!offNotice) log(`${result.message}${options.wait === false ? "" : " Nothing is captured until then; checking again every minute."}`);
      offNotice = true;
      config = null;
      return;
    }
    if (result.status === "revoked" || result.status === "unsupported") throw new Error(result.message);
    log(`${result.message} Retrying.`); // unreachable: keep the last known settings
  };

  await refresh();
  while (!config) {
    if (options.wait === false) throw new Error("App monitoring is not on for this workspace.");
    await sleep(60_000);
    await refresh();
  }

  const pipeline = new MonitorPipeline({
    level: () => (config && Date.now() >= pausedUntil ? config.level : null),
    customDetectors: () => custom,
  });
  const send = async (batch: MonitorFinding[]): Promise<SendOutcome> => {
    if (ownLlm && config) await judgeWithOwnLlm(batch, config.level, ownLlm);
    const result = await sendFindings(identity, batch);
    if (result.ok) return "sent";
    if (result.status === "disabled") {
      log(`${result.message} Capture paused.`);
      config = null;
      offNotice = true;
      return "drop";
    }
    if (result.status === "quota") {
      pausedUntil = result.resetAt ? Date.parse(result.resetAt) : Date.now() + 60 * 60_000;
      log(`${result.message} Capture paused until then.`);
      return "drop";
    }
    if (result.status === "revoked" || result.status === "unsupported") {
      fatal = new Error(result.message);
      return "drop";
    }
    return "retry";
  };

  const checkDependencies = async () => {
    if (!appDir || !config) return;
    const scan = await readInstalledPackages(appDir);
    if (!scan.packages.length) { log(`No pinned dependencies found under ${appDir}; skipping the dependency check.`); return; }
    const result = await checkPackages(identity, scan.packages);
    if (!result.ok) { log(`Dependency check skipped: ${result.message}`); return; }
    const { vulnerabilities, checked } = result.result;
    log(`Dependency check: ${vulnerabilities.length} known vulnerabilit${vulnerabilities.length === 1 ? "y" : "ies"} in ${checked} packages under ${appDir}.`);
    for (const v of vulnerabilities) pipeline.addFinding(vulnerabilityFinding(v));
  };

  const tailers = files.map(path => new FileTailer(path, line => pipeline.ingestLine(line, path), options.fromStart));
  for (const tailer of tailers) tailer.start();
  if (files.length) log(`Watching ${files.join(", ")}.`);

  let flushing = false;
  const flush = async () => {
    if (flushing) return;
    flushing = true;
    try { await pipeline.flush(send); } finally { flushing = false; }
  };
  const timers = [
    setInterval(() => void flush(), 5_000),
    setInterval(() => {
      if (Date.now() - lastRefresh >= (config ? 5 * 60_000 : 60_000)) void refresh().catch(e => { fatal = e as Error; });
    }, 15_000),
    setInterval(() => void checkDependencies(), 24 * 60 * 60_000),
  ];
  void checkDependencies();

  let stdinDone = !options.stdin;
  if (options.stdin) {
    if (options.echo !== false) process.stdout.on("error", () => { /* downstream closed; keep monitoring */ });
    const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
    lines.on("line", line => {
      if (options.echo !== false) process.stdout.write(`${line}\n`);
      pipeline.ingestLine(line, "stdin");
    });
    lines.on("close", () => { stdinDone = true; });
  }

  let stopping = false;
  const stop = () => { stopping = true; };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  // Runs until stopped or revoked; when reading only a pipe, also until the piped app exits.
  const endsWithStdin = Boolean(options.stdin) && !files.length;
  while (!stopping && !fatal && !(endsWithStdin && stdinDone)) await sleep(250);
  for (const timer of timers) clearInterval(timer);
  for (const tailer of tailers) tailer.stop();
  process.removeListener("SIGINT", stop);
  process.removeListener("SIGTERM", stop);
  // Last flush, bounded so a dead network can't hold up shutdown.
  let giveUp: NodeJS.Timeout | undefined;
  await Promise.race([flush(), new Promise(r => { giveUp = setTimeout(r, 5_000); })]);
  clearTimeout(giveUp);
  if (fatal) throw fatal;
}

const fmt = (n: number) => (n >= 2_147_483_647 ? "unlimited" : n.toLocaleString("en-US"));

export async function monitorStatus(write: (line: string) => void = console.log): Promise<number> {
  const identity = await readIdentity();
  if (!identity) { write("Not connected to a Beam workspace. Run 'beam connect' first."); return 1; }
  const result = await fetchMonitorConfig(identity);
  if (!result.ok) {
    write(result.status === "disabled" ? `App monitoring: off\n${result.message}` : result.message);
    return result.status === "disabled" ? 0 : 1;
  }
  const { level, llm, webhooks, usage, limits, resetAt, settingsUrl } = result.config;
  let own: ReturnType<typeof ownLlmConfig> = null;
  let ownError = "";
  try { own = ownLlmConfig(); } catch (error) { ownError = (error as Error).message; }
  write([
    "App monitoring: on",
    `Level:          ${level}`,
    `LLM checks:     ${own ? `your own model, ${own.model} at ${new URL(own.baseUrl).host}` : ownError ? `misconfigured: ${ownError}` : llm ? "Beam's model" : "off"}`,
    `Webhooks:       ${webhooks}`,
    `This month:     ${fmt(usage.findings)} / ${fmt(limits.findings)} findings · ${fmt(usage.cveChecks)} / ${fmt(limits.cveChecks)} dependency checks · ${fmt(usage.llmChecks)} / ${fmt(limits.llmChecks)} LLM checks (resets ${resetAt.slice(0, 10)})`,
    `Settings:       ${settingsUrl}`,
  ].join("\n"));
  return 0;
}
