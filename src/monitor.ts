// `beam monitor`: 24x7 watch over a running application's logs and traffic. Lines are matched
// against monitor-rules.ts on this machine; only redacted, deduplicated findings are sent to the
// workspace, which stores them, meters them and delivers them to the workspace's webhooks.
//
// It never blocks or alters the application: it reads log files (or a pipe it echoes straight
// through) and does nothing else to the app. The one exception is opt-in: with --deny-file, the
// senders the workspace pauses are written to a deny list for the web server in front of the app. It is also inert until the workspace turns App
// monitoring on in the dashboard -- before that, and whenever it is turned off again or the
// monthly allowance runs out, lines are read and discarded.
import { createHash } from "node:crypto";
import { hostname } from "node:os";
import { open, type FileHandle } from "node:fs/promises";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { StringDecoder } from "node:string_decoder";
import { readPolicy } from "./policy.js";
import { readInstalledPackages } from "./lockfiles.js";
import {
  checkPackages, fetchMonitorConfig, liftPause, listPauses, monitorAuth, sendFindings, sendPauses,
  type MonitorAuth, type MonitorConfig, type MonitorFinding, type MonitorLevel, type MonitorSeverity, type Vulnerability,
} from "./monitor-client.js";
import { PAUSE_SCOPES, PauseBook, normalizeTarget, type PauseScope } from "./monitor-pause.js";
import { DENY_FORMATS, DenyListWriter, type DenyFormat, type DenyListSettings } from "./monitor-deny.js";
import { trustedLineIp } from "./monitor-rules.js";
import { LLM_PROVIDERS, describeOwnLlm, detectedLlmKeys, judgeWithOwnLlm, ownLlmConfig, type OwnLlmConfig } from "./monitor-llm.js";
import { DEFAULT_MONITOR_CONFIG, ensureMonitorConfig, monitorConfigPath, resolveMonitorSettings, writeMonitorConfig, type MonitorFileConfig, type ResolvedSettings, type SettingKey } from "./monitor-config.js";
import type { CustomDetector } from "./data-detectors.js";

export { BRUTE_FORCE_THRESHOLD, DEDUPE_WINDOW_MS, MAX_NEW_FINDINGS_PER_10_MIN, MonitorPipeline, meetsLevel, type PipelineOptions, type SendOutcome } from "./monitor-pipeline.js";
import { MonitorPipeline, type SendOutcome } from "./monitor-pipeline.js";
import { STACKS, isStack } from "./monitor-stacks.js";
import { detectStack } from "./stack-detect.js";

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
  /** LLM provider for the second opinion (--llm), with this server's own key; "beam" for Beam's model. */
  llm?: string;
  /** The most of one CPU core detection may use, in percent (--max-cpu). Default: monitor.json, else 25. */
  maxCpu?: number;
  /** A project config file to use instead of ./beam.monitor.json (--config). */
  config?: string;
  /** The app's framework (--stack). Default: detected from the --app directory. */
  stack?: string;
  /** Deny lists for paused senders (--deny-file, --auth-deny-file, --llm-deny-file), their format and the reload command. */
  denyFile?: string;
  authDenyFile?: string;
  llmDenyFile?: string;
  denyFormat?: string;
  reload?: string;
}

/** The deny-list settings after the config layers: flags replace the saved ones unless the managed config locks them. */
function pauseFrom(resolved: ResolvedSettings, options: MonitorOptions, log?: (message: string) => void): DenyListSettings {
  const flags = Boolean(options.denyFile || options.authDenyFile || options.llmDenyFile || options.denyFormat || options.reload);
  if (options.denyFormat !== undefined && !DENY_FORMATS.includes(options.denyFormat as DenyFormat))
    throw new Error(`--deny-format must be ${DENY_FORMATS.join(" or ")}.`);
  if (!flags) return resolved.settings.pause;
  if (resolved.locked.has("pause")) {
    log?.("Your organization's managed config sets the deny lists; --deny-file and --reload don't apply.");
    return resolved.settings.pause;
  }
  return {
    denyFile: options.denyFile ? resolve(options.denyFile) : null,
    authDenyFile: options.authDenyFile ? resolve(options.authDenyFile) : null,
    llmDenyFile: options.llmDenyFile ? resolve(options.llmDenyFile) : null,
    format: (options.denyFormat as DenyFormat | undefined) ?? resolved.settings.pause.format,
    reload: options.reload ?? null,
  };
}

const MAX_BACKOFF_MS = 5 * 60_000;
const backoff = (failures: number) => Math.min(MAX_BACKOFF_MS, 5_000 * 2 ** Math.min(failures, 10)) * (0.5 + Math.random() / 2);
/** A server-provided resume time, sanity-checked: never in the past, never more than a day away. */
function pauseUntil(resetAt: string | undefined, fallbackMs: number): number {
  const at = resetAt ? Date.parse(resetAt) : Number.NaN;
  const now = Date.now();
  return Number.isFinite(at) && at > now ? Math.min(at, now + 24 * 60 * 60_000) : now + fallbackMs;
}

/**
 * The LLM check after the config layers. A managed lock wins over --llm and BEAM_LLM_* as well,
 * and a lock to "beam" (the workspace's setting, no personal keys) can't be bypassed by any of them.
 */
function llmFrom(resolved: ResolvedSettings, flag: string | undefined, log?: (message: string) => void): OwnLlmConfig | null {
  if (!resolved.locked.has("llm")) return ownLlmConfig(process.env, flag, resolved.settings.llm);
  if (flag && log) log(`Your organization's managed config sets the LLM check; --llm ${flag} doesn't apply.`);
  if (resolved.settings.llm.provider === "beam") return null;
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^BEAM_LLM_(?:PROVIDER|MODEL|BASE_URL)$/.test(k)));
  return ownLlmConfig(env, undefined, resolved.settings.llm);
}

/** Points at a key that's already here when no provider was chosen; it is never used without --llm. */
function llmKeyHint(own: OwnLlmConfig | null): string {
  if (own) return "";
  const [found] = detectedLlmKeys();
  return found ? ` ${found.variable} is set here: add --llm ${found.provider} to review findings with your own key instead (Beam never sees it).` : "";
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

export async function runMonitor(options: MonitorOptions, log: (message: string) => void = m => console.error(`[beam monitor] ${m}`)): Promise<void> {
  const resolved = await resolveMonitorSettings({ configPath: options.config });
  const saved = resolved.settings;
  if (resolved.created) log(`Created ${monitorConfigPath()} for App monitoring settings. Edit it, or run 'beam monitor configure'.`);
  for (const warning of resolved.warnings) log(`⚠ ${warning}`);
  // Sources on the command line replace the config's; with none, the config says what to watch.
  // Sources locked by the managed config can't be replaced.
  const sourcesLocked = resolved.locked.has("files") || resolved.locked.has("app");
  if (sourcesLocked && (options.files?.length || options.app)) log("Your organization's managed config sets what this server watches; --file and --app don't apply.");
  const fromCli = !sourcesLocked && Boolean(options.files?.length || options.stdin || options.app);
  const files = (fromCli ? options.files ?? [] : saved.files).map(f => resolve(f));
  const app = fromCli ? options.app : saved.app ?? undefined;
  const appDir = app ? resolve(app) : undefined;
  if (!files.length && !options.stdin && !appDir)
    throw new Error(`Tell beam monitor what to watch: --file <path> (repeatable) for log files, --stdin to read piped output, and/or --app <dir> for dependency checks. Or save them with 'beam monitor configure --file <path>' (${monitorConfigPath()}).`);
  // Settings first, so a misconfiguration is reported before anything else.
  const ownLlm = llmFrom(resolved, options.llm, log);
  const identity = await monitorAuth();
  if (!identity) throw new Error("Set BEAM_APP_TOKEN to the app's token from App monitoring > Settings, apps and alerts in the dashboard, or connect this machine with 'beam connect'.");
  const custom = (await readPolicy())?.rules.customDetectors ?? [];
  const denySettings = pauseFrom(resolved, options, log);
  const denyLists = new DenyListWriter(denySettings, log);
  // Who the finding being raised is about: only an address the client couldn't have written.
  let who: { ip?: string } | null = null;
  let pausesUnsupported = false;
  let pauseNotice = "";
  const book = new PauseBook({
    onNotice: (message, kind) => {
      log(`⚠ ${message}`);
      if (kind === "breaker")
        pipeline?.addFinding({
          id: `pause-breaker-${Math.floor(Date.now() / 1_800_000)}`, ruleId: "beam.pause.breaker", title: "Automatic pausing stopped: too many senders at once",
          severity: "high", category: "activity", source: "http", count: 1, firstSeen: new Date().toISOString(), evidence: message,
        });
    },
  });
  // Without a deny list nothing here can refuse a request, so an "auto" workspace gets a dry run from this server.
  const configurePauses = (next: MonitorConfig | null) => {
    const pausing = next?.pausing;
    const mode = pausing?.mode === "auto" && !denyLists.enabled ? "dry_run" : pausing?.mode;
    book.configure(pausing ? { ...pausing, mode } : null, next?.pauses ?? [], next?.lifted ?? []);
    const notice = pausing?.mode === "auto" && !denyLists.enabled
      ? "Pausing is on in the dashboard, but this server has no deny list, so it only reports what it would pause. Add --deny-file <path> (and --reload \"nginx -s reload\") to enforce it."
      : pausing && pausing.mode !== "off" && denyLists.enabled ? `Pausing: ${pausing.mode === "auto" ? "on" : "dry run"}. Paused addresses go to ${[denySettings.denyFile, denySettings.authDenyFile, denySettings.llmDenyFile].filter(Boolean).join(", ")}.` : "";
    if (notice && notice !== pauseNotice) log(notice);
    pauseNotice = notice;
    void denyLists.update(book.active());
  };
  let pipeline: MonitorPipeline | undefined;

  let config: MonitorConfig | null = null;
  let lastRefresh = 0;
  let pausedUntil = 0;
  let offNotice = false;
  // A rejected token or a missing API while running pauses capture and is checked again every 15
  // minutes, rather than exiting: during an AgentBeam incident those can be transient.
  let rejected = false;
  let fatal: Error | null = null;

  const refresh = async (startup = false): Promise<void> => {
    lastRefresh = Date.now();
    const result = await fetchMonitorConfig(identity);
    if (result.ok) {
      if (!config) {
        log(`App monitoring is on${result.config.app ? ` for ${result.config.app}` : ""} (${result.config.level} level). Findings go to your workspace${result.config.webhooks ? ` and ${result.config.webhooks} webhook${result.config.webhooks === 1 ? "" : "s"}` : ""}.`);
        log(ownLlm
          ? `LLM checks: ${describeOwnLlm(ownLlm)}. Only redacted excerpts go there, and the key never leaves this server.`
          : `LLM checks: ${result.config.llm ? "Beam's model (set in the dashboard)" : "off"}.${llmKeyHint(ownLlm)}`);
      }
      else if (config.level !== result.config.level) log(`Level changed to ${result.config.level}.`);
      if (rejected) log("AgentBeam accepted this server again. Capture resumed.");
      config = result.config;
      offNotice = false;
      rejected = false;
      configurePauses(config);
      return;
    }
    if (result.status === "disabled") {
      if (!offNotice) log(`${result.message}${options.wait === false ? "" : " Nothing is captured until then; checking again every minute."}`);
      offNotice = true;
      config = null;
      configurePauses(null);
      return;
    }
    if (result.status === "revoked" || result.status === "unsupported") {
      if (startup) throw new Error(result.message);
      if (!rejected) log(`${result.message} Capture paused; checking again every 15 minutes.`);
      rejected = true;
      config = null;
      return;
    }
    log(`${result.message} Retrying.`); // unreachable: keep the last known settings
  };

  await refresh(true);
  while (!config) {
    if (options.wait === false) throw new Error("App monitoring is not on for this workspace.");
    await sleep(60_000);
    await refresh(true);
  }

  const maxCpu = Math.min(100, Math.max(1, Number(resolved.locked.has("maxCpuPercent") ? saved.maxCpuPercent : options.maxCpu ?? saved.maxCpuPercent) || 25));
  if (options.stack !== undefined && !isStack(options.stack))
    throw new Error(`--stack must be one of: ${STACKS.join(", ")}.`);
  const stack = isStack(options.stack) ? options.stack : appDir ? detectStack(appDir) ?? undefined : undefined;
  if (stack) log(`Stack: ${stack}${options.stack ? "" : ` (detected from ${appDir})`}. Attacks on other frameworks are rolled up.`);
  const monitorPipeline = new MonitorPipeline({
    stack,
    level: () => (config && Date.now() >= pausedUntil ? config.level : null),
    customDetectors: () => custom,
    cpuBudgetMsPerMinute: 600 * maxCpu, // 1% of a core = 600 ms per minute
    onRaise: finding => {
      if (who && book.consider(finding, who)) void denyLists.update(book.active());
    },
  });
  pipeline = monitorPipeline;
  const ingest = (line: string, file: string) => {
    who = { ip: trustedLineIp(line) };
    try { monitorPipeline.ingestLine(line, file); } finally { who = null; }
  };
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
      pausedUntil = pauseUntil(result.resetAt, 60 * 60_000);
      log(`${result.message} Capture paused until then.`);
      return "drop";
    }
    if (result.status === "revoked" || result.status === "unsupported") {
      if (!rejected) log(`${result.message} Capture paused; checking again every 15 minutes.`);
      rejected = true;
      config = null;
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
    for (const v of vulnerabilities) monitorPipeline.addFinding(vulnerabilityFinding(v));
  };

  const tailers = files.map(path => new FileTailer(path, line => ingest(line, path), options.fromStart));
  for (const tailer of tailers) tailer.start();
  if (files.length) log(`Watching ${files.join(", ")}.`);

  // Pauses this server made go to the workspace (the dashboard, and the app's other instances).
  const reportPauses = async () => {
    if (pausesUnsupported || !book.size.reports) return;
    const batch = book.takeReports().slice(-100);
    const result = await sendPauses(identity, batch);
    if (result.ok) return;
    if (result.status === "unsupported") pausesUnsupported = true;
    else if (result.status === "unreachable") book.returnReports(batch);
  };

  // When AgentBeam is unreachable or erroring, sends back off (with jitter, up to 5 minutes) instead
  // of retrying every few seconds; findings wait in a queue capped at 1,000.
  let flushing = false;
  let sendFailures = 0;
  let nextSendAt = 0;
  const flush = async (force = false) => {
    if (flushing || (!force && Date.now() < nextSendAt)) return;
    flushing = true;
    let retry = false;
    try {
      await monitorPipeline.flush(async batch => {
        const outcome = await send(batch);
        retry = outcome === "retry";
        return outcome;
      }, { force });
      await reportPauses();
    } finally {
      flushing = false;
      if (retry) nextSendAt = Date.now() + backoff(++sendFailures);
      else sendFailures = 0;
    }
  };

  // Piped output: the app's lines go straight through (honoring backpressure, as without Beam),
  // and detection works through a bounded backlog in short slices. If detection can't keep up,
  // lines are skipped for detection, never held back from the app's output.
  const MAX_BACKLOG = 10_000;
  const backlog: string[] = [];
  let backlogHead = 0;
  let pipedSkipped = 0;
  let draining = false;
  const drain = () => {
    const until = performance.now() + 20;
    while (backlogHead < backlog.length && performance.now() < until) ingest(backlog[backlogHead++]!, "stdin");
    if (backlogHead > 1000) { backlog.splice(0, backlogHead); backlogHead = 0; }
    if (backlogHead < backlog.length) setImmediate(drain);
    else draining = false;
  };

  const timers = [
    setInterval(() => void flush(), 5_000),
    setInterval(() => {
      const every = config ? 5 * 60_000 : rejected ? 15 * 60_000 : 60_000;
      if (Date.now() - lastRefresh >= every) void refresh().catch(e => { fatal = e as Error; });
    }, 15_000),
    setInterval(() => {
      const skipped = (monitorPipeline.budget?.takeSkipped() ?? 0) + pipedSkipped;
      pipedSkipped = 0;
      if (skipped) log(`Skipped ${skipped} lines in the last minute to stay under ${maxCpu}% of a CPU (--max-cpu).`);
    }, 60_000),
    setInterval(() => void checkDependencies(), 24 * 60 * 60_000),
    // Pauses end on their own: the lists drop them as they expire.
    setInterval(() => void denyLists.update(book.active()), 15_000),
  ];
  for (const timer of timers) timer.unref?.();
  void checkDependencies();

  let stdinDone = !options.stdin;
  if (options.stdin) {
    const echo = options.echo !== false;
    if (echo) process.stdout.on("error", () => { /* downstream closed; keep monitoring */ });
    const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
    let paused = false;
    lines.on("line", line => {
      if (echo && !process.stdout.write(`${line}\n`) && !paused) {
        paused = true;
        lines.pause();
        process.stdout.once("drain", () => { paused = false; lines.resume(); });
      }
      if (backlog.length - backlogHead >= MAX_BACKLOG) { pipedSkipped++; return; }
      backlog.push(line);
      if (!draining) { draining = true; setImmediate(drain); }
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
  // What's left of the piped backlog, then a last flush, bounded so a dead network can't hold up shutdown.
  while (backlogHead < backlog.length) ingest(backlog[backlogHead++]!, "stdin");
  let giveUp: NodeJS.Timeout | undefined;
  await Promise.race([flush(true), new Promise(r => { giveUp = setTimeout(r, 5_000); })]);
  clearTimeout(giveUp);
  // A deny list nobody keeps current would refuse those addresses forever.
  if (denyLists.enabled) await denyLists.clear();
  if (fatal) throw fatal;
}

const fmt = (n: number) => (n >= 2_147_483_647 ? "unlimited" : n.toLocaleString("en-US"));
const MODE_LABELS: Record<string, string> = { off: "off", dry_run: "dry run (reports what it would pause)", auto: "on" };

function pausingLine(config: MonitorConfig, resolved: ResolvedSettings | null): string {
  if (!config.pausing) return "not available on this workspace yet";
  const active = (config.pauses ?? []).filter(p => !p.dryRun).length;
  const lists = resolved ? [resolved.settings.pause.denyFile, resolved.settings.pause.authDenyFile, resolved.settings.pause.llmDenyFile].filter(Boolean) : [];
  return `${MODE_LABELS[config.pausing.mode] ?? config.pausing.mode}, ${active} paused now${lists.length ? ` · deny lists ${lists.join(", ")}` : " · this server has no deny list (the SDK enforces in-app)"}`;
}

/** "15m", "2h", "1d" as milliseconds: at least a minute, at most 7 days. */
export function parseDuration(text: string): number | null {
  const m = text.trim().match(/^(\d+)\s*(m|min|h|d)$/i);
  if (!m) return null;
  const ms = Number(m[1]) * ({ m: 60_000, min: 60_000, h: 3_600_000, d: 86_400_000 } as Record<string, number>)[m[2]!.toLowerCase()]!;
  return ms >= 60_000 && ms <= 7 * 86_400_000 ? ms : null;
}

async function pauseAuth(write: (line: string) => void): Promise<MonitorAuth | null> {
  let identity;
  try { identity = await monitorAuth(); } catch (error) { write(`✖ ${(error as Error).message}`); return null; }
  if (!identity) write("✖ Set BEAM_APP_TOKEN to the app's token from App monitoring > Settings, apps and alerts in the dashboard, or connect this machine with 'beam connect'.");
  return identity;
}

/** `beam monitor pause <target>`: pause an address, range or user:<id> for this app, in every mode. */
export async function monitorPause(target: string, options: { for?: string; scope?: string; reason?: string }, write: (line: string) => void = console.log): Promise<number> {
  const normalized = normalizeTarget(target);
  if (!normalized) { write("✖ Give an IPv4 or IPv6 address, a range no wider than /16 (IPv6: /32), or user:<id>."); return 1; }
  const scope = (options.scope ?? "all") as PauseScope;
  if (!PAUSE_SCOPES.includes(scope)) { write(`✖ --scope must be one of ${PAUSE_SCOPES.join(", ")}.`); return 1; }
  const ms = parseDuration(options.for ?? "1h");
  if (!ms) { write("✖ --for takes a duration like 15m, 2h or 1d (up to 7d)."); return 1; }
  const identity = await pauseAuth(write);
  if (!identity) return 1;
  const until = new Date(Date.now() + ms).toISOString();
  const reason = (options.reason?.trim() || "Paused with beam monitor pause").slice(0, 200);
  const result = await sendPauses(identity, [{ target: normalized, scope, until, reason, source: "manual" }]);
  if (!result.ok) { write(`✖ ${result.status === "unsupported" ? "This workspace doesn't support pausing yet." : result.message}`); return 1; }
  if (!result.accepted) { write(`✖ Not paused: ${result.skipped[0]?.reason ?? "the workspace refused it"}.`); return 1; }
  write(`✔ Paused ${normalized}${scope === "all" ? "" : ` from ${scope === "auth" ? "sign-in" : "LLM"} routes`} until ${until.slice(0, 16).replace("T", " ")} UTC.`);
  write("  Apps using the SDK refuse it within 5 minutes; beam monitor with --deny-file writes it to the deny list.");
  return 0;
}

/** `beam monitor unpause <target>`: lift a pause now (it isn't remade automatically for a day). */
export async function monitorUnpause(target: string, options: { scope?: string }, write: (line: string) => void = console.log): Promise<number> {
  const normalized = normalizeTarget(target);
  if (!normalized) { write("✖ Give the address, range or user:<id> that's paused."); return 1; }
  if (options.scope && !PAUSE_SCOPES.includes(options.scope as PauseScope)) { write(`✖ --scope must be one of ${PAUSE_SCOPES.join(", ")}.`); return 1; }
  const identity = await pauseAuth(write);
  if (!identity) return 1;
  const result = await liftPause(identity, normalized, options.scope as PauseScope | undefined);
  if (!result.ok) { write(`✖ ${result.status === "unsupported" ? "This workspace doesn't support pausing yet." : result.message}`); return 1; }
  write(result.lifted ? `✔ Lifted ${result.lifted} pause${result.lifted === 1 ? "" : "s"} on ${normalized}. It won't be paused automatically again for a day.` : `${normalized} wasn't paused.`);
  return 0;
}

/** `beam monitor paused`: the pauses in force for this app, and the dry runs. */
export async function monitorPaused(options: { json?: boolean }, write: (line: string) => void = console.log): Promise<number> {
  const identity = await pauseAuth(write);
  if (!identity) return 1;
  const result = await listPauses(identity);
  if (!result.ok) { write(`✖ ${result.status === "unsupported" ? "This workspace doesn't support pausing yet." : result.message}`); return 1; }
  if (options.json) { write(JSON.stringify(result, null, 2)); return 0; }
  write(`Pausing: ${MODE_LABELS[result.mode] ?? result.mode}`);
  if (!result.pauses.length) { write("Nothing is paused."); return 0; }
  for (const p of result.pauses)
    write(`${p.dryRun ? "would pause" : "paused     "}  ${p.target.padEnd(24)} ${p.scope.padEnd(4)}  until ${p.until.slice(0, 16).replace("T", " ")} UTC  ${p.source === "manual" ? "by a person" : "automatic"}: ${p.reason}`);
  return 0;
}

export async function monitorStatus(write: (line: string) => void = console.log, llm?: string): Promise<number> {
  let identity;
  try { identity = await monitorAuth(); } catch (error) { write((error as Error).message); return 1; }
  if (!identity) { write("Set BEAM_APP_TOKEN to the app's token from App monitoring > Settings, apps and alerts in the dashboard, or connect this machine with 'beam connect'."); return 1; }
  const result = await fetchMonitorConfig(identity);
  if (!result.ok) {
    write(result.status === "disabled" ? `App monitoring: off\n${result.message}` : result.message);
    return result.status === "disabled" ? 0 : 1;
  }
  const { app, level, llm: beamLlm, webhooks, usage, limits, resetAt, settingsUrl } = result.config;
  let own: ReturnType<typeof ownLlmConfig> = null;
  let ownError = "";
  let resolved: ResolvedSettings | null = null;
  try { resolved = await resolveMonitorSettings(); own = llmFrom(resolved, llm); } catch (error) { ownError = (error as Error).message; }
  write([
    "App monitoring: on",
    ...(app ? [`App:            ${app}`] : []),
    `Level:          ${level}`,
    `LLM checks:     ${own ? describeOwnLlm(own) : ownError ? `misconfigured: ${ownError}` : `${beamLlm ? "Beam's model" : "off"}${llmKeyHint(own)}`}`,
    `Webhooks:       ${webhooks}`,
    `Pausing:        ${pausingLine(result.config, resolved)}`,
    `This month:     ${fmt(usage.findings)} / ${fmt(limits.findings)} findings · ${fmt(usage.cveChecks)} / ${fmt(limits.cveChecks)} dependency checks · ${fmt(usage.llmChecks)} / ${fmt(limits.llmChecks)} LLM checks (resets ${resetAt.slice(0, 10)})`,
    `Settings:       ${settingsUrl}`,
    `This server:    ${resolved ? originSummary(resolved) : monitorConfigPath()}`,
  ].join("\n"));
  return 0;
}

/**
 * `beam monitor test`: one test finding through the real path, to prove an integration end to end.
 * With an own LLM (--llm), also one LLM check on a harmless sample, to prove the key works.
 */
export async function monitorTest(write: (line: string) => void = console.log, llm?: string): Promise<number> {
  let identity;
  try { identity = await monitorAuth(); } catch (error) { write(`✖ ${(error as Error).message}`); return 1; }
  if (!identity) { write("✖ Set BEAM_APP_TOKEN to the app's token from App monitoring > Settings, apps and alerts in the dashboard, or connect this machine with 'beam connect'."); return 1; }
  const config = await fetchMonitorConfig(identity);
  if (!config.ok) { write(`✖ ${config.message}`); return 1; }
  const where = config.config.app ?? hostname();
  const now = new Date().toISOString();
  const result = await sendFindings(identity, [{
    id: `test-${createHash("sha256").update(`${where}\0${now}`).digest("hex").slice(0, 16)}`,
    ruleId: "beam.monitor.test", title: "Test finding from beam monitor", severity: "high", category: "integrity",
    source: "log", count: 1, firstSeen: now,
    evidence: `beam monitor test from ${where}. If you can read this on the dashboard and at your webhooks, the integration works. No action is needed.`,
  }]);
  if (!result.ok) { write(`✖ ${result.message}`); return 1; }
  write(`✔ Test finding sent for ${where}. Check the dashboard's App monitoring page${config.config.webhooks ? ` and your ${config.config.webhooks} webhook${config.config.webhooks === 1 ? "" : "s"}` : ""}.`);
  let own: OwnLlmConfig | null;
  try { own = llmFrom(await resolveMonitorSettings(), llm, write); } catch (error) { write(`✖ LLM check: ${(error as Error).message}`); return 1; }
  if (!own) return 0;
  // A harmless sample, judged separately: its verdict isn't attached to the test finding, which must reach the webhooks.
  const sample: MonitorFinding = {
    id: "llm-test", ruleId: "web.sql_injection", title: "SQL injection attempt from 203.0.113.9", severity: "high", category: "exploit",
    source: "http", count: 1, firstSeen: now, evidence: '203.0.113.9 - - "GET /items?id=1 UNION SELECT password FROM users-- HTTP/1.1" 200 "sqlmap/1.8"',
  };
  await judgeWithOwnLlm([sample], "strict", own);
  const verdict = sample.llm;
  if (!verdict || verdict.verdict === "error") { write(`✖ LLM check with ${describeOwnLlm(own)} failed: ${verdict?.reason ?? "no answer"}`); return 1; }
  write(`✔ LLM check works: ${describeOwnLlm(own)} judged a sample attack "${verdict.verdict}".`);
  return 0;
}

const SETTING_LABELS: Record<SettingKey, string> = { files: "log files", app: "app directory", maxCpuPercent: "CPU cap", llm: "LLM check", pause: "deny lists" };
/** Where each setting came from, for status and configure output. */
function originSummary(resolved: ResolvedSettings): string {
  return (Object.keys(SETTING_LABELS) as SettingKey[])
    .map(key => `${SETTING_LABELS[key]} from ${resolved.origins[key]}${resolved.locked.has(key) ? " (locked)" : ""}`)
    .join(", ");
}

export interface ConfigureOptions {
  llm?: string; model?: string; baseUrl?: string; keyEnv?: string; key?: string; forgetKey?: boolean;
  files?: string[]; noFiles?: boolean; app?: string; noApp?: boolean; maxCpu?: number;
  denyFile?: string; authDenyFile?: string; llmDenyFile?: string; denyFormat?: string; reload?: string; noDeny?: boolean;
  /** Validate every config layer and exit 1 on a problem (for CI). */
  check?: boolean;
}

/**
 * `beam monitor configure`: saves settings to the user's monitor.json so `beam monitor` needs no
 * flags. With no options, prints the effective settings and which layer each came from (managed,
 * user, project, default); with --check, validates every layer for CI. A key is only ever stored
 * from stdin (`key`), and a provider's key that isn't set in this shell is a warning, not an
 * error: it may be set only where beam monitor runs (a systemd EnvironmentFile, a container's secrets).
 */
export async function monitorConfigure(options: ConfigureOptions, write: (line: string) => void = console.log): Promise<number> {
  let resolved: ResolvedSettings;
  try {
    resolved = await resolveMonitorSettings();
  } catch (error) {
    write(`✖ ${(error as Error).message}`);
    return 1;
  }
  if (options.check) {
    write(`✔ Monitor config is valid: ${originSummary(resolved)}.`);
    for (const warning of resolved.warnings) write(`⚠ ${warning}`);
    return 0;
  }
  const current = (await ensureMonitorConfig()).config;
  const { check: _check, ...edits } = options;
  const changing = Object.values(edits).some(v => v !== undefined && v !== false);
  if (!changing) {
    const { apiKey, ...llm } = resolved.settings.llm;
    write(JSON.stringify({ ...resolved.settings, llm: { ...llm, ...(apiKey ? { apiKey: "(stored)" } : {}) } }, null, 2));
    write(`\nFrom: ${originSummary(resolved)}.`);
    for (const source of resolved.sources) write(`  ${source.layer.padEnd(8)} ${source.path} (${source.status})`);
    for (const warning of resolved.warnings) write(`⚠ ${warning}`);
    return 0;
  }
  const lockedEdits = (Object.keys(SETTING_LABELS) as SettingKey[]).filter(key => resolved.locked.has(key) && (
    key === "llm" ? Boolean(options.llm || options.model || options.baseUrl || options.keyEnv || options.key)
      : key === "files" ? Boolean(options.files?.length || options.noFiles)
      : key === "app" ? Boolean(options.app || options.noApp)
      : key === "pause" ? Boolean(options.denyFile || options.authDenyFile || options.llmDenyFile || options.denyFormat || options.reload || options.noDeny)
      : options.maxCpu !== undefined));
  if (lockedEdits.length) write(`⚠ Your organization's managed config locks the ${lockedEdits.map(k => SETTING_LABELS[k]).join(" and ")}; saved values for ${lockedEdits.length === 1 ? "it" : "them"} won't apply.`);
  if (options.denyFormat !== undefined && !DENY_FORMATS.includes(options.denyFormat as DenyFormat))
    throw new Error(`--deny-format must be ${DENY_FORMATS.join(" or ")}.`);
  const provider = options.llm?.trim().toLowerCase();
  if (provider && provider !== "beam" && !(provider in LLM_PROVIDERS))
    throw new Error(`Unknown LLM provider "${provider}". Use one of ${Object.keys(LLM_PROVIDERS).join(", ")}, or beam for Beam's model.`);
  const switching = provider !== undefined && provider !== current.llm.provider;
  const next: MonitorFileConfig = {
    ...current,
    files: options.noFiles ? [] : options.files?.length ? options.files.map(f => resolve(f)) : current.files,
    app: options.noApp ? null : options.app ? resolve(options.app) : current.app,
    maxCpuPercent: options.maxCpu ?? current.maxCpuPercent,
    pause: options.noDeny ? { ...DEFAULT_MONITOR_CONFIG.pause } : {
      denyFile: options.denyFile ? resolve(options.denyFile) : current.pause.denyFile,
      authDenyFile: options.authDenyFile ? resolve(options.authDenyFile) : current.pause.authDenyFile,
      llmDenyFile: options.llmDenyFile ? resolve(options.llmDenyFile) : current.pause.llmDenyFile,
      format: (options.denyFormat as DenyFormat | undefined) ?? current.pause.format,
      reload: options.reload ?? current.pause.reload,
    },
    llm: {
      provider: provider ?? current.llm.provider,
      // A new provider starts from its own defaults rather than the old provider's model and endpoint.
      model: options.model ?? (switching ? null : current.llm.model),
      baseUrl: options.baseUrl ?? (switching ? null : current.llm.baseUrl),
      apiKeyEnv: options.keyEnv ?? (switching ? null : current.llm.apiKeyEnv),
      ...(options.key ? { apiKey: options.key } : !options.forgetKey && !switching && current.llm.apiKey ? { apiKey: current.llm.apiKey } : {}),
    },
  };
  await writeMonitorConfig(next);
  write(`Saved ${monitorConfigPath()} (0600).`);
  try {
    const own = ownLlmConfig(process.env, undefined, next.llm);
    write(own ? `LLM checks: ${describeOwnLlm(own)}. The key stays on this server and is never sent to Beam.` : "LLM checks: Beam's model, when an admin turns it on in the dashboard.");
  } catch (error) {
    write(`⚠ ${(error as Error).message} (Saved anyway: that may be set only where beam monitor runs.)`);
  }
  if (next.files.length || next.app) write(`Watches: ${[...next.files, ...(next.app ? [`dependencies in ${next.app}`] : [])].join(", ")}. Start with 'beam monitor'.`);
  const lists = [next.pause.denyFile, next.pause.authDenyFile, next.pause.llmDenyFile].filter(Boolean);
  if (lists.length) write(`Paused senders go to ${lists.join(", ")} (${next.pause.format})${next.pause.reload ? `, then '${next.pause.reload}' runs` : ""}. Pausing itself is turned on in the dashboard.`);
  return 0;
}
