// `beam monitor`: 24x7 watch over a running application's logs and traffic. Lines are matched
// against monitor-rules.ts on this machine; only redacted, deduplicated findings are sent to the
// workspace, which stores them, meters them and delivers them to the workspace's webhooks.
//
// It never blocks or alters the application: it reads log files (or a pipe it echoes straight
// through) and does nothing else to the app. It is also inert until the workspace turns App
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
  checkPackages, fetchMonitorConfig, monitorAuth, sendFindings,
  type MonitorConfig, type MonitorFinding, type MonitorLevel, type MonitorSeverity, type Vulnerability,
} from "./monitor-client.js";
import { LLM_PROVIDERS, describeOwnLlm, detectedLlmKeys, judgeWithOwnLlm, ownLlmConfig, type OwnLlmConfig } from "./monitor-llm.js";
import { ensureMonitorConfig, monitorConfigPath, resolveMonitorSettings, writeMonitorConfig, type MonitorFileConfig, type ResolvedSettings, type SettingKey } from "./monitor-config.js";
import type { CustomDetector } from "./data-detectors.js";

export { BRUTE_FORCE_THRESHOLD, DEDUPE_WINDOW_MS, MAX_NEW_FINDINGS_PER_10_MIN, MonitorPipeline, meetsLevel, type PipelineOptions, type SendOutcome } from "./monitor-pipeline.js";
import { MonitorPipeline, type SendOutcome } from "./monitor-pipeline.js";

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
      return;
    }
    if (result.status === "disabled") {
      if (!offNotice) log(`${result.message}${options.wait === false ? "" : " Nothing is captured until then; checking again every minute."}`);
      offNotice = true;
      config = null;
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
  const pipeline = new MonitorPipeline({
    level: () => (config && Date.now() >= pausedUntil ? config.level : null),
    customDetectors: () => custom,
    cpuBudgetMsPerMinute: 600 * maxCpu, // 1% of a core = 600 ms per minute
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
    for (const v of vulnerabilities) pipeline.addFinding(vulnerabilityFinding(v));
  };

  const tailers = files.map(path => new FileTailer(path, line => pipeline.ingestLine(line, path), options.fromStart));
  for (const tailer of tailers) tailer.start();
  if (files.length) log(`Watching ${files.join(", ")}.`);

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
      await pipeline.flush(async batch => {
        const outcome = await send(batch);
        retry = outcome === "retry";
        return outcome;
      });
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
    while (backlogHead < backlog.length && performance.now() < until) pipeline.ingestLine(backlog[backlogHead++]!, "stdin");
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
      const skipped = (pipeline.budget?.takeSkipped() ?? 0) + pipedSkipped;
      pipedSkipped = 0;
      if (skipped) log(`Skipped ${skipped} lines in the last minute to stay under ${maxCpu}% of a CPU (--max-cpu).`);
    }, 60_000),
    setInterval(() => void checkDependencies(), 24 * 60 * 60_000),
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
  while (backlogHead < backlog.length) pipeline.ingestLine(backlog[backlogHead++]!, "stdin");
  let giveUp: NodeJS.Timeout | undefined;
  await Promise.race([flush(true), new Promise(r => { giveUp = setTimeout(r, 5_000); })]);
  clearTimeout(giveUp);
  if (fatal) throw fatal;
}

const fmt = (n: number) => (n >= 2_147_483_647 ? "unlimited" : n.toLocaleString("en-US"));

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

const SETTING_LABELS: Record<SettingKey, string> = { files: "log files", app: "app directory", maxCpuPercent: "CPU cap", llm: "LLM check" };
/** Where each setting came from, for status and configure output. */
function originSummary(resolved: ResolvedSettings): string {
  return (Object.keys(SETTING_LABELS) as SettingKey[])
    .map(key => `${SETTING_LABELS[key]} from ${resolved.origins[key]}${resolved.locked.has(key) ? " (locked)" : ""}`)
    .join(", ");
}

export interface ConfigureOptions {
  llm?: string; model?: string; baseUrl?: string; keyEnv?: string; key?: string; forgetKey?: boolean;
  files?: string[]; noFiles?: boolean; app?: string; noApp?: boolean; maxCpu?: number;
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
      : options.maxCpu !== undefined));
  if (lockedEdits.length) write(`⚠ Your organization's managed config locks the ${lockedEdits.map(k => SETTING_LABELS[k]).join(" and ")}; saved values for ${lockedEdits.length === 1 ? "it" : "them"} won't apply.`);
  const provider = options.llm?.trim().toLowerCase();
  if (provider && provider !== "beam" && !(provider in LLM_PROVIDERS))
    throw new Error(`Unknown LLM provider "${provider}". Use one of ${Object.keys(LLM_PROVIDERS).join(", ")}, or beam for Beam's model.`);
  const switching = provider !== undefined && provider !== current.llm.provider;
  const next: MonitorFileConfig = {
    ...current,
    files: options.noFiles ? [] : options.files?.length ? options.files.map(f => resolve(f)) : current.files,
    app: options.noApp ? null : options.app ? resolve(options.app) : current.app,
    maxCpuPercent: options.maxCpu ?? current.maxCpuPercent,
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
  return 0;
}
