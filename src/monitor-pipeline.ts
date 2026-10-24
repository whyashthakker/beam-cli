// The detection pipeline shared by `beam monitor` and the in-app SDK: rule matching, level filter,
// grouping and deduplication, flood control and batching. Pure TypeScript with no Node.js
// built-ins, so it also runs in edge runtimes (Next.js middleware).
import type { MonitorFinding, MonitorLevel, MonitorRollup, MonitorSeverity } from "./monitor-client.js";
import type { CustomDetector } from "./data-detectors.js";
import {
  clientIp, isAuthFailure, isAuthSuccess, isLlmRequest, lineSource, logUser, matchLine, privilegeChange, quickRequest, redactLine, requestMeta,
  requestOutcome, routeKey, tokenUsage, type LineSource, type MonitorRule,
} from "./monitor-rules.js";
import { DistinctPerMinute, MinuteSeries, SIGNAL_THRESHOLDS, meaningfulPath, outboundHost } from "./monitor-signals.js";

/** A short, stable fingerprint (two seeded 53-bit hashes); not cryptographic, only used for dedupe ids. */
export function fingerprint(text: string): string {
  const h = (seed: number) => {
    let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
    for (let i = 0; i < text.length; i++) {
      const ch = text.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(14, "0");
  };
  return `${h(1)}${h(2)}`.slice(0, 24);
}

const RANK: Record<MonitorSeverity, number> = { critical: 3, high: 2, medium: 1, low: 0 };
const MIN_RANK: Record<MonitorLevel, number> = { light: 3, standard: 2, strict: 1 };
/** light: critical only · standard: high and up · strict: medium and up (same thresholds as the server). */
export const meetsLevel = (severity: MonitorSeverity, level: MonitorLevel) => RANK[severity] >= MIN_RANK[level];

// One finding absorbs repeats (its `count` goes up) for this long before a new one is raised.
export const DEDUPE_WINDOW_MS: Record<MonitorLevel, number> = { light: 60 * 60_000, standard: 15 * 60_000, strict: 5 * 60_000 };
// Failed sign-ins from one address within five minutes before it counts as brute forcing.
export const BRUTE_FORCE_THRESHOLD: Record<MonitorLevel, number> = { light: 50, standard: 20, strict: 10 };
const BRUTE_FORCE_WINDOW_MS = 5 * 60_000;
// Paid model calls from one sender within five minutes before it counts as abuse: scripted use
// that runs up the app's LLM bill ("denial of wallet") or scrapes the model through the app.
export const LLM_FLOOD_THRESHOLD: Record<MonitorLevel, number> = { light: 1500, standard: 300, strict: 120 };
const LLM_FLOOD_WINDOW_MS = 5 * 60_000;
// A scan or a log loop can match thousands of distinct lines; past this many new findings in ten
// minutes the rest are folded into one summary finding so a flood can't spend the month's allowance.
export const MAX_NEW_FINDINGS_PER_10_MIN = 200;
const FLOOD_WINDOW_MS = 10 * 60_000;
const MAX_QUEUE = 1000;
const BATCH_SIZE = 100;
// Attacks that were refused or can't work here are rolled up per rule and sent this often.
export const ROLLUP_EVERY_MS = 5 * 60_000;
const ROLLUP_LIMITS = { addresses: 10_000, clients: 2000, paths: 500, userAgents: 300, countries: 250 };
const ROLLUP_TOP = { clients: 25, paths: 10, userAgents: 10, countries: 10 };

type FindingRequest = NonNullable<MonitorFinding["request"]>;
interface OpenRollup {
  ruleId: string; title: string; category: string; file?: string; outcome: MonitorRollup["outcome"];
  started: number; last: number; requests: number; excerpt: string;
  addresses: Set<string>; statuses: Map<string, number>;
  clients: Map<string, MonitorRollup["clients"][number]>;
  paths: Map<string, number>; userAgents: Map<string, number>; countries: Map<string, number>;
}
/** Adds one to `key`, keeping at most `max` keys (new keys past it aren't tracked). */
function bump(map: Map<string, number>, key: string | undefined, max: number): void {
  if (!key) return;
  const n = map.get(key);
  if (n !== undefined) map.set(key, n + 1);
  else if (map.size < max) map.set(key, 1);
}
const top = (map: Map<string, number>, n: number) => [...map].sort((a, b) => b[1] - a[1]).slice(0, n);
const OUTCOME_TITLE: Record<MonitorRollup["outcome"], string> = { blocked: "refused by the app", not_applicable: "aimed at software this app doesn't run" };

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

export interface IngestOptions {
  /** What the text is. Default: worked out from the line (an access-log line or an app log line). */
  source?: LineSource;
  /** Who sent it (client address or user id): groups repeats and counts floods. Default: the line's client address. */
  client?: string;
  /** Rules for this text only, like the SDK's canary check. */
  rules?: MonitorRule[];
  /** False sends the rule, count and sender without the text excerpt. */
  excerpt?: boolean;
}

export interface PipelineOptions {
  /** The active level, or null while capture is off (not enabled, or the allowance is spent). */
  level: () => MonitorLevel | null;
  customDetectors?: () => CustomDetector[];
  now?: () => number;
  /** Detection time allowed per minute; past it, lines are skipped (and counted) until the next minute. */
  cpuBudgetMsPerMinute?: number;
  /** Or a budget shared with other work (the SDK's prompt and output checks). */
  budget?: CpuBudget;
  /** LLM tokens one user may use in an hour before it's raised. Default: SIGNAL_THRESHOLDS.tokensPerHour for the level. */
  tokensPerUserHour?: number;
  /**
   * The app is JavaScript (the SDK): a request for a PHP, WordPress, ASP or Java path can't reach
   * code that would run it, so it's rolled up like a refused one even without a response status.
   */
  javascriptApp?: boolean;
}

const clock = () => (globalThis.performance?.now?.() ?? Date.now());

/**
 * A hard cap on detection time per minute, so monitoring can never take more than a fixed share of
 * a CPU, whatever the traffic or input. Work over the cap is skipped and counted, not queued.
 */
export class CpuBudget {
  private minute = -1;
  private spent = 0;
  private skippedSince = 0;
  constructor(private readonly msPerMinute: number) {}
  /** Runs `work` if this minute's budget isn't spent; otherwise skips it and returns undefined. */
  run<T>(work: () => T): T | undefined {
    const minute = Math.floor(Date.now() / 60_000);
    if (minute !== this.minute) { this.minute = minute; this.spent = 0; }
    if (this.spent >= this.msPerMinute) { this.skippedSince++; return undefined; }
    const start = clock();
    try { return work(); } finally { this.spent += clock() - start; }
  }
  /** How many were skipped since the last call (for a diagnostic). */
  takeSkipped(): number { const n = this.skippedSince; this.skippedSince = 0; return n; }
}

/**
 * Events per key over the last few minutes, in one-minute buckets: a fixed few numbers per key
 * however busy the key is, and at most `maxKeys` keys (the least recently active go first).
 */
export class WindowCounter {
  private keys = new Map<string, { minutes: number[]; counts: number[] }>();
  constructor(private readonly windowMinutes: number, private readonly maxKeys = 10_000) {}
  get size(): number { return this.keys.size; }
  /** Records one event and returns the count over the window, this one included. */
  add(key: string, now: number): number {
    const minute = Math.floor(now / 60_000);
    let entry = this.keys.get(key);
    if (entry) this.keys.delete(key); // re-inserted below: Map order is then least recently active first
    else entry = { minutes: new Array<number>(this.windowMinutes).fill(-1), counts: new Array<number>(this.windowMinutes).fill(0) };
    const slot = minute % this.windowMinutes;
    if (entry.minutes[slot] !== minute) { entry.minutes[slot] = minute; entry.counts[slot] = 0; }
    entry.counts[slot]!++;
    this.keys.set(key, entry);
    if (this.keys.size > this.maxKeys) this.keys.delete(this.keys.keys().next().value!);
    let total = 0;
    for (let i = 0; i < this.windowMinutes; i++) if (minute - entry.minutes[i]! < this.windowMinutes) total += entry.counts[i]!;
    return total;
  }
  /** The count over the window, without recording anything. */
  peek(key: string, now: number): number {
    const entry = this.keys.get(key);
    if (!entry) return 0;
    const minute = Math.floor(now / 60_000);
    let total = 0;
    for (let i = 0; i < this.windowMinutes; i++) if (minute - entry.minutes[i]! < this.windowMinutes) total += entry.counts[i]!;
    return total;
  }
  clear(key: string): void { this.keys.delete(key); }
  /** Drops keys with nothing in the window. */
  prune(now: number): void {
    const minute = Math.floor(now / 60_000);
    for (const [key, entry] of this.keys) if (Math.max(...entry.minutes) <= minute - this.windowMinutes) this.keys.delete(key);
  }
}

export class MonitorPipeline {
  private seen = new Map<string, { bucket: number; finding: MonitorFinding; at: number }>();
  private queue: MonitorFinding[] = [];
  private queued = new Set<string>();
  private authFailures = new WindowCounter(BRUTE_FORCE_WINDOW_MS / 60_000);
  private llmCalls = new WindowCounter(LLM_FLOOD_WINDOW_MS / 60_000);
  private floodBucket = -1;
  private floodCount = 0;
  private suppressed: { count: number; severity: MonitorSeverity } | null = null;
  private rollups = new Map<string, OpenRollup>();
  // Attack-in-progress signals (monitor-signals.ts).
  private misses = new MinuteSeries(10, 5000);
  private errors = new MinuteSeries(35, 1000);
  private walks = new DistinctPerMinute(SIGNAL_THRESHOLDS.pathWalk.light, 2000);
  private loginFailures = new WindowCounter(15, 10_000);
  private tokens = new MinuteSeries(60, 5000);
  private knownHosts = new Set<string>();
  private reportedHosts = new Set<string>();
  private maintainedMinute = -1;
  readonly budget: CpuBudget | null;

  constructor(private readonly opts: PipelineOptions) {
    this.budget = opts.budget ?? (opts.cpuBudgetMsPerMinute ? new CpuBudget(opts.cpuBudgetMsPerMinute) : null);
  }

  private now(): number { return this.opts.now?.() ?? Date.now(); }

  get pending(): MonitorFinding[] { return [...this.queue]; }
  /** Roll-ups still collecting; a forced flush sends them early. */
  get rollingUp(): number { return this.rollups.size; }

  /** Sizes of everything the pipeline keeps, for tests and diagnostics: all of them are bounded. */
  get footprint(): Record<"seen" | "queue" | "queued" | "authFailures" | "llmCalls" | "rollups" | "misses" | "errors" | "walks" | "loginFailures" | "tokens" | "hosts", number> {
    return {
      seen: this.seen.size, queue: this.queue.length, queued: this.queued.size, authFailures: this.authFailures.size, llmCalls: this.llmCalls.size,
      rollups: this.rollups.size, misses: this.misses.size, errors: this.errors.size, walks: this.walks.size, loginFailures: this.loginFailures.size,
      tokens: this.tokens.size, hosts: this.knownHosts.size + this.reportedHosts.size,
    };
  }

  /** Once a minute: forget dedupe entries and counters that can no longer matter. */
  private maintain(now: number): void {
    const minute = Math.floor(now / 60_000);
    if (minute === this.maintainedMinute) return;
    this.maintainedMinute = minute;
    const cutoff = now - 2 * DEDUPE_WINDOW_MS.light;
    for (const [fp, entry] of this.seen) if (entry.at < cutoff) this.seen.delete(fp);
    this.authFailures.prune(now);
    this.llmCalls.prune(now);
    this.misses.prune(now);
    this.errors.prune(now);
    this.walks.prune(now);
    this.loginFailures.prune(now);
    this.tokens.prune(now);
    if (this.queued.size > 5000) this.queued.clear(); // dependency ids; a repeat is deduped by the server too
    this.emitRollups(now, false);
  }

  /**
   * Matches one line and queues any findings at or above the level. Returns the rule ids raised.
   * Over the CPU budget, the line is skipped (see budget.takeSkipped()).
   */
  ingestLine(line: string, file?: string, options: IngestOptions = {}): string[] {
    if (!this.budget) return this.ingest(line, file, options);
    return this.budget.run(() => this.ingest(line, file, options)) ?? [];
  }

  private ingest(line: string, file: string | undefined, options: IngestOptions): string[] {
    const level = this.opts.level();
    if (!level || !line.trim()) return [];
    const custom = this.opts.customDetectors?.() ?? [];
    const source = options.source ?? lineSource(line);
    // Prompts and model output travel as "log" findings, which every workspace version accepts.
    const wire = source === "http" ? "http" : "log";
    const ip = options.client ? redactLine(options.client, custom).slice(0, 80) : source === "http" ? clientIp(line) : undefined;
    this.maintain(this.now());
    const excerpt = options.excerpt === false ? "(the app withheld the text)" : redactLine(line, custom);
    const request = source === "http" ? this.describeRequest(line, ip, custom, options.excerpt !== false) : undefined;
    const raised: string[] = [];
    const seenRules = new Set<string>();
    for (const rule of matchLine(line, source, options.rules)) {
      if (seenRules.has(rule.id)) continue;
      // Refused, or aimed at software that isn't here: rolled up whatever the level, as context
      // for the dashboard, never one finding (or alert) per address.
      if (request && (request.outcome === "blocked" || request.outcome === "not_applicable")) {
        seenRules.add(rule.id);
        this.rollUp(rule, request.outcome, request, file, excerpt);
        raised.push(rule.id);
        continue;
      }
      if (!meetsLevel(rule.severity, level)) continue;
      seenRules.add(rule.id);
      // Traffic groups by client address (one scan = one finding); app logs group by line shape.
      this.raise(level, ip ?? normalizeForGrouping(line), {
        ruleId: rule.id, title: ip ? `${rule.title} from ${ip}` : rule.title, severity: rule.severity,
        category: rule.category, source: wire, file, evidence: options.excerpt === false ? `Matched "${rule.title}"; the app withheld the text.` : excerpt,
        ...(request ? { request } : {}),
      });
      raised.push(rule.id);
    }
    if (isAuthFailure(line, source) && meetsLevel("high", level)) {
      const key = clientIp(line) ?? "unknown address";
      const recent = this.authFailures.add(key, this.now());
      if (recent >= BRUTE_FORCE_THRESHOLD[level]) {
        this.raise(level, key, {
          ruleId: "app.auth_bruteforce", title: `Repeated failed sign-ins from ${key}`, severity: "high", category: "recon",
          source: wire, file, evidence: `${recent} failures in 5 minutes. Latest: ${redactLine(line, custom)}`.slice(0, 600),
          ...(request ? { request } : {}),
        });
        raised.push("app.auth_bruteforce");
      }
    }
    // Only a known sender counts: behind a proxy that hides addresses, all traffic would look like one client.
    if (ip && meetsLevel("high", level) && (source === "prompt" || (source === "http" && isLlmRequest(line)))) {
      const recent = this.llmCalls.add(`${source}\0${ip}`, this.now());
      if (recent >= LLM_FLOOD_THRESHOLD[level]) {
        this.raise(level, ip, {
          ruleId: "llm.denial_of_wallet", title: `Unusual volume of LLM requests from ${ip}`, severity: "high", category: "llm",
          source: wire, file, evidence: `${recent} ${source === "prompt" ? "prompts" : "requests to LLM endpoints"} in 5 minutes. Scripted use runs up the model bill. Latest: ${excerpt}`.slice(0, 600),
          ...(request ? { request } : {}),
        });
        raised.push("llm.denial_of_wallet");
      }
    }
    if (source === "http" || source === "log") raised.push(...this.signals(line, source, wire, file, ip, request, level, custom, excerpt));
    return raised;
  }

  /** The attack-in-progress signals for one traffic or log line. Returns the rule ids raised. */
  private signals(
    line: string, source: LineSource, wire: "http" | "log", file: string | undefined, ip: string | undefined,
    request: FindingRequest | undefined, level: MonitorLevel, custom: CustomDetector[], excerpt: string,
  ): string[] {
    const now = this.now();
    const out: string[] = [];
    const high = meetsLevel("high", level);
    const base = { source: wire, file, ...(request ? { request } : {}) } as const;
    if (source === "http" && request) {
      const path = request.path ?? quickRequest(line).path;
      const status = request.status;
      // A scan finding something: an address with a run of 4xx gets a 2xx on a real page.
      if (ip && status !== undefined) {
        if (status >= 400 && status < 500) this.misses.add(ip, now);
        else if (status >= 200 && status < 300 && path && meaningfulPath(path)) {
          const misses = this.misses.sum(ip, now, 0, 9);
          if (high && misses >= SIGNAL_THRESHOLDS.probeMisses[level]) {
            const route = routeKey(redactLine(path, custom));
            this.raise(level, ip, {
              ruleId: "signal.probe_hit", title: `Scan from ${ip} found a live path`, severity: "high", category: "activity", ...base,
              evidence: `${ip} got ${misses} 4xx answers in 10 minutes, then ${status} on ${route}. Latest: ${excerpt}`.slice(0, 600),
            });
            out.push("signal.probe_hit");
          }
        }
      }
      // A jump in server errors on one route, against its own last half hour.
      if (status !== undefined && status >= 500 && path) {
        const route = routeKey(redactLine(path, custom));
        this.errors.add(route, now);
        const recent = this.errors.sum(route, now, 0, 4);
        const usual = this.errors.sum(route, now, 5, 34) / 6;
        if (high && recent >= SIGNAL_THRESHOLDS.errorSpike[level] && recent >= 5 * Math.max(1, usual)) {
          this.raise(level, route, {
            ruleId: "signal.error_spike", title: `Server errors jumped on ${route}`, severity: "high", category: "activity", ...base,
            evidence: `${recent} 5xx answers on ${route} in 5 minutes, against about ${Math.round(usual)} per 5 minutes before. Latest: ${excerpt}`.slice(0, 600),
          });
          out.push("signal.error_spike");
        }
      }
      // One address walking the app: many distinct paths in a minute.
      if (ip && path) {
        const distinct = this.walks.add(ip, path.split(/[?#]/)[0]!, now);
        if (high && distinct >= SIGNAL_THRESHOLDS.pathWalk[level]) {
          this.raise(level, ip, {
            ruleId: "signal.path_walk", title: `${ip} is walking the app's paths`, severity: "high", category: "activity", ...base,
            evidence: `${distinct}+ different paths from ${ip} within a minute: a scanner or scraper mapping the app. Latest: ${excerpt}`.slice(0, 600),
          });
          out.push("signal.path_walk");
        }
      }
    }
    // A sign-in that succeeds right after a run of failures, by address or by user.
    const who = [source === "http" ? ip : clientIp(line), logUser(line)];
    const keys = [who[0] ? `ip:${who[0]}` : null, who[1] ? `user:${who[1]}` : null].filter((k): k is string => Boolean(k));
    if (keys.length && isAuthFailure(line, source)) for (const key of keys) this.loginFailures.add(key, now);
    else if (keys.length && isAuthSuccess(line, source)) out.push(...this.loginSucceeded(level, keys, who[0], wire, file, request, excerpt));
    // A role or permission granted, or a new API key.
    const change = privilegeChange(line, source);
    if (change) out.push(...this.privilegeChanged(level, change, ip ?? normalizeForGrouping(line), wire, file, request, excerpt));
    // LLM token usage the app logs, per user.
    const usage = source === "log" ? tokenUsage(line) : null;
    if (usage) out.push(...this.noteTokens(level, usage.user ?? who[0] ?? "unknown", usage.tokens, wire, file, excerpt, custom));
    return out;
  }

  private loginSucceeded(
    level: MonitorLevel, keys: string[], ip: string | undefined, wire: "http" | "log", file: string | undefined,
    request: FindingRequest | undefined, excerpt: string,
  ): string[] {
    const now = this.now();
    const failures = Math.max(...keys.map(k => this.loginFailures.peek(k, now)));
    for (const key of keys) this.loginFailures.clear(key);
    if (failures < SIGNAL_THRESHOLDS.loginAfterFailures[level]) return [];
    this.raise(level, keys[0]!, {
      ruleId: "signal.login_after_failures", title: `Sign-in succeeded after ${failures} failed attempts${ip ? ` from ${ip}` : ""}`,
      severity: "critical", category: "activity", source: wire, file, ...(request ? { request } : {}),
      evidence: `${failures} failed sign-ins in 15 minutes, then a successful one: a guessed or stuffed password, possibly. Latest: ${excerpt}`.slice(0, 600),
    });
    return ["signal.login_after_failures"];
  }

  private privilegeChanged(
    level: MonitorLevel, change: "admin" | "key", groupKey: string, wire: "http" | "log", file: string | undefined,
    request: FindingRequest | undefined, excerpt: string,
  ): string[] {
    const severity: MonitorSeverity = change === "admin" ? "high" : "medium";
    if (!meetsLevel(severity, level)) return [];
    this.raise(level, `${change}\0${groupKey}`, {
      ruleId: "signal.privilege_change", title: change === "admin" ? "Admin or role granted" : "New API key or access token created",
      severity, category: "activity", source: wire, file, ...(request ? { request } : {}),
      evidence: `${change === "admin" ? "Someone was given admin rights or a new role." : "A new API key or access token was created."} Latest: ${excerpt}`.slice(0, 600),
    });
    return ["signal.privilege_change"];
  }

  private noteTokens(level: MonitorLevel, user: string, tokens: number, wire: "http" | "log", file: string | undefined, excerpt: string, custom: CustomDetector[]): string[] {
    const now = this.now();
    this.tokens.add(user, now, tokens);
    const total = this.tokens.sum(user, now, 0, 59);
    const limit = this.opts.tokensPerUserHour ?? SIGNAL_THRESHOLDS.tokensPerHour[level];
    if (!meetsLevel("high", level) || total < limit) return [];
    const shown = redactLine(user, custom).slice(0, 80);
    this.raise(level, user, {
      ruleId: "llm.token_spend", title: `Unusual LLM spend: ${Math.round(total).toLocaleString("en-US")} tokens in an hour for ${shown}`,
      severity: "high", category: "llm", source: wire, file,
      evidence: `${Math.round(total).toLocaleString("en-US")} tokens in the last hour for ${shown} (limit ${limit.toLocaleString("en-US")}). Scripted use or a runaway loop runs up the bill. Latest: ${excerpt}`.slice(0, 600),
    });
    return ["llm.token_spend"];
  }

  /**
   * Structured security events from the app (the SDK's event() and usage()), checked like the log
   * lines that say the same thing.
   */
  event(type: "login.failed" | "login.succeeded" | "admin.granted" | "apikey.created", who: { ip?: string; user?: string }, detail = ""): string[] {
    const level = this.opts.level();
    if (!level) return [];
    const run = () => {
      this.maintain(this.now());
      const custom = this.opts.customDetectors?.() ?? [];
      const ip = who.ip ? redactLine(who.ip, custom).slice(0, 80) : undefined;
      const keys = [who.ip ? `ip:${who.ip}` : null, who.user ? `user:${who.user}` : null].filter((k): k is string => Boolean(k));
      const excerpt = redactLine(`${type}${ip ? ` ip=${ip}` : ""}${who.user ? ` user=${who.user}` : ""}${detail ? ` ${detail}` : ""}`, custom);
      if (type === "login.failed") { for (const key of keys) this.loginFailures.add(key, this.now()); return []; }
      if (type === "login.succeeded") return keys.length ? this.loginSucceeded(level, keys, ip, "log", "security events", undefined, excerpt) : [];
      return this.privilegeChanged(level, type === "admin.granted" ? "admin" : "key", keys[1] ?? keys[0] ?? excerpt, "log", "security events", undefined, excerpt);
    };
    return (this.budget ? this.budget.run(run) : run()) ?? [];
  }

  /** LLM tokens used by one user (or address), as reported by the app. */
  usage(user: string, tokens: number, detail = ""): string[] {
    const level = this.opts.level();
    if (!level || !(tokens > 0) || !user) return [];
    this.maintain(this.now());
    const custom = this.opts.customDetectors?.() ?? [];
    return this.noteTokens(level, user, tokens, "log", "llm usage", redactLine(`${tokens} tokens user=${user}${detail ? ` ${detail}` : ""}`, custom), custom);
  }

  /** Hosts the workspace has already seen this app call (from its config), so only new ones are raised. */
  setKnownOutboundHosts(hosts: string[]): void {
    this.knownHosts = new Set(hosts.slice(0, 5000).map(h => outboundHost(h)).filter((h): h is string => Boolean(h)));
  }

  /** The app called this URL or host. Raises the first call to a host the workspace hasn't seen for this app. */
  outbound(target: string): boolean {
    const level = this.opts.level();
    const host = outboundHost(target);
    if (!level || !host || this.knownHosts.has(host) || this.reportedHosts.has(host)) return false;
    if (this.reportedHosts.size >= 2000) return false;
    this.reportedHosts.add(host);
    if (!meetsLevel("high", level)) return false;
    this.maintain(this.now());
    this.raise(level, host, {
      ruleId: "signal.new_outbound_host", title: `First call to ${host}`, severity: "high", category: "activity", source: "log", file: "outbound calls",
      evidence: `The app called ${host}, a host it hasn't called before. New destinations are how stolen data and stolen compute leave a server.`,
      request: { outcome: "unknown", host },
    });
    return true;
  }

  /** The request behind a traffic line, redacted like evidence, with what became of it. */
  private describeRequest(line: string, ip: string | undefined, custom: CustomDetector[], withText: boolean): FindingRequest {
    const meta = requestMeta(line);
    const clip = (s: string | undefined, max: number) => (s === undefined ? undefined : redactLine(s, custom).slice(0, max));
    const request: FindingRequest = {
      outcome: requestOutcome(meta, { javascriptApp: this.opts.javascriptApp }),
      ip, method: meta.method, status: meta.status, bytes: meta.bytes, durationMs: meta.durationMs,
      host: clip(meta.host, 200), country: meta.country, asn: meta.asn, userAgent: clip(meta.userAgent, 300),
      // The path and referrer carry the payload; an app that withholds text withholds them too.
      ...(withText ? { path: clip(meta.path, 500), referer: clip(meta.referer, 300) } : {}),
    };
    for (const key of Object.keys(request) as (keyof FindingRequest)[]) if (request[key] === undefined) delete request[key];
    return request;
  }

  private rollUp(rule: MonitorRule, outcome: MonitorRollup["outcome"], request: FindingRequest, file: string | undefined, excerpt: string): void {
    const now = this.now();
    const key = `${rule.id}\0${outcome}\0${file ?? ""}`;
    let r = this.rollups.get(key);
    if (!r) {
      r = {
        ruleId: rule.id, title: rule.title, category: rule.category, file, outcome, started: now, last: now, requests: 0, excerpt,
        addresses: new Set(), statuses: new Map(), clients: new Map(), paths: new Map(), userAgents: new Map(), countries: new Map(),
      };
      this.rollups.set(key, r);
    }
    r.requests++;
    r.last = now;
    r.excerpt = excerpt;
    const ip = request.ip ?? "unknown";
    if (r.addresses.size < ROLLUP_LIMITS.addresses) r.addresses.add(ip);
    bump(r.statuses, request.status === undefined ? "none" : String(request.status), 100);
    bump(r.paths, request.path, ROLLUP_LIMITS.paths);
    bump(r.userAgents, request.userAgent, ROLLUP_LIMITS.userAgents);
    bump(r.countries, request.country, ROLLUP_LIMITS.countries);
    const client = r.clients.get(ip);
    const latest = { status: request.status, path: request.path, userAgent: request.userAgent, country: request.country, asn: request.asn };
    for (const k of Object.keys(latest) as (keyof typeof latest)[]) if (latest[k] === undefined) delete latest[k];
    if (client) Object.assign(client, latest, { count: client.count + 1 });
    else if (r.clients.size < ROLLUP_LIMITS.clients) r.clients.set(ip, { ip, count: 1, ...latest });
  }

  /** Queues roll-ups that have collected for ROLLUP_EVERY_MS, or all of them when `force`. */
  private emitRollups(now: number, force: boolean): void {
    for (const [key, r] of this.rollups) {
      if (!force && now - r.started < ROLLUP_EVERY_MS) continue;
      this.rollups.delete(key);
      const statuses = Object.fromEntries(r.statuses);
      const answered = Object.entries(statuses).filter(([s]) => s !== "none").sort((a, b) => b[1] - a[1]).map(([s, n]) => `${n} × ${s}`).join(", ");
      const [topPath] = top(r.paths, 1);
      const rollup: MonitorRollup = {
        outcome: r.outcome, requests: r.requests, addresses: r.addresses.size,
        from: new Date(r.started).toISOString(), to: new Date(r.last).toISOString(), statuses,
        clients: [...r.clients.values()].sort((a, b) => b.count - a.count).slice(0, ROLLUP_TOP.clients),
        paths: top(r.paths, ROLLUP_TOP.paths).map(([path, count]) => ({ path, count })),
        userAgents: top(r.userAgents, ROLLUP_TOP.userAgents).map(([userAgent, count]) => ({ userAgent, count })),
        countries: top(r.countries, ROLLUP_TOP.countries).map(([country, count]) => ({ country, count })),
      };
      const plural = (n: number, word: string) => `${n.toLocaleString("en-US")} ${word}${n === 1 ? "" : word.endsWith("s") ? "es" : "s"}`;
      this.enqueue({
        id: `rollup-${fingerprint(key)}-${r.started}`, ruleId: r.ruleId, title: `${r.title}, ${OUTCOME_TITLE[r.outcome]}`,
        severity: "low", category: r.category, source: "http", file: r.file, count: r.requests, firstSeen: rollup.from,
        evidence: [
          `${plural(r.requests, "request")} from ${plural(r.addresses.size, "address")}${answered ? `, answered ${answered}` : ""}.`,
          topPath ? `Most sent: ${topPath[0]} (${topPath[1]}).` : "",
          `Latest: ${r.excerpt}`,
        ].filter(Boolean).join(" ").slice(0, 900),
        rollup,
      });
    }
  }

  /** Queues a finding produced elsewhere (dependency checks) under its own stable id, once. */
  addFinding(finding: MonitorFinding): boolean {
    const level = this.opts.level();
    if (!level || !meetsLevel(finding.severity, level) || this.queued.has(finding.id)) return false;
    this.maintain(this.now());
    this.queued.add(finding.id);
    this.enqueue(finding);
    return true;
  }

  private raise(level: MonitorLevel, groupKey: string, partial: Omit<MonitorFinding, "id" | "count" | "firstSeen">): void {
    const now = this.now();
    const bucket = Math.floor(now / DEDUPE_WINDOW_MS[level]);
    const fp = fingerprint(`${partial.ruleId}\0${groupKey}`);
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

  /**
   * Sends queued findings in batches; a "retry" outcome keeps the batch for the next flush.
   * `force` (shutdown, the SDK's flush({ force })) also sends roll-ups still collecting.
   */
  async flush(send: (batch: MonitorFinding[]) => Promise<SendOutcome>, options: { force?: boolean } = {}): Promise<void> {
    if (this.suppressed && Math.floor(this.now() / FLOOD_WINDOW_MS) !== this.floodBucket) this.emitSuppressed();
    this.emitRollups(this.now(), Boolean(options.force));
    while (this.queue.length) {
      const batch = this.queue.splice(0, BATCH_SIZE);
      if ((await send(batch)) === "retry") {
        this.queue.unshift(...batch);
        break;
      }
    }
    this.maintain(this.now());
  }
}
