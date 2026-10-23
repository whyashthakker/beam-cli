// The detection pipeline shared by `beam monitor` and the in-app SDK: rule matching, level filter,
// grouping and deduplication, flood control and batching. Pure TypeScript with no Node.js
// built-ins, so it also runs in edge runtimes (Next.js middleware).
import type { MonitorFinding, MonitorLevel, MonitorSeverity } from "./monitor-client.js";
import type { CustomDetector } from "./data-detectors.js";
import { clientIp, isAuthFailure, isLlmRequest, lineSource, matchLine, redactLine, type LineSource, type MonitorRule } from "./monitor-rules.js";

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
  private maintainedMinute = -1;
  readonly budget: CpuBudget | null;

  constructor(private readonly opts: PipelineOptions) {
    this.budget = opts.budget ?? (opts.cpuBudgetMsPerMinute ? new CpuBudget(opts.cpuBudgetMsPerMinute) : null);
  }

  private now(): number { return this.opts.now?.() ?? Date.now(); }

  get pending(): MonitorFinding[] { return [...this.queue]; }

  /** Sizes of everything the pipeline keeps, for tests and diagnostics: all of them are bounded. */
  get footprint(): { seen: number; queue: number; queued: number; authFailures: number; llmCalls: number } {
    return { seen: this.seen.size, queue: this.queue.length, queued: this.queued.size, authFailures: this.authFailures.size, llmCalls: this.llmCalls.size };
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
    if (this.queued.size > 5000) this.queued.clear(); // dependency ids; a repeat is deduped by the server too
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
    const raised: string[] = [];
    const seenRules = new Set<string>();
    for (const rule of matchLine(line, source, options.rules)) {
      if (!meetsLevel(rule.severity, level) || seenRules.has(rule.id)) continue;
      seenRules.add(rule.id);
      // Traffic groups by client address (one scan = one finding); app logs group by line shape.
      this.raise(level, ip ?? normalizeForGrouping(line), {
        ruleId: rule.id, title: ip ? `${rule.title} from ${ip}` : rule.title, severity: rule.severity,
        category: rule.category, source: wire, file, evidence: options.excerpt === false ? `Matched "${rule.title}"; the app withheld the text.` : excerpt,
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
        });
        raised.push("llm.denial_of_wallet");
      }
    }
    return raised;
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
    this.maintain(this.now());
  }
}
