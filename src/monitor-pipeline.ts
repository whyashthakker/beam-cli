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
}

export class MonitorPipeline {
  private seen = new Map<string, { bucket: number; finding: MonitorFinding; at: number }>();
  private queue: MonitorFinding[] = [];
  private queued = new Set<string>();
  private authFailures = new Map<string, number[]>();
  private llmCalls = new Map<string, number[]>();
  private floodBucket = -1;
  private floodCount = 0;
  private suppressed: { count: number; severity: MonitorSeverity } | null = null;

  constructor(private readonly opts: PipelineOptions) {}

  private now(): number { return this.opts.now?.() ?? Date.now(); }

  get pending(): MonitorFinding[] { return [...this.queue]; }

  /** Matches one line and queues any findings at or above the level. Returns the rule ids raised. */
  ingestLine(line: string, file?: string, options: IngestOptions = {}): string[] {
    const level = this.opts.level();
    if (!level || !line.trim()) return [];
    const custom = this.opts.customDetectors?.() ?? [];
    const source = options.source ?? lineSource(line);
    // Prompts and model output travel as "log" findings, which every workspace version accepts.
    const wire = source === "http" ? "http" : "log";
    const ip = options.client ? redactLine(options.client, custom).slice(0, 80) : source === "http" ? clientIp(line) : undefined;
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
      const recent = this.recent(this.authFailures, key, BRUTE_FORCE_WINDOW_MS, BRUTE_FORCE_THRESHOLD[level]);
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
      const recent = this.recent(this.llmCalls, `${source}\0${ip}`, LLM_FLOOD_WINDOW_MS, LLM_FLOOD_THRESHOLD[level]);
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

  /** Records one event for `key` and returns how many fell within the window (at most `cap`, all that's needed). */
  private recent(events: Map<string, number[]>, key: string, windowMs: number, cap: number): number {
    const now = this.now();
    const recent = (events.get(key) ?? []).filter(t => now - t < windowMs);
    recent.push(now);
    if (recent.length > cap) recent.splice(0, recent.length - cap);
    events.set(key, recent);
    if (events.size > 10_000) events.delete(events.keys().next().value!);
    return recent.length;
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
    const cutoff = this.now() - 2 * DEDUPE_WINDOW_MS.light;
    for (const [fp, entry] of this.seen) if (entry.at < cutoff) this.seen.delete(fp);
  }
}
