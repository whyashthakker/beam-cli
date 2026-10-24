// Counters behind the attack-in-progress signals (monitor-pipeline.ts): a scan that finds a live
// path, a jump in server errors on one route, one address walking many paths, a sign-in right after
// failures, a first call to a new outbound host, new admins and API keys, and runaway LLM spend per
// user. Pure TypeScript with no Node.js built-ins (the SDK runs in edge runtimes). Every structure
// holds a fixed number of keys and a fixed amount per key, whatever the traffic.
import type { MonitorLevel } from "./monitor-client.js";

export const SIGNAL_THRESHOLDS = {
  /** 4xx answers to one address in 10 minutes before its next 2xx counts as a scan finding something. */
  probeMisses: { light: 60, standard: 30, strict: 15 },
  /** 5xx on one route in 5 minutes (and at least 5× its usual rate) before it counts as a spike. */
  errorSpike: { light: 50, standard: 20, strict: 10 },
  /** Distinct paths from one address in one minute before it counts as walking the app. */
  pathWalk: { light: 250, standard: 100, strict: 50 },
  /** Failed sign-ins (same address or user, 15 minutes) before a success counts as a takeover risk. */
  loginAfterFailures: { light: 20, standard: 10, strict: 5 },
  /** LLM tokens for one user in an hour. */
  tokensPerHour: { light: 2_000_000, standard: 500_000, strict: 200_000 },
} satisfies Record<string, Record<MonitorLevel, number>>;

/**
 * Per-key counts in one-minute slots over the last `minutes`, for sums over any part of that span
 * (the last 5 minutes against the 30 before them). At most `maxKeys` keys; the least recently
 * active go first.
 */
export class MinuteSeries {
  private keys = new Map<string, { minutes: Int32Array; counts: Float64Array }>();
  constructor(private readonly minutes: number, private readonly maxKeys = 2000) {}
  get size(): number { return this.keys.size; }
  add(key: string, now: number, amount = 1): void {
    const minute = Math.floor(now / 60_000);
    let entry = this.keys.get(key);
    if (entry) this.keys.delete(key);
    else entry = { minutes: new Int32Array(this.minutes).fill(-1), counts: new Float64Array(this.minutes) };
    const slot = minute % this.minutes;
    if (entry.minutes[slot] !== minute) { entry.minutes[slot] = minute; entry.counts[slot] = 0; }
    entry.counts[slot]! += amount;
    this.keys.set(key, entry);
    if (this.keys.size > this.maxKeys) this.keys.delete(this.keys.keys().next().value!);
  }
  /** Sum over minutes `from` to `to` ago (0 is the current minute), inclusive. */
  sum(key: string, now: number, from: number, to: number): number {
    const entry = this.keys.get(key);
    if (!entry) return 0;
    const minute = Math.floor(now / 60_000);
    let total = 0;
    for (let i = 0; i < this.minutes; i++) {
      const age = minute - entry.minutes[i]!;
      if (age >= from && age <= to) total += entry.counts[i]!;
    }
    return total;
  }
  prune(now: number): void {
    const minute = Math.floor(now / 60_000);
    for (const [key, entry] of this.keys) if (Math.max(...entry.minutes) <= minute - this.minutes) this.keys.delete(key);
  }
}

/** Distinct values per key in the current minute, counted up to `cap` (values are hashed to numbers). */
export class DistinctPerMinute {
  private keys = new Map<string, { minute: number; seen: Set<number> }>();
  constructor(private readonly cap: number, private readonly maxKeys = 2000) {}
  get size(): number { return this.keys.size; }
  /** Records the value and returns how many distinct values the key has this minute. */
  add(key: string, value: string, now: number): number {
    const minute = Math.floor(now / 60_000);
    let entry = this.keys.get(key);
    if (entry) this.keys.delete(key);
    if (!entry || entry.minute !== minute) entry = { minute, seen: new Set() };
    if (entry.seen.size < this.cap) entry.seen.add(hash32(value));
    this.keys.set(key, entry);
    if (this.keys.size > this.maxKeys) this.keys.delete(this.keys.keys().next().value!);
    return entry.seen.size;
  }
  prune(now: number): void {
    const minute = Math.floor(now / 60_000);
    for (const [key, entry] of this.keys) if (entry.minute < minute - 1) this.keys.delete(key);
  }
}

function hash32(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

// Static files a scanner's 2xx on means nothing (they're public by design).
const STATIC = /\.(?:js|mjs|css|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|txt|xml|json|webmanifest)$/i;
/** A 2xx here is worth noticing after a scan: not the home page, not a static asset. */
export function meaningfulPath(path: string): boolean {
  const route = path.split(/[?#]/)[0] || "/";
  return route !== "/" && !STATIC.test(route) && !route.startsWith("/_next/") && !route.startsWith("/assets/");
}

/** The hostname of a URL or host string, lowercased, without port; null when it isn't one. */
export function outboundHost(value: string): string | null {
  const text = value.trim();
  if (!text) return null;
  let host: string;
  try {
    host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`).hostname;
  } catch {
    return null;
  }
  host = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return host && host.length <= 253 && /^[a-z0-9.:-]+$/.test(host) ? host : null;
}
