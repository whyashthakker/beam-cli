// Pausing: what App monitoring does about a sender once it's sure they're attacking. A pause is
// temporary, scoped to what the sender did (sign-in routes for password guessing, LLM routes for
// model abuse, the whole app for scans and exploits), and never made automatically for private,
// loopback or allowlisted addresses. The SDK turns a pause into a 429 for the app to return, and
// `beam monitor --deny-file` into a web server deny list.
//
// Who decides: the workspace's pausing mode (dashboard, sent with the config) is off, dry run
// (decide and report "would have paused", refuse nothing) or auto. Pauses an admin makes in the
// dashboard or with `beam monitor pause` apply in every mode.
//
// Safety: a pause needs an address the client can't forge (see trustedRequestIp), a burst of new
// pauses trips a breaker that stops pausing and says so, and the number active is capped. Pure
// TypeScript with no Node.js built-ins (the SDK runs in edge runtimes); every structure is bounded.
import type { MonitorFinding } from "./monitor-client.js";
import { isAuthPath, isLlmPath } from "./monitor-rules.js";

export type PauseScope = "all" | "auth" | "llm";
export type PauseMode = "off" | "dry_run" | "auto";
export const PAUSE_SCOPES: PauseScope[] = ["all", "auth", "llm"];
export const PAUSE_MODES: PauseMode[] = ["off", "dry_run", "auto"];

export interface Pause {
  /** "203.0.113.9", "2001:db8:1:2::/64" (an IPv6 sender's /64) or "user:<id>". */
  target: string;
  scope: PauseScope;
  /** Epoch ms. */
  until: number;
  reason: string;
  ruleId?: string;
  source: "auto" | "manual";
  /** Dry run: recorded and reported, never enforced. */
  dryRun?: boolean;
}

/** A pause this instance made, as sent to the workspace (POST /v1/monitor/pauses). */
export interface PauseReport {
  target: string; scope: PauseScope; until: string; reason: string; ruleId?: string; findingId?: string;
  source: "auto"; dryRun: boolean; strike: number;
}

/** The workspace's pausing settings, from the config. */
export interface PauseSettings {
  mode: PauseMode;
  /** Addresses, CIDR ranges and user:<id> targets that are never paused. */
  allowlist: string[];
  /** Automatic pauses active at once, at most. */
  maxActive: number;
  /** New automatic pauses within 10 minutes before the breaker stops pausing for 30 minutes. */
  burst: number;
}
export const DEFAULT_PAUSE_SETTINGS: PauseSettings = { mode: "off", allowlist: [], maxActive: 500, burst: 50 };

/** What to do with one request or sender. */
export interface Verdict {
  paused: boolean;
  /** Dry run: this would have been paused. */
  wouldPause?: boolean;
  scope?: PauseScope;
  reason?: string;
  /** ISO time the pause ends. */
  until?: string;
  /** Seconds until the pause ends, for a Retry-After header. */
  retryAfter?: number;
  target?: string;
}
const ALLOW: Verdict = Object.freeze({ paused: false }) as Verdict;

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
export const MAX_AUTO_PAUSE_MS = DAY;
const BURST_WINDOW_MS = 10 * MINUTE;
const BREAKER_MS = 30 * MINUTE;
// After an admin lifts a pause, the sender isn't paused automatically again for this long.
const LIFTED_GRACE_MS = DAY;

/**
 * Detections that pause their sender automatically, and for how long the first time. A repeat
 * within a day pauses for four times as long, up to a day. Detections from a single request are
 * left alone unless they're critical exploits that weren't refused: one odd request is rarely
 * worth refusing someone, a pattern is.
 */
export const AUTO_PAUSES: Record<string, { scope: PauseScope; minutes: number; label: string; by: "ip" | "sender" }> = {
  "app.auth_bruteforce": { scope: "auth", minutes: 15, label: "repeated failed sign-ins", by: "ip" },
  "llm.denial_of_wallet": { scope: "llm", minutes: 15, label: "LLM request flood", by: "sender" },
  "llm.token_spend": { scope: "llm", minutes: 15, label: "unusual LLM spend", by: "sender" },
  "signal.path_walk": { scope: "all", minutes: 60, label: "walking the app's paths", by: "ip" },
  "signal.probe_hit": { scope: "all", minutes: 60, label: "scan found a live path", by: "ip" },
};
const EXPLOIT_PAUSE = { scope: "all" as const, minutes: 60, label: "critical exploit attempt", by: "ip" as const };

/** How a finding pauses its sender, or null when it doesn't. */
export function autoPauseFor(finding: Pick<MonitorFinding, "ruleId" | "severity" | "category" | "source" | "rollup" | "request">) {
  if (finding.rollup) return null;
  const listed = AUTO_PAUSES[finding.ruleId];
  if (listed) return listed;
  const outcome = finding.request?.outcome;
  if (finding.severity === "critical" && finding.category === "exploit" && finding.source === "http" && outcome !== "blocked" && outcome !== "not_applicable")
    return EXPLOIT_PAUSE;
  return null;
}

// ---------------------------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------------------------

interface Ip { v: 4 | 6; bytes: number[] }

/** An IPv4 or IPv6 address as bytes (IPv4-mapped IPv6 is read as IPv4), or null. */
export function parseIp(text: string | null | undefined): Ip | null {
  if (typeof text !== "string") return null;
  let s = text.trim();
  if (!s || s.length > 64) return null;
  if (s.startsWith("[")) s = s.slice(1, s.indexOf("]") > 0 ? s.indexOf("]") : undefined);
  s = s.replace(/%[\w.-]+$/, ""); // zone id
  const v4 = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const bytes = v4.slice(1).map(Number);
    return bytes.every(b => b <= 255) ? { v: 4, bytes } : null;
  }
  if (!/^[0-9a-fA-F:.]+$/.test(s) || !s.includes(":")) return null;
  let tail: number[] = [];
  const lastColon = s.lastIndexOf(":");
  const last = s.slice(lastColon + 1);
  if (last.includes(".")) {
    // An IPv4 tail (::ffff:192.0.2.1, 64:ff9b::192.0.2.1) is the last two groups.
    const embedded = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(last) ? parseIp(last) : null;
    if (!embedded) return null;
    tail = [(embedded.bytes[0]! << 8) | embedded.bytes[1]!, (embedded.bytes[2]! << 8) | embedded.bytes[3]!];
    s = s.slice(0, lastColon + 1);
    if (!s.endsWith("::")) s = s.slice(0, -1);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const part = (h: string) => (h ? h.split(":") : []);
  const head = part(halves[0]!);
  const back = halves.length === 2 ? part(halves[1]!) : [];
  if (![...head, ...back].every(g => /^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  const groups = 8 - tail.length;
  const missing = groups - head.length - back.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const words = [...head.map(g => parseInt(g, 16)), ...new Array<number>(halves.length === 2 ? missing : 0).fill(0), ...back.map(g => parseInt(g, 16)), ...tail];
  if (words.length !== 8) return null;
  const bytes = words.flatMap(w => [w >> 8, w & 0xff]);
  // ::ffff:a.b.c.d is an IPv4 client on a dual-stack socket.
  if (bytes.slice(0, 10).every(b => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) return { v: 4, bytes: bytes.slice(12) };
  return { v: 6, bytes };
}

interface Range { v: 4 | 6; bytes: number[]; bits: number }
function parseRange(text: string): Range | null {
  const [addr, len, extra] = text.trim().split("/");
  if (extra !== undefined) return null;
  const ip = parseIp(addr);
  if (!ip) return null;
  const max = ip.v === 4 ? 32 : 128;
  const bits = len === undefined ? max : /^\d{1,3}$/.test(len) ? Number(len) : -1;
  return bits >= 0 && bits <= max ? { ...ip, bits } : null;
}
/** A range in one canonical spelling: host bits cleared, IPv6 in its shortest form. */
function formatRange(range: Range): string {
  const bytes = range.bytes.map((b, i) => {
    const bit = i * 8;
    if (bit >= range.bits) return 0;
    const take = Math.min(8, range.bits - bit);
    return b & ((0xff << (8 - take)) & 0xff);
  });
  if (range.v === 4) return `${bytes.join(".")}/${range.bits}`;
  const words: number[] = [];
  for (let i = 0; i < 16; i += 2) words.push((bytes[i]! << 8) | bytes[i + 1]!);
  return `${formatV6(words)}/${range.bits}`;
}
/** Eight 16-bit words as RFC 5952 text: lowercase, the longest run of two or more zero words as "::". */
function formatV6(words: number[]): string {
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (words[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = words.map(w => w.toString(16));
  if (best < 0) return hex.join(":");
  return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
}
function inRange(ip: Ip, range: Range): boolean {
  if (ip.v !== range.v) return false;
  for (let bit = 0; bit < range.bits; bit += 8) {
    const take = Math.min(8, range.bits - bit);
    const mask = (0xff << (8 - take)) & 0xff;
    if ((ip.bytes[bit / 8]! & mask) !== (range.bytes[bit / 8]! & mask)) return false;
  }
  return true;
}

// Private, loopback, link-local, shared (CGNAT) and unspecified ranges: usually a proxy, a load
// balancer or the app's own network. Pausing one could refuse everyone behind it.
const PROTECTED = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "255.255.255.255/32", "::/128", "::1/128", "fc00::/7", "fe80::/10"]
  .map(r => parseRange(r)!);
export function isProtectedIp(ip: string): boolean {
  const parsed = parseIp(ip);
  return !parsed || PROTECTED.some(r => inRange(parsed, r));
}

/**
 * What a pause on this address is keyed by: the address itself for IPv4, the /64 for IPv6 (one
 * customer's network: rotating within it is free), or null when it isn't an address.
 */
export function pauseTarget(ip: string | null | undefined): string | null {
  const parsed = parseIp(ip);
  if (!parsed) return null;
  if (parsed.v === 4) return parsed.bytes.join(".");
  return formatRange({ ...parsed, bits: 64 });
}

/** user:<id> for a user id, or null. */
export function userTarget(user: string | null | undefined): string | null {
  const id = typeof user === "string" ? user.trim().slice(0, 80) : "";
  return id ? `user:${id}` : null;
}

/** A target as typed by a person (an address, a CIDR range, or user:<id>), normalized; or null. */
export function normalizeTarget(text: string): string | null {
  const s = text.trim();
  if (/^user:/i.test(s)) return userTarget(s.slice(5));
  if (!s.includes("/")) return pauseTarget(s);
  const range = parseRange(s);
  if (!range || range.bits < (range.v === 4 ? 16 : 32)) return null; // nothing wider than a /16 or a /32
  if (range.v === 6 && range.bits === 64) return pauseTarget(s.split("/")[0]);
  if (range.v === 4 && range.bits === 32) return range.bytes.join(".");
  return formatRange(range);
}

interface Allowlist { ranges: Range[]; users: Set<string> }
function compileAllowlist(entries: string[]): Allowlist {
  const ranges: Range[] = [];
  const users = new Set<string>();
  for (const entry of entries.slice(0, 1000)) {
    if (typeof entry !== "string") continue;
    if (/^user:/i.test(entry.trim())) { const u = userTarget(entry.trim().slice(5)); if (u) users.add(u); continue; }
    const range = parseRange(entry);
    if (range) ranges.push(range);
  }
  return { ranges, users };
}

/** Pauses on a range wider than one sender (an admin's CIDR pause), to test addresses against. */
function rangeTargets(map: Map<string, Pause>): { range: Range; pause: Pause }[] {
  const out: { range: Range; pause: Pause }[] = [];
  for (const pause of map.values()) {
    if (!pause.target.includes("/") || pause.target.endsWith("::/64")) continue;
    const range = parseRange(pause.target);
    if (range) out.push({ range, pause });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Trusted client address
// ---------------------------------------------------------------------------------------------

/**
 * The client address of a request, when it can be trusted enough to pause: one the client can't
 * forge. Platforms that set or overwrite the header (Cloudflare, Vercel, Fly.io) are read
 * directly. Otherwise the address the app passed is checked against X-Forwarded-For: the first
 * entry of a list is whatever the client sent, so it's never trusted, while the last entry (added
 * by the app's own proxy), the only entry, or an address not in the header (the socket's, or
 * Express's req.ip with trust proxy) is. Returns null when the address can't be trusted.
 */
export function trustedRequestIp(
  ip: string | null | undefined,
  header: (name: string) => string | undefined,
  platform: { cloudflare?: boolean; vercel?: boolean; fly?: boolean; trustGiven?: boolean },
): string | null {
  const valid = (v: string | undefined | null) => (parseIp(v) ? String(v).trim() : null);
  if (platform.cloudflare) return valid(header("cf-connecting-ip")) ?? valid(ip);
  if (platform.fly) return valid(header("fly-client-ip")) ?? valid(ip);
  // Vercel overwrites X-Forwarded-For and sets X-Real-IP; neither carries what the client sent.
  if (platform.vercel) return valid(header("x-real-ip")) ?? valid(header("x-forwarded-for")?.split(",")[0]) ?? valid(ip);
  const given = valid(ip);
  if (!given || platform.trustGiven) return given;
  const forwarded = header("x-forwarded-for")?.split(",").map(s => s.trim()).filter(Boolean) ?? [];
  if (forwarded.length < 2) return given;
  const at = forwarded.indexOf(given);
  return at === -1 || at === forwarded.length - 1 ? given : null;
}

// ---------------------------------------------------------------------------------------------
// The pause book
// ---------------------------------------------------------------------------------------------

export interface PauseBookOptions {
  now?: () => number;
  /** Something a person should know: the breaker tripped, the cap was reached. */
  onNotice?: (message: string, kind: "breaker" | "cap") => void;
}

const key = (target: string, scope: PauseScope) => `${target}\0${scope}`;

/**
 * The pauses one app instance knows about: those it made itself (local) and those from the
 * workspace (remote: admins' pauses, and other instances' when pausing is on). Bounded.
 */
export class PauseBook {
  private local = new Map<string, Pause & { findingId?: string }>();
  private remote = new Map<string, Pause>();
  private remoteRanges: { range: Range; pause: Pause }[] = [];
  private lifted = new Map<string, number>();
  private strikes = new Map<string, { count: number; last: number }>();
  private recent: number[] = [];
  private breakerUntil = 0;
  private capNoticeAt = 0;
  private reports: PauseReport[] = [];
  private allow: Allowlist = { ranges: [], users: new Set() };
  private maintainedMinute = -1;
  private changes = 0;
  settings: PauseSettings = { ...DEFAULT_PAUSE_SETTINGS };

  /** Goes up whenever a pause is made here, so a caller can skip re-checking when nothing changed. */
  get version(): number { return this.changes; }

  constructor(private readonly opts: PauseBookOptions = {}) {}

  private now(): number { return this.opts.now?.() ?? Date.now(); }

  get size(): { local: number; remote: number; strikes: number; reports: number } {
    return { local: this.local.size, remote: this.remote.size, strikes: this.strikes.size, reports: this.reports.length };
  }

  /** The workspace's settings, its active pauses, and pauses an admin lifted (from the config). */
  configure(settings: Partial<PauseSettings> | null | undefined, pauses: unknown, lifted: unknown): void {
    const s = settings && typeof settings === "object" ? settings : {};
    this.settings = {
      mode: PAUSE_MODES.includes(s.mode as PauseMode) ? (s.mode as PauseMode) : "off",
      allowlist: Array.isArray(s.allowlist) ? s.allowlist.filter((e): e is string => typeof e === "string").slice(0, 1000) : [],
      maxActive: typeof s.maxActive === "number" && s.maxActive >= 0 ? Math.min(s.maxActive, 5000) : DEFAULT_PAUSE_SETTINGS.maxActive,
      burst: typeof s.burst === "number" && s.burst >= 1 ? Math.min(s.burst, 1000) : DEFAULT_PAUSE_SETTINGS.burst,
    };
    this.allow = compileAllowlist(this.settings.allowlist);
    const now = this.now();
    this.remote.clear();
    for (const p of Array.isArray(pauses) ? pauses.slice(0, 5000) : []) {
      const pause = readPause(p, now);
      if (pause) this.remote.set(key(pause.target, pause.scope), pause);
    }
    this.remoteRanges = rangeTargets(this.remote);
    for (const l of Array.isArray(lifted) ? lifted.slice(0, 5000) : []) {
      const target = typeof l?.target === "string" ? l.target : null;
      const at = typeof l?.at === "string" ? Date.parse(l.at) : Number.NaN;
      if (!target || !Number.isFinite(at)) continue;
      if (at + LIFTED_GRACE_MS > now) this.lifted.set(target, at + LIFTED_GRACE_MS);
      for (const scope of PAUSE_SCOPES) this.local.delete(key(target, scope));
    }
    if (this.lifted.size > 5000) this.lifted = new Map([...this.lifted].slice(-5000));
    // Turned down in the dashboard: this instance's own pauses stop being enforced too. Turned up
    // to auto: dry runs are dropped rather than enforced, so a pause always follows fresh evidence.
    for (const [k, pause] of this.local) {
      if (this.settings.mode === "off" || (this.settings.mode === "auto" && pause.dryRun)) this.local.delete(k);
      else if (this.settings.mode === "dry_run") pause.dryRun = true;
    }
  }

  /** Whether the sender (address and/or user) is paused for this request. Never throws. */
  check(who: { ip?: string | null; user?: string | null }, where: { path?: string; llm?: boolean } = {}): Verdict {
    try {
      const now = this.now();
      this.maintain(now);
      if (!this.local.size && !this.remote.size) return ALLOW;
      const scopes: PauseScope[] = ["all"];
      if (where.path !== undefined && isAuthPath(where.path)) scopes.push("auth");
      if (where.llm || (where.path !== undefined && isLlmPath(where.path))) scopes.push("llm");
      const targets: string[] = [];
      const parsed = parseIp(who.ip);
      const ipTarget = pauseTarget(who.ip);
      if (ipTarget && !this.allowedIp(parsed!)) targets.push(ipTarget);
      const user = userTarget(who.user);
      if (user && !this.allow.users.has(user)) targets.push(user);
      let dry: Pause | null = null;
      for (const target of targets)
        for (const scope of scopes) {
          const found = this.find(target, scope, now);
          if (found && !found.dryRun) return verdictFor(found, now);
          if (found) dry ??= found;
        }
      // A pause on a range (an admin's, from the dashboard) covers every address in it.
      if (parsed && this.remoteRanges.length && !this.allowedIp(parsed))
        for (const { range, pause } of this.remoteRanges)
          if (scopes.includes(pause.scope) && pause.until > now && !pause.dryRun && inRange(parsed, range)) return verdictFor(pause, now);
      return dry ? { ...verdictFor(dry, now), paused: false, wouldPause: true } : ALLOW;
    } catch {
      return ALLOW;
    }
  }

  private find(target: string, scope: PauseScope, now: number): Pause | undefined {
    const k = key(target, scope);
    const local = this.local.get(k);
    const remote = this.remote.get(k);
    const live = [local, remote].filter((p): p is Pause => Boolean(p && p.until > now));
    return live.find(p => !p.dryRun) ?? live[0];
  }

  private allowedIp(ip: Ip): boolean { return this.allow.ranges.some(r => inRange(ip, r)); }

  /**
   * A finding was raised (or repeated) about a sender. Pauses the sender when the finding calls
   * for it and the mode allows. `who` holds only what can be trusted: an address from
   * trustedRequestIp, or the app's own user id. Returns the new pause, or null.
   */
  consider(finding: MonitorFinding, who: { ip?: string | null; user?: string | null }): Pause | null {
    try {
      if (this.settings.mode === "off") return null;
      const rule = autoPauseFor(finding);
      if (!rule) return null;
      const now = this.now();
      this.maintain(now);
      const user = rule.by === "sender" ? userTarget(who.user) : null;
      const ip = user ? null : pauseTarget(who.ip);
      const target = user ?? ip;
      if (!target) return null;
      if (ip && (isProtectedIp(who.ip!) || this.allowedIp(parseIp(who.ip)!))) return null;
      if (user && this.allow.users.has(user)) return null;
      if ((this.lifted.get(target) ?? 0) > now) return null;
      for (const scope of rule.scope === "all" ? ["all" as const] : ["all" as const, rule.scope]) {
        const existing = this.find(target, scope, now);
        if (existing && (!existing.dryRun || this.settings.mode === "dry_run")) return null;
      }
      if (now < this.breakerUntil) return null;
      this.recent = this.recent.filter(t => t > now - BURST_WINDOW_MS);
      if (this.recent.length >= this.settings.burst) {
        this.breakerUntil = now + BREAKER_MS;
        this.opts.onNotice?.(
          `${this.recent.length} senders were paused within 10 minutes, the most this app pauses in a burst. Automatic pausing is stopped for 30 minutes so a misread can't refuse real users. If this is a large attack, turn on your CDN's attack mode.`,
          "breaker",
        );
        return null;
      }
      let active = 0;
      for (const p of this.local.values()) if (p.until > now) active++;
      if (active >= this.settings.maxActive) {
        if (now - this.capNoticeAt > 60 * MINUTE) {
          this.capNoticeAt = now;
          this.opts.onNotice?.(`${active} senders are paused, the most this app pauses at once. New automatic pauses wait until some expire.`, "cap");
        }
        return null;
      }
      const prior = this.strikes.get(target);
      const count = prior && prior.last > now - DAY ? prior.count + 1 : 1;
      this.strikes.delete(target);
      this.strikes.set(target, { count, last: now });
      if (this.strikes.size > 10_000) this.strikes.delete(this.strikes.keys().next().value!);
      const ms = Math.min(MAX_AUTO_PAUSE_MS, rule.minutes * MINUTE * 4 ** (count - 1));
      const pause: Pause & { findingId?: string } = {
        target, scope: rule.scope, until: now + ms, source: "auto", dryRun: this.settings.mode !== "auto",
        reason: `${rule.label[0]!.toUpperCase()}${rule.label.slice(1)} from ${target}${count > 1 ? ` (again: pause ${count})` : ""}`,
        ruleId: finding.ruleId, findingId: finding.id,
      };
      this.local.set(key(target, rule.scope), pause);
      this.changes++;
      this.recent.push(now);
      if (this.reports.length >= 200) this.reports.shift();
      this.reports.push({
        target, scope: pause.scope, until: new Date(pause.until).toISOString(), reason: pause.reason, ruleId: finding.ruleId,
        findingId: finding.id, source: "auto", dryRun: Boolean(pause.dryRun), strike: count,
      });
      return pause;
    } catch {
      return null;
    }
  }

  /** New pauses to send to the workspace; taken once. */
  takeReports(): PauseReport[] { return this.reports.splice(0); }
  /** Puts reports back after a failed send (newest kept when over the cap). */
  returnReports(reports: PauseReport[]): void { this.reports = [...reports, ...this.reports].slice(-200); }

  /** Every pause in force now (not dry runs), local and remote, for a deny list. */
  active(): Pause[] {
    const now = this.now();
    const out = new Map<string, Pause>();
    for (const map of [this.remote, this.local]) for (const [k, p] of map) if (p.until > now && !p.dryRun && !out.has(k)) out.set(k, p);
    return [...out.values()].filter(p => !this.isAllowlistedTarget(p.target));
  }

  private isAllowlistedTarget(target: string): boolean {
    if (target.startsWith("user:")) return this.allow.users.has(target);
    const parsed = parseIp(target.split("/")[0]);
    return Boolean(parsed && !target.includes("/") && this.allowedIp(parsed));
  }

  /** Once a minute: forget expired pauses, old strikes and lifted grace periods. */
  private maintain(now: number): void {
    const minute = Math.floor(now / MINUTE);
    if (minute === this.maintainedMinute) return;
    this.maintainedMinute = minute;
    for (const [k, p] of this.local) if (p.until <= now) this.local.delete(k);
    for (const [k, p] of this.remote) if (p.until <= now) this.remote.delete(k);
    for (const [t, s] of this.strikes) if (s.last <= now - DAY) this.strikes.delete(t);
    for (const [t, until] of this.lifted) if (until <= now) this.lifted.delete(t);
  }
}

function verdictFor(pause: Pause, now: number): Verdict {
  return {
    paused: true, scope: pause.scope, reason: pause.reason, target: pause.target,
    until: new Date(pause.until).toISOString(), retryAfter: Math.max(1, Math.ceil((pause.until - now) / 1000)),
  };
}

/** A pause from the config, validated: unknown, expired or malformed ones are dropped. */
function readPause(value: unknown, now: number): Pause | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  const target = typeof v.target === "string" ? normalizeTarget(v.target) : null;
  const scope = PAUSE_SCOPES.includes(v.scope as PauseScope) ? (v.scope as PauseScope) : "all";
  const until = typeof v.until === "string" ? Date.parse(v.until) : Number.NaN;
  if (!target || !Number.isFinite(until) || until <= now) return null;
  return {
    target, scope, until: Math.min(until, now + 30 * DAY),
    reason: typeof v.reason === "string" ? v.reason.slice(0, 200) : "Paused in the dashboard",
    ruleId: typeof v.ruleId === "string" ? v.ruleId.slice(0, 100) : undefined,
    source: v.source === "auto" ? "auto" : "manual",
    dryRun: v.dryRun === true,
  };
}

/** The body an app returns to a paused sender: generic, so it tells an attacker nothing about why. */
export function pausedBody(): string {
  return JSON.stringify({ error: "Too many requests. Try again later." });
}
