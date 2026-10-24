// AgentBeam App monitoring inside your app: `import { createAppMonitor } from "@agent-beam/beam/monitor"`.
//
// The in-process alternative to running `beam monitor` next to an app. Hand it each request
// (Next.js middleware, an Express/Fastify hook) and, optionally, log lines. Apps with LLM features
// also hand it what goes into the model (prompt) and what comes out (output). Detection runs right
// here with the same rules as the CLI; only redacted findings leave the process, in batches,
// authenticated with the app's least-privilege BEAM_APP_TOKEN.
//
// It never throws, never blocks or alters a request, and never makes a request wait on the
// network: findings are sent in the background (pass flush() to event.waitUntil in middleware).
// It's built to stay out of the way when things go wrong: detection has a hard CPU budget
// (maxCpuPercent), every rule is linear in the input, memory is bounded, and when AgentBeam is
// slow or down it backs off (up to 5 minutes between tries) and holds at most 1,000 findings.
// prompt() and output() return what they found, so the app can decide to refuse or withhold.
// If AgentBeam is unreachable, App monitoring is off for the workspace, or the monthly allowance
// is spent, findings are dropped and the app doesn't notice. No dependencies and no Node.js
// built-ins, so it runs in edge runtimes too.
import type { MonitorFinding, MonitorLevel, MonitorSeverity } from "./monitor-client.js";
import { CpuBudget, MonitorPipeline, type SendOutcome } from "./monitor-pipeline.js";
import { matchLine, type MonitorRule } from "./monitor-rules.js";
import { isStack, type Stack } from "./monitor-stacks.js";
import { containsCanary } from "./prompt-attacks.js";
import { judgeWithOwnLlm, ownLlmConfig, type OwnLlmConfig } from "./monitor-llm.js";

export interface AppMonitorOptions {
  /** The app's token from the dashboard (App monitoring > Settings, apps and alerts). Default: BEAM_APP_TOKEN. */
  token?: string;
  /** Default: BEAM_DASHBOARD_URL, else https://app.agentbeam.com. Must be https (localhost excepted). */
  dashboardUrl?: string;
  /** How often pending findings are sent, at most. Default 5000 ms. */
  flushIntervalMs?: number;
  /** Diagnostics (misconfiguration, App monitoring turned off, revoked token). Silent by default. */
  onError?: (message: string) => void;
  /**
   * Random strings planted in your system prompt (at least 8 characters, e.g. "canary-7f3a9c1e").
   * One showing up in output() means the system prompt leaked: a critical finding.
   */
  canaries?: string[];
  /** False: findings from prompt() and output() carry the rule and sender but no text excerpt. Default true. */
  excerpts?: boolean;
  /**
   * The most of one CPU core detection may use, in percent (0.1 to 50): that much for request()
   * and log(), and as much again for prompt() and output(). Past it, checks are skipped until the
   * next minute: request() and log() quietly, prompt() and output() with `skipped: true` so the
   * app can decide. Default 2.
   */
  maxCpuPercent?: number;
  /**
   * Review flagged findings with your own LLM key before they're sent, like `beam monitor --llm`:
   * "openai", "anthropic", "gemini", "groq", "openrouter", "mistral", "deepseek", "xai", "ollama"
   * or "custom", with the key the app already has (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...), or
   * "beam" to leave it to the workspace's setting. Default: BEAM_LLM_PROVIDER. The key stays in
   * the app and only the verdict goes to AgentBeam. Runs during flush(), never on a request.
   */
  llm?: string;
  /**
   * True when this app proxies or rewrites some paths to a PHP, WordPress, ASP or Java server.
   * By default an attack on such a path (/wp-admin/, *.php) is rolled up as aimed at software the
   * app doesn't run, instead of raised on its own, since a JavaScript app can't execute it.
   */
  proxiesOtherStacks?: boolean;
  /**
   * The app's framework: "nextjs", "express", "nestjs", "vite", "node" (the default), or for a
   * backend that reports through a Node service, "django", "flask", "fastapi", "rails", "laravel",
   * "php", "wordpress", "spring", "java", "go", "dotnet". Turns on that framework's rules, and
   * rolls up attacks on frameworks the app doesn't run.
   */
  stack?: Stack;
  /**
   * Note the host of every fetch() the app makes, so a first call to a new host is raised (after
   * the workspace has learned the app's usual hosts for a day). Wraps globalThis.fetch once; only
   * the hostname is kept, never the URL, headers or body. Calls made without fetch (Node's http
   * module, some SDKs) can be reported with outbound(). Default false.
   */
  watchOutbound?: boolean;
  /** LLM tokens one user may use in an hour before it's raised (usage()). Default: 500,000 on the standard level. */
  tokensPerUserHour?: number;
}

/** Who a security event is about. The user is an opaque id, not an email. */
export interface SecurityEventInfo {
  ip?: string | null;
  user?: string | null;
  /** A short note shown with the finding, e.g. "role=admin by user 12". Redacted like evidence. */
  detail?: string;
}

export interface RequestInfo {
  method: string;
  /** Path and query string, e.g. request.nextUrl.pathname + request.nextUrl.search. */
  url: string;
  ip?: string | null;
  userAgent?: string | null;
  /**
   * The response status, when the hook runs after the response (Express `res.on("finish")`,
   * Fastify `onResponse`). Attacks the app refused (3xx/4xx) are rolled up instead of alerted on.
   */
  status?: number | null;
  /** Response size in bytes and time taken, when known. */
  bytes?: number | null;
  durationMs?: number | null;
  /** Two-letter country and autonomous system number of the client, when the host or CDN provides them. */
  country?: string | null;
  asn?: number | null;
  /**
   * The request's headers (a Headers object or a plain record). Read for Host, Referer, User-Agent
   * and the country your platform adds (x-vercel-ip-country, cf-ipcountry,
   * cloudfront-viewer-country). Nothing else is read and no header is sent as-is.
   */
  headers?: Headers | Record<string, string | string[] | undefined> | null;
}

export interface PromptInfo {
  /** Who sent it, to group repeats and spot floods: the client address or an opaque user id (not an email). */
  ip?: string | null;
  user?: string | null;
  /** Shown with the finding, e.g. "support chat" or "retrieved web page". Default "prompts" or "model output". */
  label?: string;
}

/** What a local check found. Matches count whatever the dashboard's level; reporting follows the level. */
export interface TextCheck {
  flagged: boolean;
  /** True when the check didn't run because the CPU budget for this minute was spent. */
  skipped?: boolean;
  /** The most severe match, or null when nothing matched. */
  severity: MonitorSeverity | null;
  matches: { ruleId: string; title: string; severity: MonitorSeverity }[];
}

export interface AppMonitor {
  /** Check one incoming request. Cheap and synchronous; never throws. */
  request(info: RequestInfo): void;
  /** Check one application log line (errors, auth failures, anything the app prints). */
  log(line: string): void;
  /**
   * Check text before it reaches your model: the user's message, or content the model will read
   * (a retrieved document, web page, email or tool result). Flags prompt injection, hidden
   * instructions, forged chat markers, jailbreaks and system prompt extraction, and floods from
   * one sender. Synchronous and local; never throws.
   */
  prompt(text: string, info?: PromptInfo): TextCheck;
  /**
   * Check model output before you show it or act on it: zero-click exfiltration links, credentials,
   * script, a leaked canary, and injected instructions passed along to the next agent.
   */
  output(text: string, info?: PromptInfo): TextCheck;
  /**
   * Report a security event: failed and successful sign-ins (a success right after a run of
   * failures is raised as a possible account takeover), admin or role grants, and new API keys.
   */
  event(type: "login.failed" | "login.succeeded" | "admin.granted" | "apikey.created", info?: SecurityEventInfo): void;
  /** Report LLM tokens used for one user, to catch runaway or scripted spend (tokensPerUserHour). */
  usage(info: { tokens: number; user?: string | null; ip?: string | null; model?: string }): void;
  /** Report an outbound call (a URL or host) the app made, when watchOutbound can't see it. */
  outbound(target: string): void;
  /**
   * Send pending findings when the flush interval is due (or now, with `force`). Returns the
   * in-flight send, so `event.waitUntil(beam.flush())` keeps it alive past the response; cheap to
   * call on every request. Never rejects.
   */
  flush(options?: { force?: boolean }): Promise<void>;
  /** False when there's no valid token or it was revoked: nothing is reported, and prompt() and output() only check locally. */
  readonly enabled: boolean;
}

const TOKEN = /^beam_app_[\w-]{40,}$/;
const CONFIG_EVERY_MS = 5 * 60 * 1000;
const CONFIG_RETRY_MS = 60 * 1000;

function env(name: string): string | undefined {
  const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  return p?.env?.[name]?.trim() || undefined;
}

/** Case-insensitive lookup in a Headers object or a plain record; the first value of a list. */
function headerReader(headers: RequestInfo["headers"]): (name: string) => string | undefined {
  if (!headers || typeof headers !== "object") return () => undefined;
  if (typeof (headers as Headers).get === "function") return name => (headers as Headers).get(name) ?? undefined;
  const lower = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v[0] : v]));
  return name => lower.get(name) ?? undefined;
}

function withTimeout(ms: number): { signal: AbortSignal; done: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  // Never keep the app's process alive for a report (Node returns a Timeout with unref; edge runtimes a number).
  (timer as { unref?: () => void }).unref?.();
  return { signal: controller.signal, done: () => clearTimeout(timer) };
}

const REQUEST_TIMEOUT_MS = 5_000;
const MAX_BACKOFF_MS = 5 * 60_000;
const REVOKED_RECHECK_MS = 15 * 60_000;
const MAX_PAUSE_MS = 24 * 60 * 60_000;
/** Doubling delays with jitter, so many app instances don't retry an outage in lockstep. */
const backoff = (base: number, failures: number) => Math.min(MAX_BACKOFF_MS, base * 2 ** Math.min(failures, 10)) * (0.5 + Math.random() / 2);
/** A server-provided resume time, sanity-checked: never in the past, never more than a day away. */
function pauseUntil(resetAt: unknown): number {
  const at = typeof resetAt === "string" ? Date.parse(resetAt) : Number.NaN;
  const now = Date.now();
  return Number.isFinite(at) && at > now ? Math.min(at, now + MAX_PAUSE_MS) : now + 60_000;
}

const SEVERITY_RANK: Record<MonitorSeverity, number> = { critical: 3, high: 2, medium: 1, low: 0 };
const clean = (): TextCheck => ({ flagged: false, severity: null, matches: [] });

function canaryRule(canaries: string[]): MonitorRule[] {
  const usable = canaries.filter(c => typeof c === "string" && c.replace(/[^a-z0-9]/gi, "").length >= 8);
  return usable.length
    ? [{ id: "llm.system_prompt_leak", title: "System prompt leaked in model output", severity: "critical", category: "llm", sources: ["output"],
        match: (_s, raw) => containsCanary(raw, usable) }]
    : [];
}

// Rules read 16 KB at a time; a long retrieved document is read in overlapping windows, up to 256 KB.
const WINDOW = 16_384;
const OVERLAP = 512;
const MAX_TEXT = 262_144;

/** The check, and the window that matched (what gets reported). */
function scan(text: unknown, source: "prompt" | "output", extra: MonitorRule[] = []): { result: TextCheck; window: string } {
  try {
    if (typeof text !== "string" || !text.trim()) return { result: clean(), window: "" };
    const all = text.slice(0, MAX_TEXT);
    let window = all.slice(0, WINDOW);
    let rules: MonitorRule[] = [];
    for (let at = 0; at < all.length && !rules.length; at += WINDOW - OVERLAP) {
      window = all.slice(at, at + WINDOW);
      rules = matchLine(window, source, extra);
    }
    if (!rules.length) return { result: clean(), window: all.slice(0, WINDOW) };
    const matches = rules.map(r => ({ ruleId: r.id, title: r.title, severity: r.severity }))
      .filter((m, i, list) => list.findIndex(o => o.ruleId === m.ruleId) === i);
    const severity = matches.reduce((worst, m) => (SEVERITY_RANK[m.severity] > SEVERITY_RANK[worst] ? m.severity : worst), matches[0]!.severity);
    return { result: { flagged: true, severity, matches }, window };
  } catch {
    return { result: clean(), window: "" };
  }
}
const check = (text: unknown, source: "prompt" | "output", extra?: MonitorRule[]) => scan(text, source, extra).result;

/** Checks text bound for an LLM, locally, without reporting it anywhere. Never throws. */
export function checkPrompt(text: string): TextCheck {
  return check(text, "prompt");
}

/** Checks model output, locally, without reporting it anywhere. Pass your system prompt's canaries to catch leaks. */
export function checkOutput(text: string, options: { canaries?: string[] } = {}): TextCheck {
  return check(text, "output", canaryRule(options.canaries ?? []));
}

// Without a token the checks still work locally; nothing is reported.
const noop: AppMonitor = {
  request() {}, log() {}, event() {}, usage() {}, outbound() {}, flush: async () => {}, enabled: false,
  prompt: text => checkPrompt(text),
  output: text => checkOutput(text),
};

export function createAppMonitor(options: AppMonitorOptions = {}): AppMonitor {
  try {
    return start(options ?? {});
  } catch {
    // A bad option or an unusual runtime: monitoring is off, and the app carries on.
    return noop;
  }
}

function start(options: AppMonitorOptions): AppMonitor {
  const report = (message: string) => { try { options.onError?.(message); } catch { /* never throw */ } };
  const token = (typeof options.token === "string" ? options.token.trim() : "") || env("BEAM_APP_TOKEN");
  const canaries = canaryRule(Array.isArray(options.canaries) ? options.canaries : []);
  const percent = Math.min(50, Math.max(0.1, Number(options.maxCpuPercent) || 2));
  // 1% of a core = 600 ms per minute. Traffic and logs get one budget; prompt() and output() get
  // their own, so a flood of requests can't switch off the checks an app may block on.
  const budget = new CpuBudget(600 * percent);
  const localBudget = new CpuBudget(600 * percent);
  const budgeted = (text: unknown, source: "prompt" | "output", extra: MonitorRule[] = []) =>
    localBudget.run(() => scan(text, source, extra)) ?? { result: { ...clean(), skipped: true }, window: "" };
  const local: AppMonitor = { ...noop, prompt: text => budgeted(text, "prompt").result, output: text => budgeted(text, "output", canaries).result };
  if (!token || !TOKEN.test(token)) {
    report("AgentBeam App monitoring is off: set BEAM_APP_TOKEN to the app's token (beam_app_…) from the dashboard.");
    return local;
  }
  if (typeof fetch !== "function" || typeof AbortController !== "function") {
    report("AgentBeam App monitoring is off: this runtime has no fetch.");
    return local;
  }
  const base = (options.dashboardUrl || env("BEAM_DASHBOARD_URL") || "https://app.agentbeam.com").replace(/\/+$/, "");
  let url: URL;
  try { url = new URL(base); } catch { report(`AgentBeam App monitoring is off: ${base} isn't a valid URL.`); return local; }
  if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
    report("AgentBeam App monitoring is off: refusing to send the app token over plain HTTP.");
    return local;
  }

  const flushEvery = Math.max(1000, Number(options.flushIntervalMs) || 5000);
  let ownLlm: OwnLlmConfig | null = null;
  try {
    const processEnv = (globalThis as { process?: { env?: NodeJS.ProcessEnv } }).process?.env ?? {};
    const llm = ownLlmConfig(processEnv, typeof options.llm === "string" ? options.llm : undefined, null);
    // Short timeouts: this runs inside the app's background work (event.waitUntil on serverless).
    ownLlm = llm ? { ...llm, timeoutMs: 8_000 } : null;
  } catch (error) {
    report(`AgentBeam App monitoring: your own LLM check is off: ${(error as Error).message}`);
  }
  const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
  let level: MonitorLevel | null = null;
  // A 401 pauses reporting and is checked again later: during an AgentBeam incident a working token
  // can be rejected for a while, and the app shouldn't need a restart to resume.
  let revokedUntil = 0;
  let pausedUntil = 0;
  let configAt = 0;
  let configFailures = 0;
  let configInFlight = false;
  let lastFlush = 0;
  let sendFailures = 0;
  let nextSendAt = 0;
  let flushing: Promise<void> | null = null;
  let budgetReportedAt = 0;
  const revoked = () => Date.now() < revokedUntil;

  const pipeline = new MonitorPipeline({
    level: () => (!revoked() && Date.now() >= pausedUntil ? level : null),
    budget,
    // Proxying other stacks' paths: nothing can be ruled out by stack.
    stack: options.proxiesOtherStacks === true ? undefined : isStack(options.stack) ? options.stack : "node",
    tokensPerUserHour: typeof options.tokensPerUserHour === "number" && options.tokensPerUserHour > 0 ? options.tokensPerUserHour : undefined,
  });

  const refreshConfig = async () => {
    configInFlight = true;
    const t = withTimeout(REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(`${base}/v1/monitor/config`, { headers, signal: t.signal });
      const body = (await response.json().catch(() => ({}))) as { level?: MonitorLevel; error?: string; resetAt?: string; outbound?: { hosts?: unknown } };
      configFailures = response.status >= 500 ? configFailures + 1 : 0;
      if (response.ok) {
        level = body.level ?? "standard";
        revokedUntil = 0;
        const hosts = body.outbound?.hosts;
        if (Array.isArray(hosts)) pipeline.setKnownOutboundHosts(hosts.filter((h): h is string => typeof h === "string"));
      }
      else if (response.status === 401) {
        if (!revoked()) report("AgentBeam App monitoring paused: this app token was rejected (rotated or removed). Checking again in 15 minutes.");
        revokedUntil = Date.now() + REVOKED_RECHECK_MS;
      }
      else if (response.status === 403) { level = null; report(typeof body.error === "string" ? body.error : "AgentBeam App monitoring is turned off for this workspace."); }
      else if (response.status === 429) pausedUntil = pauseUntil(body.resetAt);
    } catch {
      configFailures++; // unreachable or slow: keep the last known level and back off
    } finally {
      t.done();
      configAt = Date.now();
      configInFlight = false;
    }
  };

  const ensureConfig = () => {
    if (configInFlight || revoked()) return;
    const every = level && !configFailures ? CONFIG_EVERY_MS : backoff(CONFIG_RETRY_MS, configFailures);
    if (!configAt || Date.now() - configAt >= every) void refreshConfig();
  };

  const send = async (batch: MonitorFinding[]): Promise<SendOutcome> => {
    // The app's own model, with the app's own key: only the verdict travels with the finding.
    if (ownLlm && level) await judgeWithOwnLlm(batch, level, ownLlm).catch(() => 0);
    const t = withTimeout(REQUEST_TIMEOUT_MS);
    const outcome = await (async (): Promise<SendOutcome> => {
      try {
        const response = await fetch(`${base}/v1/monitor/findings`, { method: "POST", headers, body: JSON.stringify({ findings: batch }), signal: t.signal });
        if (response.ok) return "sent";
        const body = (await response.json().catch(() => ({}))) as { error?: string; resetAt?: string };
        if (response.status === 401) {
          if (!revoked()) report("AgentBeam App monitoring paused: this app token was rejected (rotated or removed). Checking again in 15 minutes.");
          revokedUntil = Date.now() + REVOKED_RECHECK_MS;
          return "drop";
        }
        if (response.status === 403) { level = null; return "drop"; }
        if (response.status === 429) { pausedUntil = pauseUntil(body.resetAt); return "drop"; }
        return response.status >= 500 ? "retry" : "drop";
      } catch {
        return "retry";
      } finally {
        t.done();
      }
    })();
    if (outcome === "retry") nextSendAt = Date.now() + backoff(flushEvery, ++sendFailures);
    else sendFailures = 0;
    return outcome;
  };

  const flush = (force = false): Promise<void> => {
    // A forced flush waits for one in flight, then sends what that one left (roll-ups still collecting).
    if (flushing) return force ? flushing.then(() => flush(true)) : flushing;
    if (!pipeline.pending.length && !(force && pipeline.rollingUp)) return Promise.resolve();
    const now = Date.now();
    if (!force && (now - lastFlush < flushEvery || now < nextSendAt)) return Promise.resolve();
    lastFlush = now;
    flushing = pipeline.flush(send, { force }).catch(() => {}).finally(() => { flushing = null; });
    return flushing;
  };

  const noteBudget = () => {
    if (Date.now() - budgetReportedAt < 60_000) return;
    const skipped = budget.takeSkipped() + localBudget.takeSkipped();
    budgetReportedAt = Date.now();
    if (skipped) report(`AgentBeam App monitoring skipped ${skipped} checks in the last minute to stay under ${percent}% of a CPU (maxCpuPercent).`);
  };

  const ingest = (line: string, file: string, ingestOptions?: Parameters<MonitorPipeline["ingestLine"]>[2]) => {
    try {
      ensureConfig();
      noteBudget();
      if (!level || revoked()) return;
      pipeline.ingestLine(line, file, ingestOptions);
      if (Date.now() - lastFlush >= flushEvery) void flush();
    } catch {
      /* never let monitoring affect the app */
    }
  };

  const llmText = (text: string, source: "prompt" | "output", info: PromptInfo | undefined): TextCheck => {
    const { result, window } = budgeted(text, source, source === "output" ? canaries : []);
    try {
      if (!window.trim()) return result;
      const client = String(info?.ip ?? info?.user ?? "").trim().slice(0, 80) || undefined;
      const label = typeof info?.label === "string" && info.label.trim() ? info.label.trim().slice(0, 60) : source === "prompt" ? "prompts" : "model output";
      // Clean prompts are still counted per sender, to spot floods.
      if (result.flagged || (source === "prompt" && client))
        ingest(window, label, { source, client, rules: source === "output" ? canaries : undefined, excerpt: options.excerpts !== false });
    } catch {
      /* never let monitoring affect the app */
    }
    return result;
  };

  // Each call goes through the same gate as request(): nothing is counted until the config says on.
  const guarded = (work: () => void) => {
    try {
      ensureConfig();
      if (!level || revoked()) return;
      work();
      if (Date.now() - lastFlush >= flushEvery) void flush();
    } catch {
      /* never let monitoring affect the app */
    }
  };
  const short = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : undefined);
  const outbound = (target: unknown) => {
    const text = typeof target === "string" ? target : target instanceof URL ? target.href : (target as { url?: unknown } | null)?.url;
    if (typeof text !== "string") return;
    // Beam's own reports aren't the app's traffic.
    if (text.startsWith(base) || text === url.host) return;
    guarded(() => { pipeline.outbound(text.slice(0, 2048)); });
  };
  if (options.watchOutbound === true) {
    const g = globalThis as { fetch: typeof fetch; __beamFetchWrapped?: boolean };
    if (!g.__beamFetchWrapped) {
      const original = g.fetch;
      g.fetch = function beamWatchedFetch(input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) {
        try { outbound(input); } catch { /* never in the way */ }
        return original.call(globalThis, input, init);
      } as typeof fetch;
      g.__beamFetchWrapped = true;
    }
  }

  void refreshConfig();
  return {
    enabled: true,
    event(type, info) {
      if (!["login.failed", "login.succeeded", "admin.granted", "apikey.created"].includes(type)) return;
      guarded(() => {
        pipeline.event(type, { ip: short(info?.ip, 64), user: short(info?.user, 80) }, short(info?.detail, 200) ?? "");
      });
    },
    usage(info) {
      const tokens = Number(info?.tokens);
      const who = short(info?.user, 80) ?? short(info?.ip, 64);
      if (!(tokens > 0) || !who) return;
      guarded(() => { pipeline.usage(who, Math.min(tokens, 1e9), short(info?.model, 80) ? `model=${short(info?.model, 80)}` : ""); });
    },
    outbound,
    request(info) {
      try {
        if (!info || typeof info.url !== "string") return;
        const text = (v: unknown, max: number) => (v === null || v === undefined || v === "" ? undefined : String(v).slice(0, max));
        const count = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.round(v) : undefined);
        const header = headerReader(info.headers);
        const country = text(info.country ?? header("x-vercel-ip-country") ?? header("cf-ipcountry") ?? header("cloudfront-viewer-country"), 2);
        // Same JSON shape as an access-log line, so the rules see method, path+query, client and agent.
        // The referrer isn't included: it's the page the visitor came from, usually this app's own.
        ingest(JSON.stringify({
          method: String(info.method || "GET").toUpperCase().slice(0, 16),
          path: info.url.slice(0, 8192),
          httpStatus: count(info.status),
          srcIp: text(info.ip, 64),
          clientUa: text(info.userAgent ?? header("user-agent"), 512),
          host: text(header("host"), 200),
          responseBytes: count(info.bytes),
          durationMs: count(info.durationMs),
          country: country && /^[A-Za-z]{2}$/.test(country) ? country.toUpperCase() : undefined,
          asn: count(info.asn),
          // Sent only by Next.js itself; from a client it's an attempt to skip middleware (CVE-2025-29927).
          "x-middleware-subrequest": text(header("x-middleware-subrequest"), 200),
        }), "requests");
      } catch {
        /* never let monitoring affect the app */
      }
    },
    log(line) {
      if (typeof line === "string" && line.trim()) ingest(line.slice(0, 16_384), "app log");
    },
    prompt: (text, info) => llmText(text, "prompt", info),
    output: (text, info) => llmText(text, "output", info),
    flush: (opts) => flush(Boolean(opts?.force)).catch(() => {}),
  };
}
