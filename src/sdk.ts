// AgentBeam App monitoring inside your app: `import { createAppMonitor } from "@agent-beam/beam/monitor"`.
//
// The in-process alternative to running `beam monitor` next to an app. Hand it each request
// (Next.js middleware, an Express/Fastify hook) and, optionally, log lines. Detection runs right
// here with the same rules as the CLI; only redacted findings leave the process, in batches,
// authenticated with the app's least-privilege BEAM_APP_TOKEN.
//
// It never throws, never blocks or alters a request, and never makes a request wait on the
// network: findings are sent in the background (pass flush() to event.waitUntil in middleware).
// If AgentBeam is unreachable, App monitoring is off for the workspace, or the monthly allowance
// is spent, findings are dropped and the app doesn't notice. No dependencies and no Node.js
// built-ins, so it runs in edge runtimes too.
import type { MonitorFinding, MonitorLevel } from "./monitor-client.js";
import { MonitorPipeline, type SendOutcome } from "./monitor-pipeline.js";

export interface AppMonitorOptions {
  /** The app's token from the dashboard (App monitoring > Apps). Default: BEAM_APP_TOKEN. */
  token?: string;
  /** Default: BEAM_DASHBOARD_URL, else https://app.agentbeam.com. Must be https (localhost excepted). */
  dashboardUrl?: string;
  /** How often pending findings are sent, at most. Default 5000 ms. */
  flushIntervalMs?: number;
  /** Diagnostics (misconfiguration, App monitoring turned off, revoked token). Silent by default. */
  onError?: (message: string) => void;
}

export interface RequestInfo {
  method: string;
  /** Path and query string, e.g. request.nextUrl.pathname + request.nextUrl.search. */
  url: string;
  ip?: string | null;
  userAgent?: string | null;
  status?: number | null;
}

export interface AppMonitor {
  /** Check one incoming request. Cheap and synchronous; never throws. */
  request(info: RequestInfo): void;
  /** Check one application log line (errors, auth failures, anything the app prints). */
  log(line: string): void;
  /** Send pending findings now. Resolves when done; never rejects. */
  flush(): Promise<void>;
  /** False when there's no valid token or it was revoked: every call is then a no-op. */
  readonly enabled: boolean;
}

const TOKEN = /^beam_app_[\w-]{40,}$/;
const CONFIG_EVERY_MS = 5 * 60 * 1000;
const CONFIG_RETRY_MS = 60 * 1000;

function env(name: string): string | undefined {
  const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  return p?.env?.[name]?.trim() || undefined;
}

function withTimeout(ms: number): { signal: AbortSignal; done: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, done: () => clearTimeout(timer) };
}

const noop: AppMonitor = { request() {}, log() {}, flush: async () => {}, enabled: false };

export function createAppMonitor(options: AppMonitorOptions = {}): AppMonitor {
  const report = (message: string) => { try { options.onError?.(message); } catch { /* never throw */ } };
  const token = options.token?.trim() || env("BEAM_APP_TOKEN");
  if (!token || !TOKEN.test(token)) {
    report("AgentBeam App monitoring is off: set BEAM_APP_TOKEN to the app's token (beam_app_…) from the dashboard.");
    return noop;
  }
  const base = (options.dashboardUrl || env("BEAM_DASHBOARD_URL") || "https://app.agentbeam.com").replace(/\/+$/, "");
  let url: URL;
  try { url = new URL(base); } catch { report(`AgentBeam App monitoring is off: ${base} isn't a valid URL.`); return noop; }
  if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
    report("AgentBeam App monitoring is off: refusing to send the app token over plain HTTP.");
    return noop;
  }

  const flushEvery = Math.max(1000, options.flushIntervalMs ?? 5000);
  const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
  let level: MonitorLevel | null = null;
  let revoked = false;
  let pausedUntil = 0;
  let configAt = 0;
  let configInFlight = false;
  let lastFlush = 0;
  let flushing: Promise<void> | null = null;

  const pipeline = new MonitorPipeline({ level: () => (!revoked && Date.now() >= pausedUntil ? level : null) });

  const refreshConfig = async () => {
    configInFlight = true;
    const t = withTimeout(10_000);
    try {
      const response = await fetch(`${base}/v1/monitor/config`, { headers, signal: t.signal });
      const body = (await response.json().catch(() => ({}))) as { level?: MonitorLevel; error?: string; resetAt?: string };
      if (response.ok) level = body.level ?? "standard";
      else if (response.status === 401) { revoked = true; report("AgentBeam App monitoring stopped: this app token was rotated or removed."); }
      else if (response.status === 403) { level = null; report(body.error ?? "AgentBeam App monitoring is turned off for this workspace."); }
      else if (response.status === 429) pausedUntil = body.resetAt ? Date.parse(body.resetAt) : Date.now() + 60_000;
    } catch {
      /* unreachable: keep the last known level and try again later */
    } finally {
      t.done();
      configAt = Date.now();
      configInFlight = false;
    }
  };

  const ensureConfig = () => {
    if (revoked || configInFlight) return;
    const every = level ? CONFIG_EVERY_MS : CONFIG_RETRY_MS;
    if (!configAt || Date.now() - configAt >= every) void refreshConfig();
  };

  const send = async (batch: MonitorFinding[]): Promise<SendOutcome> => {
    const t = withTimeout(10_000);
    try {
      const response = await fetch(`${base}/v1/monitor/findings`, { method: "POST", headers, body: JSON.stringify({ findings: batch }), signal: t.signal });
      if (response.ok) return "sent";
      const body = (await response.json().catch(() => ({}))) as { error?: string; resetAt?: string };
      if (response.status === 401) { revoked = true; report("AgentBeam App monitoring stopped: this app token was rotated or removed."); return "drop"; }
      if (response.status === 403) { level = null; return "drop"; }
      if (response.status === 429) { pausedUntil = body.resetAt ? Date.parse(body.resetAt) : Date.now() + 60_000; return "drop"; }
      return response.status >= 500 ? "retry" : "drop";
    } catch {
      return "retry";
    } finally {
      t.done();
    }
  };

  const flush = (): Promise<void> => {
    if (flushing) return flushing;
    if (!pipeline.pending.length) return Promise.resolve();
    lastFlush = Date.now();
    flushing = pipeline.flush(send).catch(() => {}).finally(() => { flushing = null; });
    return flushing;
  };

  const ingest = (line: string, file: string) => {
    try {
      ensureConfig();
      if (!level || revoked) return;
      pipeline.ingestLine(line, file);
      if (Date.now() - lastFlush >= flushEvery) void flush();
    } catch {
      /* never let monitoring affect the app */
    }
  };

  void refreshConfig();
  return {
    enabled: true,
    request(info) {
      if (!info || typeof info.url !== "string") return;
      // Same JSON shape as an access-log line, so the rules see method, path+query, client and agent.
      ingest(JSON.stringify({
        method: String(info.method || "GET").toUpperCase().slice(0, 16),
        path: info.url.slice(0, 8192),
        httpStatus: info.status ?? undefined,
        srcIp: info.ip ?? undefined,
        clientUa: info.userAgent?.slice(0, 512) ?? undefined,
      }), "requests");
    },
    log(line) {
      if (typeof line === "string" && line.trim()) ingest(line.slice(0, 16_384), "app log");
    },
    flush: () => flush().catch(() => {}),
  };
}
