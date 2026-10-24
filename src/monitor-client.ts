// Calls to the workspace's App monitoring API. Like the rest of the device API these go to the
// enrolled identity.apiBase, authenticated with the device secret. The server decides whether
// this workspace has App monitoring turned on; nothing is sent until it says yes.
import { readIdentity, type Identity } from "./enroll.js";
import { getDashboardUrl } from "./config.js";
import type { InstalledPackage } from "./lockfiles.js";
import type { RequestMeta, RequestOutcome } from "./monitor-rules.js";

/** What the App monitoring API needs: where to send, and the secret to send with. */
export type MonitorAuth = Pick<Identity, "apiBase" | "deviceSecret">;

/**
 * An app token (BEAM_APP_TOKEN, created per app under App monitoring > Settings, apps and alerts) for
 * servers, containers and CI; otherwise this machine's own connection from 'beam connect'.
 */
export async function monitorAuth(env: NodeJS.ProcessEnv = process.env): Promise<MonitorAuth | null> {
  const token = env.BEAM_APP_TOKEN?.trim();
  if (token) {
    if (!/^beam_app_[\w-]{40,}$/.test(token)) throw new Error("BEAM_APP_TOKEN doesn't look like an app token (beam_app_…). Copy it again from App monitoring > Settings, apps and alerts in the dashboard.");
    const apiBase = getDashboardUrl();
    // A bearer token over plain HTTP can be read on the wire; only loopback (local testing) is exempt.
    const url = new URL(apiBase);
    if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
      throw new Error(`Refusing to send BEAM_APP_TOKEN to ${apiBase} over plain HTTP. Use an https:// BEAM_DASHBOARD_URL.`);
    return { deviceSecret: token, apiBase };
  }
  return readIdentity();
}

export type MonitorLevel = "light" | "standard" | "strict";
export type MonitorSeverity = "critical" | "high" | "medium" | "low";
export interface MonitorUsage { findings: number; cveChecks: number; llmChecks: number }
export interface MonitorConfig {
  enabled: true; app: string | null; level: MonitorLevel; llm: boolean; webhooks: number;
  usage: MonitorUsage; limits: MonitorUsage; resetAt: string; settingsUrl: string;
}
export interface MonitorFinding {
  id: string; ruleId: string; title: string; severity: MonitorSeverity; category?: string;
  source: "log" | "http" | "cve"; file?: string; evidence: string; count: number; firstSeen: string;
  /** Verdict from the user's own LLM (BEAM_LLM_*), when one is configured on this machine. */
  llm?: { verdict: "malicious" | "suspicious" | "benign" | "declined" | "error"; reason: string; model: string };
  /** The flagged request (traffic findings): client, agent, path, response status and what became of it. Redacted. */
  request?: RequestMeta & { ip?: string; outcome: RequestOutcome };
  /** Set on a roll-up: many requests that matched a rule but couldn't have worked, sent as one finding. */
  rollup?: MonitorRollup;
}
/**
 * Requests that matched one rule but were refused (3xx/4xx) or aimed at software the app doesn't
 * run, over a few minutes. Sent as one low-severity finding instead of one per address, so a
 * botnet's scan shows up as one campaign and doesn't spend the month's allowance or page anyone.
 */
export interface MonitorRollup {
  outcome: "blocked" | "not_applicable";
  requests: number;
  /** Distinct client addresses (counted up to 10,000). */
  addresses: number;
  from: string; to: string;
  statuses: Record<string, number>;
  /** The busiest addresses, with what each sent last. */
  clients: { ip: string; count: number; status?: number; path?: string; userAgent?: string; country?: string; asn?: number }[];
  paths: { path: string; count: number }[];
  userAgents: { userAgent: string; count: number }[];
  countries: { country: string; count: number }[];
}
export interface Vulnerability {
  id: string; slug: string; url: string; title: string; severity: string; kev: boolean; epss: number | null;
  ecosystem: string; name: string; version: string; vulnerable: string; patched: string | null; files: string[];
}
export interface CveCheckResult {
  checked: number; vulnerabilities: Vulnerability[]; database: { generatedAt: string; advisories: number };
  remaining: number; resetAt: string;
}

// Everything that isn't a success, normalized so callers only branch on what to do next.
export type ApiFailure = { ok: false; message: string } & (
  | { status: "disabled" } // feature not granted or turned off in the dashboard
  | { status: "quota"; resetAt?: string } // monthly allowance used up
  | { status: "revoked" }
  | { status: "unsupported" } // workspace API predates App monitoring
  | { status: "unreachable" } // network/5xx: retry later
);

async function call(identity: MonitorAuth, path: string, init: RequestInit = {}): Promise<{ ok: true; body: unknown } | ApiFailure> {
  let response: Response;
  try {
    response = await fetch(`${identity.apiBase}${path}`, {
      ...init,
      headers: { ...(init.body ? { "Content-Type": "application/json" } : {}), Authorization: `Bearer ${identity.deviceSecret}` },
      signal: AbortSignal.timeout(20_000),
    });
  } catch (error) {
    return { ok: false, status: "unreachable", message: `Could not reach ${identity.apiBase}: ${error instanceof Error ? error.message : String(error)}` };
  }
  let body: { error?: string; resetAt?: string } & Record<string, unknown> = {};
  try { body = (await response.json()) as typeof body; } catch { /* empty or non-JSON body */ }
  if (response.ok) return { ok: true, body };
  const message = typeof body.error === "string" ? body.error : `${identity.apiBase} responded with HTTP ${response.status}.`;
  if (response.status === 403) return { ok: false, status: "disabled", message };
  if (response.status === 429) return { ok: false, status: "quota", message, resetAt: typeof body.resetAt === "string" ? body.resetAt : undefined };
  if (response.status === 401)
    return {
      ok: false,
      status: "revoked",
      message: identity.deviceSecret.startsWith("beam_app_")
        ? `This app token was rotated or removed, or its app was deleted. Copy the current token from ${getDashboardUrl()}/dashboard/monitoring/settings#apps into BEAM_APP_TOKEN.`
        : "This device was revoked or is unknown to the workspace. Run 'beam connect' again.",
    };
  if (response.status === 404 || response.status === 405)
    return { ok: false, status: "unsupported", message: `${identity.apiBase} doesn't support App monitoring yet.` };
  return { ok: false, status: "unreachable", message };
}

export async function fetchMonitorConfig(identity: MonitorAuth): Promise<{ ok: true; config: MonitorConfig } | ApiFailure> {
  const result = await call(identity, "/v1/monitor/config");
  return result.ok ? { ok: true, config: result.body as MonitorConfig } : result;
}

export async function sendFindings(identity: MonitorAuth, findings: MonitorFinding[]): Promise<{ ok: true; accepted: number; dropped: number } | ApiFailure> {
  const result = await call(identity, "/v1/monitor/findings", { method: "POST", body: JSON.stringify({ findings }) });
  if (!result.ok) return result;
  const body = result.body as { accepted?: number; dropped?: number };
  return { ok: true, accepted: body.accepted ?? 0, dropped: body.dropped ?? 0 };
}

export async function checkPackages(identity: MonitorAuth, packages: InstalledPackage[]): Promise<{ ok: true; result: CveCheckResult } | ApiFailure> {
  const result = await call(identity, "/v1/cve/check", { method: "POST", body: JSON.stringify({ packages }) });
  return result.ok ? { ok: true, result: result.body as CveCheckResult } : result;
}
