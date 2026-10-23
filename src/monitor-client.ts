// Calls to the workspace's App monitoring API. Like the rest of the device API these go to the
// enrolled identity.apiBase, authenticated with the device secret. The server decides whether
// this workspace has App monitoring turned on; nothing is sent until it says yes.
import type { Identity } from "./enroll.js";
import type { InstalledPackage } from "./lockfiles.js";

export type MonitorLevel = "light" | "standard" | "strict";
export type MonitorSeverity = "critical" | "high" | "medium" | "low";
export interface MonitorUsage { findings: number; cveChecks: number; llmChecks: number }
export interface MonitorConfig {
  enabled: true; level: MonitorLevel; llm: boolean; webhooks: number;
  usage: MonitorUsage; limits: MonitorUsage; resetAt: string; settingsUrl: string;
}
export interface MonitorFinding {
  id: string; ruleId: string; title: string; severity: MonitorSeverity; category?: string;
  source: "log" | "http" | "cve"; file?: string; evidence: string; count: number; firstSeen: string;
  /** Verdict from the user's own LLM (BEAM_LLM_*), when one is configured on this machine. */
  llm?: { verdict: "malicious" | "suspicious" | "benign" | "declined" | "error"; reason: string; model: string };
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

async function call(identity: Identity, path: string, init: RequestInit = {}): Promise<{ ok: true; body: unknown } | ApiFailure> {
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
  if (response.status === 401) return { ok: false, status: "revoked", message: "This device was revoked or is unknown to the workspace. Run 'beam connect' again." };
  if (response.status === 404 || response.status === 405)
    return { ok: false, status: "unsupported", message: `${identity.apiBase} doesn't support App monitoring yet.` };
  return { ok: false, status: "unreachable", message };
}

export async function fetchMonitorConfig(identity: Identity): Promise<{ ok: true; config: MonitorConfig } | ApiFailure> {
  const result = await call(identity, "/v1/monitor/config");
  return result.ok ? { ok: true, config: result.body as MonitorConfig } : result;
}

export async function sendFindings(identity: Identity, findings: MonitorFinding[]): Promise<{ ok: true; accepted: number; dropped: number } | ApiFailure> {
  const result = await call(identity, "/v1/monitor/findings", { method: "POST", body: JSON.stringify({ findings }) });
  if (!result.ok) return result;
  const body = result.body as { accepted?: number; dropped?: number };
  return { ok: true, accepted: body.accepted ?? 0, dropped: body.dropped ?? 0 };
}

export async function checkPackages(identity: Identity, packages: InstalledPackage[]): Promise<{ ok: true; result: CveCheckResult } | ApiFailure> {
  const result = await call(identity, "/v1/cve/check", { method: "POST", body: JSON.stringify({ packages }) });
  return result.ok ? { ok: true, result: result.body as CveCheckResult } : result;
}
