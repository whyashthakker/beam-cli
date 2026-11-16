import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readIdentity } from "./enroll.js";
import { versionHeaders } from "./version.js";

// An administrator can queue a `beam audit` run for a device from the dashboard. The device finds
// it on its existing minute-long poll (GET /v1/device/update -- see remote-update.ts, same poll,
// same route), runs beam-audit's own checks against the user's home directory, and POSTs the
// resulting report to /v1/audit. Fire-and-forget, same pattern as forwardScan: never blocks or
// fails the caller. A user running `beam audit` themselves is untouched by this -- that invocation
// never carries a requestedBy and never reaches here; this only answers a request an admin queued.
export type RemoteAuditResult = { status: "none" | "ran" | "failed"; reason?: string };

export type RemoteAuditDeps = { runAudit?: (argv: string[]) => Promise<void> };

export async function runRemoteAudit(deps: RemoteAuditDeps = {}): Promise<RemoteAuditResult> {
  const identity = await readIdentity();
  if (!identity) return { status: "none" };
  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${identity.deviceSecret}`, ...versionHeaders() };
  let requested = false;
  let requestedBy: string | undefined;
  try {
    const response = await fetch(`${identity.apiBase}/v1/device/update`, { headers, signal: AbortSignal.timeout(8000) });
    if (!response.ok) return { status: "none" }; // a collector from before this route
    const data = (await response.json()) as { auditRequested?: boolean; auditRequestedBy?: string };
    requested = Boolean(data.auditRequested);
    requestedBy = data.auditRequestedBy;
  } catch { return { status: "none" }; }
  if (!requested) return { status: "none" };

  const dir = await mkdtemp(join(tmpdir(), "beam-audit-remote-"));
  const jsonPath = join(dir, "report.json");
  // beam-audit sets process.exitCode on its own when it finds a failing check -- harmless for its
  // own one-shot CLI, but this runs inside the long-lived background service process, so that
  // would silently change the service's eventual exit code for an unrelated reason. Restore it.
  const previousExitCode = process.exitCode;
  try {
    const run = deps.runAudit ?? (await import("beam-audit")).runAudit;
    await run(["--json", jsonPath]);
    const raw = JSON.parse(await readFile(jsonPath, "utf8")) as { generatedAt: string; platform?: string; checks: unknown[]; matrices?: unknown[] };
    const payload = { id: randomUUID(), generatedAt: raw.generatedAt, platform: raw.platform, checks: raw.checks, matrices: raw.matrices, requestedBy };
    const posted = await fetch(`${identity.apiBase}/v1/audit`, { method: "POST", headers, body: JSON.stringify(payload), signal: AbortSignal.timeout(60_000) });
    if (!posted.ok) return { status: "failed", reason: `Collector returned ${posted.status}.` };
    return { status: "ran" };
  } catch (error) {
    return { status: "failed", reason: (error instanceof Error ? error.message : String(error)).slice(0, 300) };
  } finally {
    process.exitCode = previousExitCode;
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}
