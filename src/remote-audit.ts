import { readIdentity } from "./enroll.js";
import { forwardAuditReport } from "./forward.js";
import { versionHeaders } from "./version.js";

// An administrator can queue a `beam audit` run for a device from the dashboard. The device finds
// it on its existing minute-long poll (GET /v1/device/update -- see remote-update.ts, same poll,
// same route), runs beam-audit's own checks, and POSTs the resulting report to /v1/audit
// (forwardAuditReport -- the same path a self-run `beam audit` uses). Fire-and-forget, same
// pattern as forwardScan: never blocks or fails the caller. A user running `beam audit` themselves
// is untouched by this -- that invocation never carries a requestedBy and never reaches here; this
// only answers a request an admin queued.
//
// An admin/owner queuing this wants the real thing, not the conservative local-only default: real
// API calls against installed agents to verify blocking behavior (--live), external evidence
// queries including credentialed MCP introspection (--online), and the whole machine, not just the
// home directory (--whole-pc) -- deliberately NOT --full, which also launches a visible VS Code
// window and writes beam-audit-report.html/.json to disk. Neither belongs on someone else's
// machine from an unattended background poll: nothing is written here, and nothing opens on
// screen. Only the structured report leaves the device, over the same channel every other
// beam-audit run already uses.
export type RemoteAuditResult = { status: "none" | "ran" | "failed"; reason?: string };

export type RemoteAuditDeps = { runAudit?: (argv: string[]) => Promise<{ generatedAt: string; platform: string; checks: unknown[]; matrices: unknown[] }> };

export async function runRemoteAudit(deps: RemoteAuditDeps = {}): Promise<RemoteAuditResult> {
  const identity = await readIdentity();
  if (!identity) return { status: "none" };
  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${identity.deviceSecret}`, ...versionHeaders() };
  let requested = false;
  let requestedBy: string | undefined;
  try {
    const response = await fetch(`${identity.apiBase}/v1/device/update`, { headers, signal: AbortSignal.timeout(8000) });
    if (!response.ok) return { status: "failed", reason: `Audit poll returned HTTP ${response.status}` };
    const data = (await response.json()) as { auditRequested?: boolean; auditRequestedBy?: string };
    requested = Boolean(data.auditRequested);
    requestedBy = data.auditRequestedBy;
  } catch (error) { return { status: "failed", reason: `Audit poll failed: ${error instanceof Error ? error.message : String(error)}` }; }
  if (!requested) return { status: "none" };

  // beam-audit sets process.exitCode on its own when it finds a failing check -- harmless for its
  // own one-shot CLI, but this runs inside the long-lived background service process, so that
  // would silently change the service's eventual exit code for an unrelated reason. Restore it.
  const previousExitCode = process.exitCode;
  try {
    const run = deps.runAudit ?? (await import("beam-audit")).runAudit;
    const report = await run(["--live", "--online", "--whole-pc"]);
    const forwarded = await forwardAuditReport(report, requestedBy);
    if (!forwarded.sent) return { status: "failed", reason: forwarded.reason };
    return { status: "ran" };
  } catch (error) {
    return { status: "failed", reason: (error instanceof Error ? error.message : String(error)).slice(0, 300) };
  } finally {
    process.exitCode = previousExitCode;
  }
}
