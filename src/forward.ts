import { mkdir, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { getApiUrl, getDataDirectory } from "./config.js";
import { lastGoodPolicyPath } from "./policy.js";
import { readIdentity, type Identity } from "./enroll.js";
import type { Event, Scan } from "./core.js";
import type { McpInventory } from "./mcp-config.js";
import type { SkillReport } from "./skill-sync.js";
import { versionHeaders } from "./version.js";

function policyPath(): string {
  return join(getDataDirectory(), "policy.json");
}

// Like other identity-authenticated calls, this must hit the enrolled device's own
// identity.apiBase -- not a separately configured URL -- otherwise a device enrolled against a
// non-default workspace API (self-hosted, staging, a local dev dashboard) silently forwards
// events to the wrong place while `beam whoami`/`beam account` and policy sync (which do use
// identity.apiBase) keep reporting the device as enrolled and healthy.
export async function forwardEvents(events: Event | Event[], expected?: Pick<Identity, "deviceId" | "orgId" | "apiBase">): Promise<boolean> {
  const identity = await readIdentity();
  if (!identity) return false;
  if (expected && (identity.deviceId !== expected.deviceId || identity.orgId !== expected.orgId || identity.apiBase !== expected.apiBase)) return false;
  try {
    const response = await fetch(`${identity.apiBase}/v1/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${identity.deviceSecret}`,
      },
      body: JSON.stringify(events),
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return true;
  } catch (error) {
    console.error(`Beam workspace event delivery failed: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

export interface ForwardMcpInventoryResult { ok: boolean; reason?: string }

// Unlike every other call in this file, this deliberately does NOT use identity.apiBase (the
// dashboard host, app.agentbeam.com by default). As of now /v1/mcp/inventory only exists on the
// dedicated collector API (collector.agentbeam.com, getApiUrl()'s default) -- the dashboard
// carries the account/policy/enterprise-package surface but hasn't picked up this route yet. If
// that changes and the dashboard gains this route (or proxies it), this can go back to
// identity.apiBase like the rest of this file.
export async function forwardMcpInventory(servers: McpInventory[]): Promise<ForwardMcpInventoryResult> {
  if (!servers.length) return { ok: true };
  const identity = await readIdentity();
  if (!identity) return { ok: false, reason: "This device isn't connected to a Beam workspace." };
  const collectorBase = getApiUrl();
  try {
    const response = await fetch(`${collectorBase}/v1/mcp/inventory`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${identity.deviceSecret}` },
      body: JSON.stringify({ servers }), signal: AbortSignal.timeout(5000),
    });
    if (response.ok) return { ok: true };
    // 404 means a collector deployment that predates this route; anything else (401/403/5xx) is
    // a real problem worth surfacing rather than folding into the same generic message.
    const reason = response.status === 404
      ? "This workspace's collector doesn't support MCP inventory yet."
      : `Collector responded with HTTP ${response.status}.`;
    return { ok: false, reason };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, reason: `Could not reach ${collectorBase}: ${message}` };
  }
}

// Same host and auth as MCP inventory: the dedicated collector, keyed by the device secret.
export async function forwardSkillInventory(report: SkillReport): Promise<ForwardMcpInventoryResult> {
  const identity = await readIdentity();
  if (!identity) return { ok: false, reason: "This device isn't connected to a Beam workspace." };
  const collectorBase = getApiUrl();
  try {
    const response = await fetch(`${collectorBase}/v1/skills/inventory`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${identity.deviceSecret}` },
      body: JSON.stringify(report), signal: AbortSignal.timeout(15_000),
    });
    if (response.ok) return { ok: true };
    return { ok: false, reason: response.status === 404 ? "This workspace's collector doesn't support skill inventory yet." : `Collector responded with HTTP ${response.status}.` };
  } catch (error) {
    return { ok: false, reason: `Could not reach ${collectorBase}: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export const FORWARD_BATCH_SIZE = 6;
export const FORWARD_FLUSH_MS = 10_000;

// Persist before acknowledging local ingest. Delivery failures and process restarts leave
// events in this outbox; the remote (orgId, dedupeKey) constraint makes retries idempotent.
// Each envelope is bound to the enrolled device so re-enrollment cannot send old activity
// into a different workspace. Only already-normalized, redacted events enter this queue.
export class ForwardQueue {
  private flushTimer: NodeJS.Timeout | undefined;
  private writing: Promise<void> = Promise.resolve();
  private flushing: Promise<void> | undefined;
  private stopped = false;
  private readonly directory: string;

  constructor(directory = getDataDirectory()) {
    this.directory = join(directory, "event-outbox");
    this.scheduleFlush();
  }

  push(events: Event[]): Promise<void> {
    const write = this.writing.then(async () => {
      if (!events.length) return;
      const identity = await readIdentity();
      if (!identity) return;
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      for (let i = 0; i < events.length; i += FORWARD_BATCH_SIZE) {
        const name = `${Date.now()}-${randomUUID()}`;
        const temp = join(this.directory, `${name}.tmp`);
        const envelope = { deviceId: identity.deviceId, orgId: identity.orgId, apiBase: identity.apiBase, events: events.slice(i, i + FORWARD_BATCH_SIZE) };
        try {
          await writeFile(temp, JSON.stringify(envelope), { mode: 0o600, flag: "wx" });
          await rename(temp, join(this.directory, `${name}.json`));
        } finally { await rm(temp, { force: true }); }
      }
    });
    this.writing = write.catch(() => {});
    return write.then(() => {
      if (events.length >= FORWARD_BATCH_SIZE) void this.flush();
    });
  }

  private scheduleFlush(): void {
    if (this.stopped || this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined;
      void this.flush();
    }, FORWARD_FLUSH_MS);
    this.flushTimer.unref?.();
  }

  flush(): Promise<void> {
    if (this.flushing) return this.flushing;
    if (this.flushTimer) { clearTimeout(this.flushTimer); this.flushTimer = undefined; }
    this.flushing = this.deliver().catch(error => {
      console.error(`Beam event outbox: ${error instanceof Error ? error.message : String(error)}`);
    }).finally(() => { this.flushing = undefined; this.scheduleFlush(); });
    return this.flushing;
  }

  close(): Promise<void> {
    this.stopped = true;
    return this.flush();
  }

  private async deliver(): Promise<void> {
    await this.writing;
    const identity = await readIdentity();
    if (!identity) return;
    let files: string[];
    try { files = await readdir(this.directory); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return; throw error; }
    let attempted = 0;
    let pending: Event[] = [];
    let paths: string[] = [];
    const send = async (): Promise<boolean> => {
      if (!pending.length) return true;
      if (!await forwardEvents(pending, identity)) return false;
      for (const path of paths) await rm(path, { force: true });
      pending = []; paths = [];
      return true;
    };
    for (const name of files.filter(n => /^\d+-[\da-f-]+\.json$/.test(n)).sort()) {
      const path = join(this.directory, name);
      const envelope = JSON.parse(await readFile(path, "utf8"));
      if (envelope.deviceId !== identity.deviceId || envelope.orgId !== identity.orgId || envelope.apiBase !== identity.apiBase) continue;
      if (attempted++ >= 100) break;
      if (pending.length + envelope.events.length > FORWARD_BATCH_SIZE && !await send()) return;
      pending.push(...envelope.events); paths.push(path);
      if (pending.length >= FORWARD_BATCH_SIZE && !await send()) return;
    }
    await send();
  }
}

// Fire-and-forget: forwarding a local skill/MCP scan must never block or fail the caller.
export async function forwardScan(scan: Scan): Promise<void> {
  const identity = await readIdentity();
  if (!identity) return;
  try {
    await fetch(`${identity.apiBase}/v1/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${identity.deviceSecret}`,
      },
      body: JSON.stringify(scan),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    /* offline / unreachable — the local collector still has the record */
  }
}

// Fire-and-forget: forwarding a review toggle must never block or fail the caller.
export async function forwardReview(id: string, reviewed: boolean): Promise<void> {
  const identity = await readIdentity();
  if (!identity) return;
  try {
    await fetch(`${identity.apiBase}/v1/ingest`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${identity.deviceSecret}`,
      },
      body: JSON.stringify({ id, reviewed }),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    /* offline / unreachable — the local collector still has the record */
  }
}

export interface PolicySyncResult {
  status: "updated" | "unchanged" | "not-enrolled" | "unreachable";
  version?: number;
  path?: string;
}

// Pull the current policy bundle and cache it locally for the hook to enforce.
export async function syncPolicy(): Promise<PolicySyncResult> {
  const identity = await readIdentity();
  if (!identity) return { status: "not-enrolled" };

  let response: Response;
  try {
    response = await fetch(`${identity.apiBase}/v1/policy`, {
      headers: { Authorization: `Bearer ${identity.deviceSecret}`, ...versionHeaders() },
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    return { status: "unreachable" };
  }
  if (response.status === 304) return { status: "unchanged" };
  if (!response.ok) return { status: "unreachable" };

  const bundle = await response.json();
  const path = policyPath();
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const contents = `${JSON.stringify(bundle, null, 2)}\n`;
  const temp = `${path}.tmp`;
  await writeFile(temp, contents, { mode: 0o600 });
  await rename(temp, path);
  await writeFile(lastGoodPolicyPath(), contents, { mode: 0o600 });
  return { status: "updated", version: bundle.version, path };
}
