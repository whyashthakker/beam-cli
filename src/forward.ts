import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { getDataDirectory } from "./config.js";
import { readIdentity } from "./enroll.js";
import type { Event } from "./core.js";

function policyPath(): string {
  return join(getDataDirectory(), "policy.json");
}

// Fire-and-forget: forwarding to the workspace must never block or fail the agent.
export async function forwardEvents(events: Event | Event[]): Promise<void> {
  const identity = await readIdentity();
  if (!identity) return;
  try {
    await fetch(`${identity.apiBase}/v1/ingest`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${identity.deviceSecret}`,
      },
      body: JSON.stringify(events),
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
      headers: { Authorization: `Bearer ${identity.deviceSecret}` },
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
  await writeFile(path, `${JSON.stringify(bundle, null, 2)}\n`, { mode: 0o600 });
  return { status: "updated", version: bundle.version, path };
}
