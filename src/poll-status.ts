import { readFile, mkdir, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import { getDataDirectory } from "./config.js";
import { readIdentity } from "./enroll.js";
import { versionHeaders } from "./version.js";
type State = { pid?: number; lastPoll?: string; nextPoll?: string; audit?: string; update?: string };
let state: State = {};
let writes = Promise.resolve();
export function recordPollStatus(patch: State): Promise<void> {
  state = { ...state, ...patch };
  const snapshot = JSON.stringify(state);
  writes = writes.catch(() => {}).then(async () => {
    const dir = getDataDirectory();
    await mkdir(dir, { recursive: true });
    const target = join(dir, "poll-status.json");
    const temp = `${target}.${process.pid}.tmp`;
    await writeFile(temp, snapshot, { mode: 0o600 });
    await rename(temp, target);
  });
  return writes.catch(() => {});
}
export async function printPollStatus(): Promise<void> {
  let saved: State = {};
  try { saved = JSON.parse(await readFile(join(getDataDirectory(), "poll-status.json"), "utf8")); } catch {}
  let alive = false;
  if (saved.pid) try { process.kill(saved.pid, 0); alive = true; } catch {}
  const fresh = alive && !!saved.lastPoll && Date.now() - Date.parse(saved.lastPoll) < 150_000;
  console.log(`Background polling: ${fresh ? "active" : "unknown or stale — service heartbeat delayed or stopped"}`);
  console.log(`Last poll: ${saved.lastPoll ?? "unknown"}`);
  console.log(`Next scheduled poll: ${fresh ? saved.nextPoll ?? "unknown" : "unknown"}`);
  const identity = await readIdentity();
  if (!identity) return;
  console.log(`Device: ${identity.hostname} (${identity.deviceId})`);
  console.log(`Collector: ${identity.apiBase}`);
  try {
    const response = await fetch(`${identity.apiBase}/v1/device/update`, { headers: { Authorization: `Bearer ${identity.deviceSecret}`, ...versionHeaders() }, signal: AbortSignal.timeout(8000) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json() as { auditRequested?: boolean; update?: { version?: string } };
    console.log("Collector connection: connected (authenticated)");
    console.log(`Audit: ${alive && saved.audit === "running" ? (fresh ? "running" : "last reported running; heartbeat stale, completion unconfirmed") : data.auditRequested ? "queued (or running on a service without diagnostics)" : "no request queued"}`);
    console.log(`Last audit status: ${saved.audit ?? "unknown"}${fresh ? "" : " (historical)"}`);
    console.log(`Update queue: ${data.update?.version ?? "none"}`);
    console.log(`Last update status: ${saved.update ?? "unknown"}`);
  } catch (error) { console.log(`Collector connection: failed (${error instanceof Error ? error.message : String(error)})`); }
}
