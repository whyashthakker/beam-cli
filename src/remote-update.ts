import { readIdentity } from "./enroll.js";
import { compareVersions, installKind, npmInstall, readUpdateState, writeUpdateState, type InstallKind } from "./auto-update.js";
import { beamVersion, versionHeaders } from "./version.js";

// An administrator can queue an update for a device from the dashboard. The device finds it on its
// minute-long poll (GET /v1/device/update), installs that exact version the way background
// auto-update does -- npm only, never asking for sudo -- and reports how it went. The workspace
// learns the new version from the next poll. A failed install is not retried for 30 minutes.
// Turn it off on a device with BEAM_REMOTE_UPDATE=0.
const RETRY_AFTER_MS = 30 * 60_000;

export type RemoteUpdateResult = { status: "none" | "current" | "updated" | "failed" | "waiting"; version?: string; reason?: string };

export const remoteUpdateEnabled = (env = process.env) => !["0", "false", "off", "no"].includes(String(env.BEAM_REMOTE_UPDATE ?? "").trim().toLowerCase());

export type RemoteUpdateDeps = { current?: string; kind?: InstallKind; install?: (version: string) => Promise<void>; statePath?: string; now?: number };

export async function runRemoteUpdate(deps: RemoteUpdateDeps = {}): Promise<RemoteUpdateResult> {
  if (!remoteUpdateEnabled()) return { status: "none" };
  const identity = await readIdentity();
  if (!identity) return { status: "none" };
  const current = deps.current ?? beamVersion();
  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${identity.deviceSecret}`, ...versionHeaders() };
  let version: string | undefined;
  try {
    const response = await fetch(`${identity.apiBase}/v1/device/update`, { headers, signal: AbortSignal.timeout(8000) });
    if (!response.ok) return { status: "none" }; // a collector from before this route
    version = ((await response.json()) as { update?: { version?: string } | null }).update?.version;
  } catch { return { status: "none" }; }
  if (!version || !/^\d+\.\d+\.\d+$/.test(version)) return { status: "none" };
  if (compareVersions(version, current) <= 0) return { status: "current", version };

  const state = await readUpdateState(deps.statePath);
  const now = deps.now ?? Date.now();
  if (state.remoteAttempt?.version === version && now - Date.parse(state.remoteAttempt.at) < RETRY_AFTER_MS) return { status: "waiting", version };
  await writeUpdateState({ ...state, remoteAttempt: { version, at: new Date(now).toISOString() } }, deps.statePath);

  const report = (ok: boolean, reason?: string) => fetch(`${identity.apiBase}/v1/device/update-result`, { method: "POST", headers, body: JSON.stringify({ version, ok, reason }), signal: AbortSignal.timeout(8000) }).catch(() => {});
  const kind = deps.kind ?? installKind();
  if (kind !== "npm") {
    const reason = kind === "binary" ? "Standalone binary: reinstall with the install script, it can't update itself." : "Source checkout: update it with git.";
    await report(false, reason);
    return { status: "failed", version, reason };
  }
  try {
    await (deps.install ?? npmInstall)(version);
    await report(true);
    return { status: "updated", version };
  } catch (error) {
    const reason = (error instanceof Error ? error.message : String(error)).slice(0, 300);
    await report(false, reason);
    return { status: "failed", version, reason };
  }
}

/** True when this process is a background service its manager restarts on exit (launchd KeepAlive, systemd Restart=always). */
export const supervised = (env = process.env) => Boolean(env.XPC_SERVICE_NAME && env.XPC_SERVICE_NAME !== "0") || Boolean(env.INVOCATION_ID);
