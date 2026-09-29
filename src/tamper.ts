// Tamper detection: beam's hook install/service can be removed two ways -- through beam itself
// ('beam uninstall', 'beam agent install-all', ...), which is authorized and already tells the
// workspace via revokeDevice()/reportControlEvent() below, or by hand (editing an agent's config
// file directly, deleting it, unloading the launchd/systemd job) -- which today leaves no record
// anywhere. This module gives the collector a baseline of what *should* be installed and reports
// the difference as a critical finding the moment it notices something vanished outside beam's
// own code path. It cannot detect the collector process itself being killed -- a dead process
// can't self-report -- that has to be inferred workspace-side from a heartbeat/last-seen gap;
// this module only covers "the collector is still alive but something under it was tampered with."
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir, hostname } from "node:os";
import { dirname, join } from "node:path";
import { getDataDirectory } from "./config.js";
import { findAgent } from "./agents.js";
import { installedHookAgentIds } from "./install.js";
import { normalize, type Event, type Severity } from "./core.js";
import { forwardEvents } from "./forward.js";

export interface TamperState { expectedHooks: string[]; updatedAt: string }

function tamperStatePath(): string {
  return join(getDataDirectory(), "tamper-state.json");
}

export async function readTamperState(): Promise<TamperState | null> {
  try { return JSON.parse(await readFile(tamperStatePath(), "utf8")) as TamperState; }
  catch { return null; }
}

async function writeTamperState(state: TamperState): Promise<void> {
  const path = tamperStatePath();
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
}

// Snapshots which agents currently have beam's hook installed and remembers it as the expected
// baseline. Call this right after any *authorized* change to hook state (installHook,
// uninstallHook, installAllDetectedHooks, uninstallAllHooks, and every 'beam start') so the
// baseline always reflects the last state a beam command itself produced. checkForTampering()
// below then only flags a gap between that baseline and reality -- i.e. a change nobody made
// through beam.
export async function recordExpectedHooks(home = homedir()): Promise<void> {
  const expectedHooks = await installedHookAgentIds(home);
  await writeTamperState({ expectedHooks, updatedAt: new Date().toISOString() });
}

function selfMonitorRecord(fields: Record<string, unknown>, severity: Severity): Record<string, unknown> {
  return {
    record_type: "finding",
    source_agent: "beam",
    source_type: "self-monitor",
    severity,
    hostname: hostname(),
    timestamp: new Date().toISOString(),
    ...fields,
  };
}

function tamperFindingRecord(agentId: string): Record<string, unknown> {
  const name = findAgent(agentId)?.name ?? agentId;
  return selfMonitorRecord({
    event_type: "beam.tamper",
    rule_id: "beam.tamper.hook_removed",
    title: `Beam monitoring hook removed from ${name}`,
    summary: `${name}'s beam hook disappeared from its config on ${hostname()} outside of any 'beam uninstall' or 'beam agent' command. This agent is no longer being observed or policy-enforced by beam.`,
  }, "critical");
}

// Compares the live on-disk hook set against the last known-good baseline and returns one
// critical finding Event per hook that vanished without going through beam. The caller (serve.ts)
// stores these locally and forwards them to the workspace exactly like any other captured event,
// so they land on the dashboard's existing Activity/Security risks views with no new backend
// route required. Never throws -- a failure here must not take down the collector's poll loop.
export async function checkForTampering(home = homedir()): Promise<Event[]> {
  try {
    const state = await readTamperState();
    const current = await installedHookAgentIds(home);
    if (!state) { await recordExpectedHooks(home); return []; }

    const missing = state.expectedHooks.filter(id => !current.includes(id));
    const changed = missing.length > 0
      || current.length !== state.expectedHooks.length
      || current.some(id => !state.expectedHooks.includes(id));
    if (changed) await writeTamperState({ expectedHooks: current, updatedAt: new Date().toISOString() });
    if (!missing.length) return [];

    const events: Event[] = [];
    for (const agentId of missing) {
      try { events.push(normalize(tamperFindingRecord(agentId))); } catch { /* skip a record normalize() can't accept */ }
    }
    return events;
  } catch {
    return [];
  }
}

// Explicit, non-tamper notice for an authorized stop/uninstall/logout, so the dashboard can tell
// "an admin or device owner deliberately turned this off" apart from the silent disappearance
// checkForTampering() exists to catch. Sent directly (not through the local collector, which may
// already be shutting down as part of the same command) using whatever identity is still on disk
// at the moment the caller invokes this -- callers must call it *before* clearing that identity.
// Best-effort: never blocks the command that calls it.
export async function reportControlEvent(ruleSuffix: string, title: string, detail: string): Promise<void> {
  try {
    const event = normalize(selfMonitorRecord({
      event_type: "beam.control",
      rule_id: `beam.control.${ruleSuffix}`,
      title,
      summary: detail,
    }, "info"));
    await forwardEvents(event);
  } catch { /* best-effort only */ }
}
