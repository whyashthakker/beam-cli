import { access } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Event } from "./core.js";
import { AGENTS } from "./agents.js";

export async function inventory(events: Event[], home = homedir()) {
  const exists = async (paths: string[]) => (await Promise.all(paths.map(async p => { try { await access(join(home, p)); return true; } catch { return false; } }))).some(Boolean);
  return Promise.all(AGENTS.map(async d => {
    const matches = events.filter(e => e.agent === d.id || e.agent === d.id.replace("-code", "").replace("-cli", ""));
    const last = matches.reduce<string | null>((value, e) => !value || e.receivedAt > value ? e.receivedAt : value, null);
    return {
      agent: d.id, name: d.name, configPresent: await exists(d.configs), artifactsPresent: await exists(d.artifacts),
      captureStatus: last ? "records received" : "not verified", lastReceived: last,
      hookInstallable: Boolean(d.hookConfigPath), payloadVerified: d.verifiedPayload, integration: d.notes,
    };
  }));
}
