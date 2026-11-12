// Incident records for policy 8.2: report to the security lead within four hours of discovery.
// Beam drafts a record itself when it sees a disclosure it could not prevent; the developer adds the
// ones only a person knows about (`beam incident new`), and reviews and sends each one. Records hold
// kinds, counts and sources only -- never a credential or personal value -- and live in the data directory.
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { getDataDirectory } from "./config.js";

export const REPORT_WINDOW_MS = 4 * 60 * 60 * 1000;
export const INCIDENT_TYPES = ["secret-disclosure", "pii-disclosure", "prompt-injection", "history-secret", "vendor-incident", "workstation-loss", "other"] as const;
export type IncidentType = typeof INCIDENT_TYPES[number];

export interface Incident {
  id: string; type: IncidentType; source: "auto" | "manual"; summary: string; details: string[];
  discoveredAt: string; reportBy: string; status: "open" | "reported";
  reportedAt?: string; reportedTo?: string; key?: string;
}

const STEPS: Record<IncidentType, string[]> = {
  "secret-disclosure": ["Rotate the exposed credential with its provider now, before anything else.", "Check the provider's access logs for use since the exposure.", "If it was committed or pushed, remove it from history (git filter-repo or BFG) and force-push."],
  "pii-disclosure": ["Identify what data and whose it was, and which regulation or contract applies.", "Do not re-send it to the model; use the vault placeholders.", "Tell the security lead what reached the model and when."],
  "prompt-injection": ["Stop the session and do not run anything the agent proposed.", "Review what it already did (`beam activity`) and revoke any credential it could reach.", "Keep the source file or page that carried the instruction."],
  "history-secret": ["Rotate the credential, then clean history (git filter-repo or BFG) and force-push.", "Ask collaborators to re-clone.", "Check whether the repository was ever public or forked."],
  "vendor-incident": ["Read Anthropic's advisory at trust.anthropic.com and note the affected window.", "List what your sessions sent in that window.", "Rotate the Anthropic API key."],
  "workstation-loss": ["Lock or remote-wipe the machine.", "Rotate the Anthropic API key and every credential that was on it.", "Sign out of Claude Code and revoke session tokens."],
  other: ["Describe what happened and what data or systems were involved."],
};
export const stepsFor = (type: IncidentType) => STEPS[type];

const dirOf = (base?: string) => join(base ?? getDataDirectory(), "incidents");
const stamp = (d: Date) => d.toISOString().replace(/[-:]/g, "").replace(/\..*$/, "");

function write(incident: Incident, base?: string): void {
  const dir = dirOf(base); mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, `${incident.id}.json`), JSON.stringify(incident, null, 2), { mode: 0o600 });
}

export function listIncidents(base?: string): Incident[] {
  let names: string[] = []; try { names = readdirSync(dirOf(base)).filter(n => n.endsWith(".json")); } catch { return []; }
  return names.flatMap(n => { try { return [JSON.parse(readFileSync(join(dirOf(base), n), "utf8")) as Incident]; } catch { return []; } })
    .sort((a, b) => a.discoveredAt.localeCompare(b.discoveredAt));
}

export function findIncident(idOrPrefix: string, base?: string): Incident | null {
  const all = listIncidents(base); const hits = all.filter(i => i.id === idOrPrefix || i.id.startsWith(idOrPrefix));
  return hits.length === 1 ? hits[0]! : null;
}

export interface NewIncident { type: IncidentType; summary: string; details?: string[]; source?: "auto" | "manual"; key?: string; at?: Date; dir?: string }

/**
 * Records an incident. Automatic detections pass a `key`; a second detection with the same key inside the
 * reporting window is folded into the first, so one pasted file doesn't become twenty records.
 */
export function createIncident(input: NewIncident): { incident: Incident; created: boolean } {
  const at = input.at ?? new Date();
  if (input.key) {
    const dup = listIncidents(input.dir).find(i => i.key === input.key && at.getTime() - Date.parse(i.discoveredAt) < REPORT_WINDOW_MS);
    if (dup) return { incident: dup, created: false };
  }
  const incident: Incident = {
    id: `inc_${stamp(at)}_${randomBytes(2).toString("hex")}`, type: input.type, source: input.source ?? "manual",
    summary: input.summary, details: input.details ?? [], discoveredAt: at.toISOString(),
    reportBy: new Date(at.getTime() + REPORT_WINDOW_MS).toISOString(), status: "open", key: input.key,
  };
  write(incident, input.dir);
  return { incident, created: true };
}

export function markReported(id: string, to: string, base?: string, at = new Date()): Incident | null {
  const incident = findIncident(id, base); if (!incident) return null;
  const next = { ...incident, status: "reported" as const, reportedAt: at.toISOString(), reportedTo: to };
  write(next, base); return next;
}

export type Urgency = "reported" | "overdue" | "due-soon" | "open";
export function urgency(i: Incident, now = new Date()): Urgency {
  if (i.status === "reported") return "reported";
  const left = Date.parse(i.reportBy) - now.getTime();
  return left < 0 ? "overdue" : left < 60 * 60 * 1000 ? "due-soon" : "open";
}

export function timeLeft(i: Incident, now = new Date()): string {
  const ms = Date.parse(i.reportBy) - now.getTime(); const abs = Math.abs(ms);
  const h = Math.floor(abs / 3_600_000), m = Math.floor((abs % 3_600_000) / 60_000);
  return `${h}h ${String(m).padStart(2, "0")}m ${ms < 0 ? "overdue" : "left"}`;
}

/** A plain-text report the developer can paste into email or chat for the security lead. */
export function formatReport(i: Incident, now = new Date()): string {
  const lines = [
    `Security incident ${i.id}`, `Type: ${i.type}  |  Found: ${i.source === "auto" ? "automatically by Beam" : "reported by developer"}`,
    `Discovered: ${i.discoveredAt}`, `Report to security lead by: ${i.reportBy}${i.status === "open" ? ` (${timeLeft(i, now)})` : ""}`,
    `Status: ${i.status}${i.reportedAt ? ` -- sent ${i.reportedAt}${i.reportedTo ? ` to ${i.reportedTo}` : ""}` : ""}`, "", `What happened: ${i.summary}`,
  ];
  if (i.details.length) lines.push("", "Details (kinds and counts only, no values):", ...i.details.map(d => `  - ${d}`));
  lines.push("", "Recommended actions:", ...STEPS[i.type].map((s, n) => `  ${n + 1}. ${s}`));
  return lines.join("\n");
}
