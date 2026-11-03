import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { getDataDirectory } from "./config.js";
import { readIdentity } from "./enroll.js";
import { forwardSkillInventory } from "./forward.js";
import { readInventory, trustedHashes, type InventorySkill } from "./skill-inventory.js";
import { createHash, randomUUID } from "node:crypto";

// What leaves the machine, per skill: name, agent, risk score and level, finding titles, hashes
// and dates. Never the skill's text or evidence lines, and never the absolute path -- the home
// directory is collapsed to "~" and the repo is reduced to its folder name.
export type SkillReportItem = {
  id: string; name: string; agent: string; scope: string; path: string; repo: string | null;
  hash: string; score: number; level: string; findings: number; injection: boolean; trusted: boolean;
  topFindings: NonNullable<InventorySkill["topFindings"]>; allFindings: NonNullable<InventorySkill["allFindings"]>; files: number; firstSeen: string; lastSeen: string; modifiedAt: string | null;
};
export type SkillReport = { generatedAt: string; day: string; skills: SkillReportItem[] };
type PendingSkillReport = { deviceId: string; orgId: string; apiBase: string; syncId: string; report: SkillReport };

export const MAX_REPORT_SKILLS = 1000;

// The matched line of each finding is sent so the dashboard can show what exactly triggered it.
// That is skill text leaving the machine (secrets are redacted first, and it is capped at a few
// lines per skill), so it can be switched off: BEAM_SKILL_SEND_LINES=0 sends titles, locations
// and explanations only.
export function sendMatchedLines(env = process.env): boolean {
  return !["0", "false", "off", "no"].includes(String(env.BEAM_SKILL_SEND_LINES ?? "").trim().toLowerCase());
}
const stateFile = () => join(getDataDirectory(), "skills-sync.json");
const pendingFile = () => join(getDataDirectory(), "skills-sync-pending.json");
const today = () => new Date().toISOString().slice(0, 10);

export function redactPath(dir: string, home = homedir()): string {
  return dir === home ? "~" : dir.startsWith(home + "/") || dir.startsWith(home + "\\") ? `~${dir.slice(home.length)}` : dir;
}

export async function buildSkillReport(home = homedir()): Promise<SkillReport | null> {
  const inventory = await readInventory();
  if (!inventory) return null;
  const trusted = await trustedHashes();
  const lines = sendMatchedLines();
  // Riskiest first, so the cap (a safety limit) only ever drops the least interesting skills.
  const skills = inventory.skills.slice(0, MAX_REPORT_SKILLS).map((s): SkillReportItem => ({
    id: s.id ?? createHash("sha256").update(s.dir).digest("hex").slice(0, 16), name: s.name, agent: s.agent, scope: s.scope,
    path: redactPath(s.dir, home), repo: s.repo ? basename(s.repo) : null, hash: s.hash, score: s.score, level: s.level,
    findings: s.findings, injection: s.injection, trusted: trusted.has(s.hash), allFindings: s.allFindings ?? [], topFindings: (s.topFindings ?? []).map(({ evidence, ...rest }) => (lines && evidence ? { ...rest, evidence } : rest)),
    files: s.files, firstSeen: s.firstSeen, lastSeen: s.lastSeen, modifiedAt: s.modifiedAt,
  }));
  return { generatedAt: inventory.generatedAt, day: today(), skills };
}

// What the workspace already knows. Dates are left out on purpose: re-indexing bumps lastSeen on
// every skill, and that alone must never count as an update. A skill added, removed, edited (new
// hash), re-scored, or trusted/untrusted does change it.
export function fingerprint(report: SkillReport): string {
  // The findings are hashed in too, so a report that gains matched lines (an upgrade, or the switch
  // above being flipped) is sent once even though no skill's score changed.
  const detail = (s: SkillReportItem) => createHash("sha256").update(JSON.stringify([s.topFindings, s.allFindings])).digest("hex").slice(0, 12);
  return createHash("sha256").update(report.skills.map(s => `${s.id}|${s.name}|${s.score}|${s.level}|${s.hash}|${s.trusted}|${detail(s)}`).sort().join("\n")).digest("hex");
}

async function lastSent(): Promise<{ fingerprint: string | null; deviceId?: string; orgId?: string; apiBase?: string }> {
  try { const state = JSON.parse(await readFile(stateFile(), "utf8")); return { fingerprint: typeof state.fingerprint === "string" ? state.fingerprint : null, deviceId: state.deviceId, orgId: state.orgId, apiBase: state.apiBase }; } catch { return { fingerprint: null }; }
}
async function recordSent(print: string, day: string, identity: { deviceId: string; orgId: string; apiBase: string }): Promise<void> {
  await mkdir(getDataDirectory(), { recursive: true, mode: 0o700 });
  const temp = `${stateFile()}.${randomUUID()}.tmp`;
  await writeFile(temp, JSON.stringify({ fingerprint: print, day, sentAt: new Date().toISOString(), ...identity }) + "\n", { mode: 0o600 });
  await rename(temp, stateFile());
}

async function savePending(report: SkillReport, identity: { deviceId: string; orgId: string; apiBase: string }): Promise<void> {
  await mkdir(getDataDirectory(), { recursive: true, mode: 0o700 });
  const temp = `${pendingFile()}.${randomUUID()}.tmp`;
  await writeFile(temp, JSON.stringify({ ...identity, syncId: randomUUID(), report }), { mode: 0o600 });
  await rename(temp, pendingFile());
}

async function pendingMatches(report: SkillReport, identity: { deviceId: string; orgId: string; apiBase: string }): Promise<boolean> {
  try {
    const pending = JSON.parse(await readFile(pendingFile(), "utf8")) as PendingSkillReport;
    return pending.deviceId === identity.deviceId && pending.orgId === identity.orgId &&
      pending.apiBase === identity.apiBase && fingerprint(pending.report) === fingerprint(report);
  } catch { return false; }
}

async function hasPendingReport(): Promise<boolean> {
  try { await readFile(pendingFile(), "utf8"); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code !== "ENOENT"; }
}

export type SkillSyncResult = { status: "sent" | "queued" | "unchanged" | "not-enrolled" | "no-inventory" | "failed"; skills?: number; reason?: string };

let draining: Promise<SkillSyncResult> | undefined;

// Sends at most one persisted snapshot at a time. The fixed local file coalesces
// repeated scans while offline, retaining only the latest complete inventory.
export function drainSkillInventoryOutbox(): Promise<SkillSyncResult> {
  if (draining) return draining;
  const current: Promise<SkillSyncResult> = (async (): Promise<SkillSyncResult> => {
    const identity = await readIdentity();
    if (!identity) return { status: "not-enrolled" };
    let pending: PendingSkillReport;
    try { pending = JSON.parse(await readFile(pendingFile(), "utf8")) as PendingSkillReport; }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { status: "no-inventory" };
      return { status: "failed", reason: "Could not read the pending skill report." };
    }
    if (pending.deviceId !== identity.deviceId || pending.orgId !== identity.orgId || pending.apiBase !== identity.apiBase)
      return { status: "failed", reason: "The pending report belongs to a different workspace; run beam setup to create a new one." };
    const print = fingerprint(pending.report);
    const sent = await forwardSkillInventory(pending.report, pending.syncId);
    if (!sent.ok) return { status: "failed", reason: sent.reason };
    await recordSent(print, pending.report.day, identity);
    // A fresh setup can replace the queued snapshot while this one is uploading.
    // Delete only the report that was actually sent.
    try {
      const latest = JSON.parse(await readFile(pendingFile(), "utf8")) as PendingSkillReport;
      if (latest.syncId === pending.syncId) await rm(pendingFile(), { force: true });
    } catch { /* another drain or setup already removed/replaced the file */ }
    return { status: "sent", skills: pending.report.skills.length };
  })().catch((error): SkillSyncResult => ({ status: "failed", reason: error instanceof Error ? error.message : "unexpected error" }))
    .finally(() => { if (draining === current) draining = undefined; });
  draining = current;
  return current;
}

// Sends the skill names and risk scores to the workspace collector only when they differ from what
// was last sent -- a new skill, a changed one, or a removed one. An unchanged machine sends nothing,
// however often this runs. A failed send isn't recorded, so the next run retries it.
export async function syncSkillInventory(options: { force?: boolean; home?: string } = {}): Promise<SkillSyncResult> {
  const identity = await readIdentity();
  if (!identity) return { status: "not-enrolled" };
  const report = await buildSkillReport(options.home);
  if (!report) return { status: "no-inventory" };
  const print = fingerprint(report);
  const previous = await lastSent();
  const sameWorkspace = previous.deviceId === identity.deviceId && previous.orgId === identity.orgId && previous.apiBase === identity.apiBase;
  if (!options.force && previous.fingerprint === print && sameWorkspace) {
    if (await pendingMatches(report, identity)) return drainSkillInventoryOutbox();
    if (!await hasPendingReport()) return { status: "unchanged" };
  }
  try { await savePending(report, identity); }
  catch (error) { return { status: "failed", reason: error instanceof Error ? error.message : "Could not save the pending skill report." }; }
  return drainSkillInventoryOutbox();
}

// Setup calls this after local indexing and returns without waiting for workspace requests.
export async function queueSkillInventory(options: { home?: string } = {}): Promise<SkillSyncResult> {
  const identity = await readIdentity();
  if (!identity) return { status: "not-enrolled" };
  const report = await buildSkillReport(options.home);
  if (!report) return { status: "no-inventory" };
  const print = fingerprint(report);
  const previous = await lastSent();
  const sameWorkspace = previous.deviceId === identity.deviceId && previous.orgId === identity.orgId && previous.apiBase === identity.apiBase;
  if (previous.fingerprint === print && sameWorkspace) {
    if (await pendingMatches(report, identity)) return { status: "queued", skills: report.skills.length };
    if (!await hasPendingReport()) return { status: "unchanged" };
  }
  try { await savePending(report, identity); }
  catch (error) { return { status: "failed", reason: error instanceof Error ? error.message : "Could not save the pending skill report." }; }
  return { status: "queued", skills: report.skills.length };
}
