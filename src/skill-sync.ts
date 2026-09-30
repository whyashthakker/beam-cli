import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { getDataDirectory } from "./config.js";
import { readIdentity } from "./enroll.js";
import { forwardSkillInventory } from "./forward.js";
import { readInventory, trustedHashes, type InventorySkill } from "./skill-inventory.js";
import { createHash } from "node:crypto";

// What leaves the machine, per skill: name, agent, risk score and level, finding titles, hashes
// and dates. Never the skill's text or evidence lines, and never the absolute path -- the home
// directory is collapsed to "~" and the repo is reduced to its folder name.
export type SkillReportItem = {
  id: string; name: string; agent: string; scope: string; path: string; repo: string | null;
  hash: string; score: number; level: string; findings: number; injection: boolean; trusted: boolean;
  topFindings: NonNullable<InventorySkill["topFindings"]>; allFindings: NonNullable<InventorySkill["allFindings"]>; files: number; firstSeen: string; lastSeen: string; modifiedAt: string | null;
};
export type SkillReport = { generatedAt: string; day: string; skills: SkillReportItem[] };

export const MAX_REPORT_SKILLS = 1000;

// The matched line of each finding is sent so the dashboard can show what exactly triggered it.
// That is skill text leaving the machine (secrets are redacted first, and it is capped at a few
// lines per skill), so it can be switched off: BEAM_SKILL_SEND_LINES=0 sends titles, locations
// and explanations only.
export function sendMatchedLines(env = process.env): boolean {
  return !["0", "false", "off", "no"].includes(String(env.BEAM_SKILL_SEND_LINES ?? "").trim().toLowerCase());
}
const stateFile = () => join(getDataDirectory(), "skills-sync.json");
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

async function lastSent(): Promise<{ fingerprint: string | null }> {
  try { const state = JSON.parse(await readFile(stateFile(), "utf8")); return { fingerprint: typeof state.fingerprint === "string" ? state.fingerprint : null }; } catch { return { fingerprint: null }; }
}
async function recordSent(print: string, day: string): Promise<void> {
  await mkdir(getDataDirectory(), { recursive: true, mode: 0o700 });
  const temp = `${stateFile()}.tmp`;
  await writeFile(temp, JSON.stringify({ fingerprint: print, day, sentAt: new Date().toISOString() }) + "\n", { mode: 0o600 });
  await rename(temp, stateFile());
}

export type SkillSyncResult = { status: "sent" | "unchanged" | "not-enrolled" | "no-inventory" | "failed"; skills?: number; reason?: string };

// Sends the skill names and risk scores to the workspace collector only when they differ from what
// was last sent -- a new skill, a changed one, or a removed one. An unchanged machine sends nothing,
// however often this runs. A failed send isn't recorded, so the next run retries it.
export async function syncSkillInventory(options: { force?: boolean; home?: string } = {}): Promise<SkillSyncResult> {
  if (!await readIdentity()) return { status: "not-enrolled" };
  const report = await buildSkillReport(options.home);
  if (!report) return { status: "no-inventory" };
  const print = fingerprint(report);
  if (!options.force && (await lastSent()).fingerprint === print) return { status: "unchanged" };
  const sent = await forwardSkillInventory(report);
  if (!sent.ok) return { status: "failed", reason: sent.reason };
  await recordSent(print, report.day);
  return { status: "sent", skills: report.skills.length };
}
