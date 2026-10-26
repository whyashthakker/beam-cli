import { lstat, open, readdir, realpath, rm, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, sep } from "node:path";
import { redact } from "./core.js";
import { readIdentity } from "./enroll.js";
import { agentSkillRoots, indexSkills, readInventory, type InventorySkill } from "./skill-inventory.js";
import { syncSkillInventory } from "./skill-sync.js";
import { versionHeaders } from "./version.js";

// What an administrator can ask this device to do with a skill from the dashboard: delete it, or
// send its SKILL.md once. Both are polled from the workspace (GET /v1/skills/actions), named by the
// skill's id from this machine's own inventory -- the workspace never supplies a path, so a request
// can only reach a skill beam already found here. Turn it off with BEAM_SKILL_REMOTE_ACTIONS=0.
export const MAX_FILE_BYTES = 64 * 1024;

export type SkillActionsResult = { removed: string[]; sent: string[]; skipped: Array<{ id: string; reason: string }> };

export const remoteActionsEnabled = (env = process.env) => !["0", "false", "off", "no"].includes(String(env.BEAM_SKILL_REMOTE_ACTIONS ?? "").trim().toLowerCase());

async function skillFile(dir: string): Promise<string | null> {
  try { const name = (await readdir(dir)).find(entry => entry.toLowerCase() === "skill.md"); return name ? join(dir, name) : null; } catch { return null; }
}

// A skill folder is only deleted when it is clearly one: it holds a SKILL.md, sits inside the home
// folder or a place beam searched, and is not one of those places itself. A symlinked skill (a
// linked package) loses the link, never the folder it points to.
async function removeSkillDir(skill: InventorySkill, roots: string[], home: string): Promise<string | null> {
  const dir = skill.dir;
  const inside = [home, ...roots].some(root => dir.startsWith(root + sep));
  if (!inside || [home, ...roots].includes(dir)) return "outside the places beam searched";
  let info; try { info = await lstat(dir); } catch { return null; } // already gone
  if (!await skillFile(dir)) return "no SKILL.md in that folder";
  if (info.isSymbolicLink()) { await unlink(dir); return null; }
  // Compare real paths on both sides (macOS temp and home folders are reached through symlinks).
  const real = await realpath(dir);
  const realRoots = await Promise.all([home, ...roots].map(root => realpath(root).catch(() => root)));
  if (!realRoots.some(root => real.startsWith(root + sep))) return "resolves outside the places beam searched";
  await rm(dir, { recursive: true, force: true });
  return null;
}

async function readSkillText(dir: string): Promise<{ content: string; truncated: boolean } | null> {
  const file = await skillFile(dir);
  if (!file) return null;
  const handle = await open(file, "r");
  try {
    const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const truncated = bytesRead > MAX_FILE_BYTES;
    return { content: redact(buffer.subarray(0, Math.min(bytesRead, MAX_FILE_BYTES)).toString("utf8")), truncated };
  } finally { await handle.close(); }
}

export async function runSkillActions(options: { home?: string } = {}): Promise<SkillActionsResult | null> {
  if (!remoteActionsEnabled()) return null;
  const identity = await readIdentity();
  if (!identity) return null;
  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${identity.deviceSecret}`, ...versionHeaders() };
  let actions: { remove?: Array<{ id: string }>; read?: Array<{ id: string }> };
  try {
    const response = await fetch(`${identity.apiBase}/v1/skills/actions`, { headers, signal: AbortSignal.timeout(8000) });
    if (!response.ok) return null; // an older collector has no such route
    actions = await response.json() as typeof actions;
  } catch { return null; }
  const remove = actions.remove ?? []; const read = actions.read ?? [];
  if (!remove.length && !read.length) return null;

  const home = options.home ?? homedir();
  const inventory = await readInventory();
  const byId = new Map((inventory?.skills ?? []).map(s => [s.id, s]));
  const result: SkillActionsResult = { removed: [], sent: [], skipped: [] };

  for (const { id } of read) {
    const skill = byId.get(id);
    if (!skill) { result.skipped.push({ id, reason: "not in this device's inventory" }); continue; }
    try {
      const text = await readSkillText(skill.dir);
      if (!text) { result.skipped.push({ id, reason: "SKILL.md not found" }); continue; }
      const response = await fetch(`${identity.apiBase}/v1/skills/content`, { method: "POST", headers, body: JSON.stringify({ id, hash: skill.hash, ...text }), signal: AbortSignal.timeout(15_000) });
      if (response.ok) result.sent.push(id); else result.skipped.push({ id, reason: `workspace responded with HTTP ${response.status}` });
    } catch (error) { result.skipped.push({ id, reason: error instanceof Error ? error.message : String(error) }); }
  }

  if (remove.length) {
    const roots = [...(inventory?.roots ?? []), ...await agentSkillRoots(home)];
    const parents = new Set<string>();
    for (const { id } of remove) {
      const skill = byId.get(id);
      if (!skill) { result.skipped.push({ id, reason: "not in this device's inventory" }); continue; }
      try {
        const refused = await removeSkillDir(skill, roots, home);
        if (refused) result.skipped.push({ id, reason: refused }); else { result.removed.push(skill.dir); parents.add(dirname(skill.dir)); }
      } catch (error) { result.skipped.push({ id, reason: error instanceof Error ? error.message : String(error) }); }
    }
    if (result.removed.length) {
      // Re-index where the skills were, then report: the workspace drops them from its list.
      await indexSkills({ roots: [...parents] }, home).catch(() => {});
      await syncSkillInventory({ force: true, home }).catch(() => {});
    }
  }
  return result;
}
