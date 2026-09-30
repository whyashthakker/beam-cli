import { agentSkillRoots, indexSkills, readInventory, type IndexChanges } from "./skill-inventory.js";
import { syncSkillInventory, type SkillSyncResult } from "./skill-sync.js";

export const CHECK_EVERY_MS = 24 * 60 * 60_000;

export type SkillCheck = { scanned: "agents" | "full" | "none"; changes: IndexChanges; sync: SkillSyncResult | null };

// Due when there is no inventory yet, or the last index (this watch, or a manual `beam skills
// index` / `beam skills sync`) is a day old. Reading one small file is all this costs.
export async function skillCheckDue(now = Date.now()): Promise<boolean> {
  const inventory = await readInventory();
  const last = inventory ? Date.parse(inventory.generatedAt) : NaN;
  return !Number.isFinite(last) || now - last >= CHECK_EVERY_MS;
}

// The daily skill scan:
//  - if you have already searched your whole home folder (`beam skills index` or `beam skills
//    list`), repeat that search, so skills added in project folders are found too;
//  - otherwise only check the agents' own skill folders. It never starts the whole-home search on
//    its own: that search is what makes macOS ask for access to Desktop, Documents and
//    Downloads, and it should only happen when you asked for it;
//  - then report to the workspace if anything changed (skill-sync.ts sends nothing otherwise).
export async function checkSkills(options: { home?: string } = {}): Promise<SkillCheck> {
  const previous = await readInventory();
  let scanned: SkillCheck["scanned"] = "none";
  let changes: IndexChanges = { added: [], modified: [], removed: [] };
  if (previous?.lastFullScanAt) {
    ({ changes } = await indexSkills({}, options.home));
    scanned = "full";
  } else {
    const roots = await agentSkillRoots(options.home);
    if (roots.length) { ({ changes } = await indexSkills({ roots }, options.home)); scanned = "agents"; }
  }
  if (scanned === "none" && !previous) return { scanned, changes, sync: null };
  return { scanned, changes, sync: await syncSkillInventory({ home: options.home }).catch(() => null) };
}

// What the background service calls: does nothing unless a day has passed.
export async function checkSkillsIfDue(options: { home?: string; now?: number } = {}): Promise<SkillCheck | null> {
  return await skillCheckDue(options.now) ? checkSkills(options) : null;
}
