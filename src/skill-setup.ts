import { agentSkillRoots, indexSkills, readInventory } from "./skill-inventory.js";
import { syncSkillInventory, type SkillSyncResult } from "./skill-sync.js";

export type SkillSetupResult = { total: number; highRisk: number; searchedHome: boolean; sync: SkillSyncResult };

// What `beam setup` does about skills: index what is installed and, if this device is connected
// to a workspace, report the names and risk scores right away instead of waiting for the daily
// check. The agents' own skill folders are always covered (no macOS folder prompt). Searching the
// rest of the home folder for skills inside project repos is what raises the "beam would like to
// access Desktop / Documents / Downloads" prompt, so it only happens when the caller asked for it
// (setup asks; a non-interactive run does not). Doing it once also switches on the daily
// whole-home rescan in skill-watch.ts.
export async function indexAndReportSkills(options: { searchProjects: boolean; home?: string }): Promise<SkillSetupResult> {
  const roots = await agentSkillRoots(options.home);
  if (options.searchProjects) await indexSkills({}, options.home);
  else if (roots.length) await indexSkills({ roots }, options.home);
  const inventory = await readInventory();
  const skills = inventory?.skills ?? [];
  const sync = await syncSkillInventory({ home: options.home }).catch((): SkillSyncResult => ({ status: "failed", reason: "unexpected error" }));
  return {
    total: skills.length,
    highRisk: skills.filter(s => s.level === "HIGH" || s.level === "CRITICAL").length,
    searchedHome: options.searchProjects,
    sync,
  };
}
