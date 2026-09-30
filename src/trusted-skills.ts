import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { getDataDirectory } from "./config.js";

// Human-maintained list of skills whose exact content has been reviewed. Keyed by content hash,
// not path, so editing a trusted skill afterwards (a "rug pull") drops it back to being scanned.
// Lives in the data directory that isBeamSelfProtectionTarget() already protects from agent
// writes, so an agent can't approve its own skill.
export type TrustedSkill = { name: string; hash: string; trustedAt: string };
export const trustedSkillsFile = () => join(getDataDirectory(), "trusted-skills.json");

export async function readTrustedSkills(): Promise<TrustedSkill[]> {
  try {
    const parsed = JSON.parse(await readFile(trustedSkillsFile(), "utf8"));
    return Array.isArray(parsed) ? parsed.filter((t): t is TrustedSkill => typeof t?.hash === "string" && typeof t?.name === "string") : [];
  } catch { return []; }
}

async function write(list: TrustedSkill[]): Promise<void> {
  await mkdir(getDataDirectory(), { recursive: true, mode: 0o700 });
  const file = trustedSkillsFile(); const temp = `${file}.tmp`;
  await writeFile(temp, JSON.stringify(list, null, 2) + "\n", { mode: 0o600 });
  await rename(temp, file);
}

export async function trustSkill(name: string, hash: string): Promise<void> {
  const list = (await readTrustedSkills()).filter(t => t.hash !== hash);
  await write([...list, { name, hash, trustedAt: new Date().toISOString() }]);
}
export async function untrustSkill(nameOrHash: string): Promise<number> {
  const list = await readTrustedSkills();
  const next = list.filter(t => t.name !== nameOrHash && t.hash !== nameOrHash);
  await write(next);
  return list.length - next.length;
}
