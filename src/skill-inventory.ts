import { createHash } from "node:crypto";
import { access, mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join, sep } from "node:path";
import { getDataDirectory } from "./config.js";
import { redact } from "./core.js";
import { findingFingerprint, scanSkillDir, type SkillScan } from "./skill-scan.js";

const MAX_ALL_FINDINGS = 200;
import { readTrustedSkills } from "./trusted-skills.js";

// One file listing every skill found anywhere on this machine -- in the agents' global skill
// folders, inside project repos, nested plugin caches -- with its risk score and whether it
// changed since the last index. Lives in Beam's data directory.
// `evidence` is the line that matched (secrets already redacted, at most 300 characters) and
// `explanation` is the rule's fixed "why this is risky" text.
export type SkillFindingSummary = { id: string; title: string; severity: string; file: string; line?: number; explanation?: string; evidence?: string; fp?: string };
/** Every finding, minimal: enough for the dashboard to re-score a skill after some are reviewed as safe. */
export type SkillFindingRef = { id: string; severity: string; fp: string };
export type InventorySkill = {
  /** Stable per-machine id (hash of the folder), so a report can name a skill without its path. Absent in files written before this field existed. */
  id?: string; topFindings?: SkillFindingSummary[]; allFindings?: SkillFindingRef[];
  name: string; dir: string; agent: string; scope: "global" | "project" | "other"; repo: string | null;
  hash: string; score: number; level: SkillScan["level"]; findings: number; injection: boolean;
  files: number; firstSeen: string; lastSeen: string; modifiedAt: string | null;
};
export type Inventory = {
  version: 1; generatedAt: string; roots: string[]; truncated: boolean; skills: InventorySkill[];
  /** When a whole-home search last ran (`beam skills index`). Null/absent: only agent skill folders have been checked. */
  lastFullScanAt?: string | null;
};
export type IndexChanges = { added: string[]; modified: string[]; removed: string[] };

export const inventoryFile = () => join(getDataDirectory(), "skills-inventory.json");

const SKIP = new Set(["node_modules", ".git", "Library", ".Trash", "Applications", "venv", ".venv", "__pycache__", "site-packages", "target", "Pods", ".gradle", ".m2", ".cargo", ".rustup", ".npm", ".pnpm-store", ".cache", ".next", ".turbo", "DerivedData"]);
// Dot-directories are skipped wholesale (caches, tool state) except the ones agents keep skills in.
const DOT_ALLOW = new Set([".claude", ".agents", ".codex", ".cursor", ".gemini", ".github", ".windsurf", ".roo", ".cline", ".continue", ".opencode", ".copilot"]);

function classify(dir: string, home: string): Pick<InventorySkill, "agent" | "scope"> {
  const p = dir.split(sep);
  const agent = p.includes(".claude") ? "claude-code" : p.includes(".codex") ? "codex" : p.includes(".cursor") ? "cursor"
    : p.includes(".gemini") ? "gemini" : p.includes(".copilot") ? "copilot-cli" : p.includes(".opencode") ? "opencode" : p.includes(".agents") ? "universal" : p.includes(".windsurf") ? "windsurf" : "unknown";
  const rel = dir.startsWith(home + sep) ? dir.slice(home.length + 1).split(sep) : [];
  const globalRoot = rel.length === 3 && rel[0].startsWith(".") && rel[1] === "skills";
  return { agent, scope: globalRoot ? "global" : agent === "unknown" ? "other" : "project" };
}

// The folders agents keep their own skills and plugins in. These are dot-directories directly under
// home, which macOS does not protect -- unlike Desktop, Documents, Downloads, iCloud and external
// volumes, which raise a "beam would like to access files in..." prompt the moment something walks
// them. Anything that runs unattended (the background service) must stay inside these; walking the
// rest of home is reserved for an explicit `beam skills index` / `beam skills list`.
const AGENT_HOME_DIRS = [".claude", ".agents", ".codex", ".cursor", ".gemini", ".copilot", ".windsurf", ".opencode", ".continue", ".config/opencode"];
export async function agentSkillRoots(home = homedir()): Promise<string[]> {
  const found: string[] = [];
  for (const rel of AGENT_HOME_DIRS) { const dir = join(home, rel); try { await access(dir); found.push(dir); } catch { /* not installed */ } }
  return found;
}

export type DiscoverOptions = { roots?: string[]; maxDepth?: number; maxDirs?: number; budgetMs?: number };

// Finds every folder that contains a SKILL.md. Does not descend into a skill it found (bundled
// fixtures/examples aren't separate skills), never follows symlinks, and stops at the dir/time
// budget rather than hanging on a huge disk -- `truncated` reports when that happened.
export async function discoverAllSkills(options: DiscoverOptions = {}): Promise<{ found: Array<{ dir: string; repo: string | null }>; roots: string[]; truncated: boolean }> {
  // An explicit empty list means "search nothing", never "fall back to the whole home directory".
  const roots = options.roots ?? [homedir()];
  const maxDepth = options.maxDepth ?? 10, maxDirs = options.maxDirs ?? 400_000;
  const deadline = Date.now() + (options.budgetMs ?? 60_000);
  const found: Array<{ dir: string; repo: string | null }> = [];
  const seen = new Set<string>();
  let visited = 0, truncated = false;
  const stack = roots.map(r => ({ dir: r, depth: 0, repo: null as string | null }));
  while (stack.length) {
    if (visited++ > maxDirs || Date.now() > deadline) { truncated = true; break; }
    const { dir, depth, repo } = stack.pop()!;
    let entries; try { entries = await readdir(dir, { withFileTypes: true }); } catch { continue; }
    if (entries.some(e => e.isFile() && e.name === "SKILL.md")) { if (!seen.has(dir)) { seen.add(dir); found.push({ dir, repo }); } continue; }
    const here = entries.some(e => e.name === ".git") ? dir : repo;
    if (depth >= maxDepth) continue;
    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink() || SKIP.has(e.name)) continue;
      if (e.name.startsWith(".") && !DOT_ALLOW.has(e.name)) continue;
      stack.push({ dir: join(dir, e.name), depth: depth + 1, repo: here });
    }
  }
  return { found, roots, truncated };
}

export async function readInventory(): Promise<Inventory | null> {
  try { const inv = JSON.parse(await readFile(inventoryFile(), "utf8")); return inv?.version === 1 && Array.isArray(inv.skills) ? inv : null; }
  catch { return null; }
}

async function write(inv: Inventory): Promise<void> {
  await mkdir(getDataDirectory(), { recursive: true, mode: 0o700 });
  const file = inventoryFile(); const temp = `${file}.tmp`;
  await writeFile(temp, JSON.stringify(inv, null, 2) + "\n", { mode: 0o600 });
  await rename(temp, file);
}

// Full re-index: discover, scan each skill, diff against the previous file, write it back.
// Skills that vanished are dropped -- but only when the walk finished; a truncated walk can't
// prove absence, so previously known skills under the same roots are kept in that case.
export async function indexSkills(options: DiscoverOptions = {}, home = homedir()): Promise<{ inventory: Inventory; changes: IndexChanges }> {
  const previous = await readInventory();
  const prev = new Map((previous?.skills ?? []).map(s => [s.dir, s]));
  const full = options.roots === undefined;
  const { found, roots, truncated } = await discoverAllSkills(full ? { ...options, roots: [home] } : options);
  const now = new Date().toISOString();
  const skills: InventorySkill[] = []; const changes: IndexChanges = { added: [], modified: [], removed: [] };
  for (const { dir, repo } of found) {
    let scan: SkillScan; try { scan = await scanSkillDir(dir, basename(dir)); } catch { continue; }
    const old = prev.get(dir);
    if (!old) changes.added.push(dir); else if (old.hash !== scan.hash) changes.modified.push(dir);
    skills.push({
      id: createHash("sha256").update(dir).digest("hex").slice(0, 16),
      topFindings: scan.findings.slice(0, 5).map(f => ({
        id: f.id, title: f.title, severity: f.severity, file: f.file, ...(f.line ? { line: f.line } : {}),
        explanation: f.explanation.slice(0, 300), ...(f.evidence ? { evidence: redact(f.evidence).slice(0, 300) } : {}),
        fp: findingFingerprint(f, f.file),
      })),
      allFindings: scan.findings.slice(0, MAX_ALL_FINDINGS).map(f => ({ id: f.id, severity: f.severity, fp: findingFingerprint(f, f.file) })),
      name: scan.name, dir, ...classify(dir, home), repo, hash: scan.hash, score: scan.score, level: scan.level,
      findings: scan.findings.length, injection: scan.findings.some(f => f.id.startsWith("injection.")), files: scan.filesScanned,
      firstSeen: old?.firstSeen ?? now, lastSeen: now, modifiedAt: !old ? null : old.hash !== scan.hash ? now : old.modifiedAt,
    });
  }
  const scanned = new Set(skills.map(s => s.dir));
  for (const old of prev.values()) {
    if (scanned.has(old.dir)) continue;
    const inScope = roots.some(r => old.dir === r || old.dir.startsWith(r + sep));
    if (truncated && inScope) skills.push(old); // can't prove it's gone
    else if (inScope) changes.removed.push(old.dir);
    else skills.push(old); // outside this run's roots (e.g. an ad-hoc --root): leave untouched
  }
  skills.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  const inventory: Inventory = { version: 1, generatedAt: now, roots: [...new Set([...(previous?.roots ?? []), ...roots])], truncated, skills, lastFullScanAt: full ? now : previous?.lastFullScanAt ?? null };
  await write(inventory);
  return { inventory, changes };
}

export async function trustedHashes(): Promise<Set<string>> { return new Set((await readTrustedSkills()).map(t => t.hash)); }

// One 0-100 skills risk score for this machine (higher = riskier). Starts from the worst skill and
// adds 5 for every further HIGH/CRITICAL one (capped at +20). Skills you have trusted are left
// out. The workspace collector computes the same number for each device
// (beam/apps/collector/src/skill-score.ts) -- keep the two in step.
export function deviceSkillsScore(skills: Array<{ score: number; level: string; hash: string }>, trusted: Set<string>): { score: number; highCount: number } {
  const counted = skills.filter(s => !trusted.has(s.hash));
  if (!counted.length) return { score: 0, highCount: 0 };
  const highCount = counted.filter(s => s.level === "HIGH" || s.level === "CRITICAL").length;
  return { score: Math.min(100, Math.max(...counted.map(s => s.score)) + Math.min(20, 5 * Math.max(0, highCount - 1))), highCount };
}
