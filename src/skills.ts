import { execFile } from "node:child_process";
import { cp, lstat, mkdir, mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { promisify } from "node:util";
import { severityRank } from "./core.js";
import { scanSkillDir, type SkillScan } from "./skill-scan.js";

const run = promisify(execFile);

// Skill directory per agent, relative to the project (or home with --global). Codex, Cursor and
// Gemini CLI and OpenCode share the universal .agents/skills location. Copilot CLI is the one
// agent whose project and user folders differ (.github/skills vs ~/.copilot/skills).
export const SKILL_TARGETS: Record<string, { project: string; global: string }> = {
  "claude-code": { project: ".claude/skills", global: ".claude/skills" },
  codex: { project: ".agents/skills", global: ".agents/skills" },
  cursor: { project: ".agents/skills", global: ".agents/skills" },
  gemini: { project: ".agents/skills", global: ".agents/skills" },
  opencode: { project: ".agents/skills", global: ".agents/skills" },
  "copilot-cli": { project: ".github/skills", global: ".copilot/skills" },
};
export const ALL_SKILL_AGENTS = Object.keys(SKILL_TARGETS);
// Every folder skills can live in, for scanning what's already installed.
export const SKILL_DIRS = [...new Set(Object.values(SKILL_TARGETS).flatMap(t => [t.project, t.global]))];

export type AddSkillOptions = { skill?: string; agent?: string[]; allAgents?: boolean; global?: boolean; force?: boolean; scanOnly?: boolean; cwd?: string; home?: string };
export type AddSkillResult = { source: string; scans: SkillScan[]; installed: Array<{ name: string; path: string }>; blocked: string[] };

// Blocks on prompt-injection findings at high+, or any critical finding. Other high findings
// (production changes, metadata endpoints...) only warn: legitimate skills, defensive security
// ones especially, describe those things without being malicious.
export const isBlocked = (scan: SkillScan) => scan.findings.some(f => f.severity === "critical" || (f.id.startsWith("injection.") && severityRank[f.severity] >= severityRank.high));

const SHORTHAND = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

async function isDir(path: string) { try { return (await stat(path)).isDirectory(); } catch { return false; } }
async function hasSkillMd(dir: string) { try { return (await stat(join(dir, "SKILL.md"))).isFile(); } catch { return false; } }

function cloneUrl(source: string): string | null {
  const short = source.match(SHORTHAND);
  if (short) return `https://github.com/${short[1]}/${short[2].replace(/\.git$/, "")}.git`;
  if (/^https:\/\/(?:github\.com|gitlab\.com)\/[\w.-]+\/[\w.-]+?(?:\.git)?\/?$/.test(source)) return source.replace(/\/$/, "");
  return null;
}

// SKILL.md at the root, or under skills/<name>/ (and .claude/skills, .agents/skills), matching
// the layouts explainx and the Vercel skills CLI both use.
export async function discoverSkills(root: string): Promise<Array<{ name: string; dir: string }>> {
  if (await hasSkillMd(root)) return [{ name: basename(root), dir: root }];
  const found: Array<{ name: string; dir: string }> = [];
  for (const base of ["skills", ".claude/skills", ".agents/skills"]) {
    const parent = join(root, base);
    if (!await isDir(parent)) continue;
    for (const entry of await readdir(parent, { withFileTypes: true })) {
      if (entry.isDirectory() && await hasSkillMd(join(parent, entry.name))) found.push({ name: entry.name, dir: join(parent, entry.name) });
    }
  }
  return found;
}

export async function addSkill(source: string, options: AddSkillOptions = {}): Promise<AddSkillResult> {
  const cwd = options.cwd ?? process.cwd();
  const agents = options.allAgents ? ALL_SKILL_AGENTS : options.agent?.length ? options.agent : ["claude-code"];
  for (const a of agents) if (!SKILL_TARGETS[a]) throw new Error(`Unknown agent "${a}". Choose from: ${Object.keys(SKILL_TARGETS).join(", ")}.`);

  const staging = await mkdtemp(join(tmpdir(), "beam-skill-"));
  try {
    let root: string;
    const local = resolve(cwd, source);
    if (await isDir(local)) root = local;
    else {
      const url = cloneUrl(source);
      if (!url) throw new Error(`"${source}" is neither a local folder nor an owner/repo or https GitHub/GitLab URL.`);
      root = join(staging, "repo");
      // hooksPath=/dev/null: a cloned repo must never get to run its own git hooks.
      await run("git", ["-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--quiet", url, root], { timeout: 60_000 });
    }

    let skills = await discoverSkills(root);
    if (options.skill) skills = skills.filter(s => s.name === options.skill);
    if (!skills.length) throw new Error(options.skill ? `No skill named "${options.skill}" found in ${source}.` : `No SKILL.md found in ${source}.`);
    if (skills.length > 1 && !options.skill && !options.scanOnly) {
      throw new Error(`${source} contains ${skills.length} skills (${skills.map(s => s.name).join(", ")}). Pick one with --skill <name>.`);
    }

    const scans = await Promise.all(skills.map(s => scanSkillDir(s.dir, s.name)));
    const result: AddSkillResult = { source, scans, installed: [], blocked: [] };
    if (options.scanOnly) return result;

    const base = options.global ? (options.home ?? homedir()) : cwd;
    for (const scan of scans) {
      if (isBlocked(scan) && !options.force) { result.blocked.push(scan.name); continue; }
      if (!SAFE_NAME.test(scan.name)) throw new Error(`Refusing unsafe skill name "${scan.name}".`);
      for (const dest of new Set(agents.map(a => join(base, SKILL_TARGETS[a][options.global ? "global" : "project"], scan.name)))) {
        await mkdir(join(dest, ".."), { recursive: true });
        // Symlinks are dropped so a skill can't point an installed file at something outside itself.
        await cp(scan.dir, dest, { recursive: true, force: true, filter: async src => !/[\\/]\.git(?:[\\/]|$)/.test(src) && !(await lstat(src)).isSymbolicLink() });
        result.installed.push({ name: scan.name, path: dest });
      }
    }
    return result;
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

// `beam skills scan` with no path: every skill already installed for the supported agents.
export async function scanInstalledSkills(home = homedir(), cwd = process.cwd()): Promise<SkillScan[]> {
  const scans: SkillScan[] = [];
  const seen = new Set<string>();
  for (const base of [home, cwd]) {
    for (const rel of SKILL_DIRS) {
      const parent = join(base, rel);
      if (!await isDir(parent)) continue;
      for (const entry of await readdir(parent, { withFileTypes: true })) {
        const dir = join(parent, entry.name);
        if (!entry.isDirectory() || seen.has(dir) || !await hasSkillMd(dir)) continue;
        seen.add(dir);
        scans.push(await scanSkillDir(dir, entry.name));
      }
    }
  }
  return scans;
}
