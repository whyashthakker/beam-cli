import { readdir, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { homedir } from "node:os";
import { SKILL_DIRS, isBlocked } from "./skills.js";
import { scanSkillDir, scanSkillFile, type SkillScan } from "./skill-scan.js";
import { readInventory } from "./skill-inventory.js";
import { readTrustedSkills } from "./trusted-skills.js";

export type SkillGateResult = { action: "allow" | "ask" | "deny"; reason?: string; scan: SkillScan };
export type Target = { kind: "dir"; path: string; name: string } | { kind: "file"; path: string; name: string };

// How each agent loads a skill (tool names are matched case-insensitively):
//  - Claude Code `Skill`, OpenCode `skill`, Gemini CLI `activate_skill`: a native tool taking a name.
//  - Claude Code `Read`, Cursor `Read`, Copilot CLI `view`, Gemini `read_file`/`read_many_files`,
//    OpenCode `read`: a file-read tool on SKILL.md or one of the skill's reference files.
//  - Codex (no read tool at all) and every other agent's shell tool: `cat`/`sed`/`head`... on the file.
const NAME_TOOLS = /^(?:skill|activate_skill|use_skill|load_skill)$/i;
const READ_TOOLS = /^(?:read|read_file|readfile|read_text_file|read_many_files|view|open|cat|fs_read)$/i;
const SHELL_TOOLS = /^(?:bash|shell|sh|zsh|powershell|pwsh|run_shell_command|run_terminal_cmd|execute_bash|exec_command|exec|local_shell|terminal|command)$/i;
// Verbs that put a file's content in front of the model. Deliberately not `rm`/`cp`/`git`: a
// command merely *mentioning* a skill path isn't loading it.
const READ_VERBS = /^(?:cat|sed|head|tail|less|more|bat|batcat|nl|awk|type|get-content|gc|tac|cut|strings|xxd|od|rg|grep|view|open|python3?|node|ruby|perl)$/i;
const SKILL_MD = /^skills?\.md$/i;
const PATH_KEYS = ["file_path", "path", "filePath", "absolute_path", "target_file", "file", "filename"];

async function isFile(p: string) { try { return (await stat(p)).isFile(); } catch { return false; } }

// Copilot CLI sends toolArgs as a JSON *string*; other agents send an object. Accept both.
export function coerceInput(input: unknown): Record<string, unknown> {
  if (typeof input === "string") { try { return coerceInput(JSON.parse(input)); } catch { return { command: input }; } }
  return input && typeof input === "object" && !Array.isArray(input) ? input as Record<string, unknown> : {};
}

// Finds <name>/SKILL.md in the standard skill roots, then the machine-wide inventory, then
// (best effort, bounded) inside installed plugins, whose layout varies. A "plugin:skill" name is
// reduced to its skill part.
async function findNamedSkill(rawName: string, cwd: string, home: string): Promise<string | null> {
  const name = rawName.replace(/^\//, "").split(":").pop() ?? "";
  if (!/^[\w.-]+$/.test(name)) return null;
  for (const root of [cwd, home]) {
    for (const rel of SKILL_DIRS) {
      const dir = join(root, rel, name);
      if (root && await isFile(join(dir, "SKILL.md"))) return dir;
    }
  }
  const fromIndex = (await readInventory())?.skills.find(s => s.name === name);
  if (fromIndex && await isFile(join(fromIndex.dir, "SKILL.md"))) return fromIndex.dir;
  const walk = async (dir: string, depth: number): Promise<string | null> => {
    if (depth > 6) return null;
    let entries; try { entries = await readdir(dir, { withFileTypes: true }); } catch { return null; }
    for (const e of entries) {
      if (!e.isDirectory() || e.name === "node_modules" || e.name === ".git") continue;
      const full = join(dir, e.name);
      if (e.name === name && await isFile(join(full, "SKILL.md"))) return full;
      const hit = await walk(full, depth + 1); if (hit) return hit;
    }
    return null;
  };
  return walk(join(home, ".claude", "plugins"), 0);
}

// Markdown files a read tool is pointed at: the usual path keys, plus any string (or list of
// strings) in the input that looks like a .md path -- covers Gemini's read_many_files.
function readPaths(input: Record<string, unknown>): string[] {
  const out = new Set<string>();
  for (const key of PATH_KEYS) if (typeof input[key] === "string") out.add(input[key] as string);
  for (const value of Object.values(input)) {
    if (typeof value === "string") out.add(value);
    else if (Array.isArray(value)) for (const v of value) if (typeof v === "string") out.add(v);
  }
  return [...out].filter(p => /\.md$/i.test(p.trim()));
}

// Paths a shell command reads with a content-printing verb: `cat ~/.codex/skills/x/SKILL.md`,
// `sed -n '1,200p' SKILL.md`, `head -50 skills.md && echo ok`, `Get-Content .\SKILL.md`.
export function shellReadPaths(command: string): string[] {
  const out: string[] = [];
  for (const segment of command.split(/&&|\|\||[;|\n]/)) {
    const tokens = segment.trim().match(/"[^"]*"|'[^']*'|\S+/g)?.map(t => t.replace(/^["']|["']$/g, "")) ?? [];
    const verb = tokens.findIndex(t => READ_VERBS.test(basename(t)));
    if (verb < 0) continue;
    for (const t of tokens.slice(verb + 1)) if (/\.md$/i.test(t)) out.push(t.replace(/^~(?=$|[\\/])/, homedir()));
  }
  return out;
}

async function targetForFile(raw: string, cwd: string): Promise<Target | null> {
  const file = isAbsolute(raw) ? raw : resolve(cwd || ".", raw);
  const parts = file.split(sep);
  const at = parts.lastIndexOf("skills");
  if (at >= 0 && at < parts.length - 2) {
    // <...>/skills/<name>/<anything>.md -> the whole skill folder, so a poisoned reference file
    // is judged together with the SKILL.md that pulls it in.
    const dir = parts.slice(0, at + 2).join(sep);
    if (await isFile(join(dir, "SKILL.md"))) return { kind: "dir", path: dir, name: parts[at + 1] };
  }
  if (SKILL_MD.test(basename(file)) && await isFile(file)) {
    return /^skill\.md$/i.test(basename(file)) ? { kind: "dir", path: dirname(file), name: basename(dirname(file)) } : { kind: "file", path: file, name: basename(file) };
  }
  return null;
}

// Every skill this tool call loads into the agent. Empty when the call is unrelated to skills.
export async function resolveSkillTargets(tool: string, rawInput: unknown, cwd = "", home = homedir()): Promise<Target[]> {
  const input = coerceInput(rawInput);
  const targets = new Map<string, Target>();
  const add = (t: Target | null) => { if (t) targets.set(t.path, t); };
  if (NAME_TOOLS.test(tool)) {
    const name = String(input.skill ?? input.name ?? input.skill_name ?? input.command ?? "");
    const dir = name ? await findNamedSkill(name, cwd, home) : null;
    if (dir) add({ kind: "dir", path: dir, name: basename(dir) });
  } else if (READ_TOOLS.test(tool)) {
    for (const p of readPaths(input)) add(await targetForFile(p.trim(), cwd));
  } else if (SHELL_TOOLS.test(tool)) {
    const command = Array.isArray(input.command) ? input.command.join(" ") : String(input.command ?? input.cmd ?? "");
    for (const p of shellReadPaths(command)) add(await targetForFile(p, cwd));
  }
  return [...targets.values()];
}

export async function resolveSkillTarget(tool: string, input: unknown, cwd = "", home = homedir()): Promise<Target | null> {
  return (await resolveSkillTargets(tool, input, cwd, home))[0] ?? null;
}

export function formatSkillRisk(scan: SkillScan): string {
  const top = scan.findings.slice(0, 3).map(f => `${f.title} (${f.file}${f.line ? `:${f.line}` : ""})`).join("; ");
  return `Skill "${scan.name}" risk score ${scan.score}/100 (${scan.level})${top ? `: ${top}` : ""}${scan.findings.length > 3 ? `; +${scan.findings.length - 3} more` : ""}. Review with: beam skills scan ${scan.dir}. If you trust it: beam skills trust ${scan.dir}`;
}

// Returns null when the call doesn't involve a skill at all. Otherwise: trusted (by content hash)
// or clean-enough skills pass; prompt-injection / critical skills are held for approval, or denied
// outright under an enforce policy. Medium-risk skills pass but are still scored on the event. If
// one call loads several skills, the riskiest one decides.
export async function gateSkill(tool: string, input: unknown, cwd: string, enforce: boolean, home = homedir()): Promise<SkillGateResult | null> {
  const targets = await resolveSkillTargets(tool, input, cwd, home);
  if (!targets.length) return null;
  const trusted = new Set((await readTrustedSkills()).map(t => t.hash));
  const results: SkillGateResult[] = [];
  for (const target of targets) {
    const scan = target.kind === "dir" ? await scanSkillDir(target.path, target.name) : await scanSkillFile(target.path);
    if (trusted.has(scan.hash)) results.push({ action: "allow", scan });
    else if (!isBlocked(scan)) results.push({ action: "allow", reason: scan.findings.length ? formatSkillRisk(scan) : undefined, scan });
    else results.push({ action: enforce ? "deny" : "ask", reason: formatSkillRisk(scan), scan });
  }
  const rank = (r: SkillGateResult) => (r.action === "allow" ? 0 : 1000) + r.scan.score;
  return results.sort((a, b) => rank(b) - rank(a))[0];
}
