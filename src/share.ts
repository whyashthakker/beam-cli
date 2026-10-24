import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, mkdtemp, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { getDataDirectory } from "./config.js";
import type { Identity } from "./enroll.js";
import { scanSkillDir, scanSkillFile, type SkillScan } from "./skill-scan.js";
import { isBlocked, SKILL_TARGETS } from "./skills.js";

// `beam share`: the team library. Shares a skill, CLAUDE.md / AGENTS.md, slash command, subagent
// or Cursor rule with everyone in the workspace, and installs what teammates shared.
//
// What leaves the machine: exactly the files listed before you confirm -- never anything else in
// the folder (hidden files, node_modules, symlinks and non-text files are left out). A file with a
// credential is refused here before upload, and again by the workspace. Downloads are checked
// against the workspace's content hash, validated, and re-scanned before anything is written.
//
// The file rules mirror the dashboard's lib/shared-assets/files.ts -- keep the two in step.

export const SHARE_KINDS = ["SKILL", "INSTRUCTIONS", "COMMAND", "SUBAGENT", "RULE"] as const;
export type ShareKind = (typeof SHARE_KINDS)[number];
export type ShareFile = { path: string; content: string };

export const KIND_NAMES: Record<ShareKind, string> = { SKILL: "skill", INSTRUCTIONS: "instructions", COMMAND: "slash command", SUBAGENT: "subagent", RULE: "Cursor rule" };

export const MAX_FILES = 100;
export const MAX_FILE_BYTES = 128 * 1024;
export const MAX_TOTAL_BYTES = 512 * 1024;
const TEXT_EXT = /\.(?:md|mdx|mdc|txt|json|ya?ml|toml|sh|bash|zsh|py|js|mjs|cjs|ts|rb|ps1)$/i;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$/;
export const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const INSTRUCTION_FILES = new Set(["CLAUDE.md", "AGENTS.md", "GEMINI.md"]);
const SKIP_DIR = new Set(["node_modules", "__pycache__", ".git", ".venv"]);

export const slugify = (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
const byPath = (a: ShareFile, b: ShareFile) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);

export function pathProblem(path: string): string | null {
  if (path.length > 300) return "is too long";
  const segments = path.split("/");
  if (segments.length > 7) return "is nested too deeply";
  if (!segments.every(s => SEGMENT.test(s))) return "has an unsupported name";
  if (!TEXT_EXT.test(path)) return "is not a supported text file";
  return null;
}

/** Same algorithm as the workspace: each path and its content's hash, sorted by path. */
export function contentHash(files: ShareFile[]): string {
  return sha256([...files].sort(byPath).map(f => `${f.path}\0${sha256(f.content)}\n`).join(""));
}

export function validateShareFiles(kind: ShareKind, raw: ShareFile[]): ShareFile[] {
  const files = [...raw].sort(byPath);
  const seen = new Set<string>();
  let total = 0;
  if (!files.length) throw new Error("There are no files to share.");
  if (files.length > MAX_FILES) throw new Error(`More than ${MAX_FILES} files.`);
  for (const f of files) {
    const problem = pathProblem(f.path);
    if (problem) throw new Error(`"${f.path}" ${problem}.`);
    if (seen.has(f.path.toLowerCase())) throw new Error(`"${f.path}" appears more than once.`);
    seen.add(f.path.toLowerCase());
    if (f.content.includes("\u0000")) throw new Error(`"${f.path}" is not a text file.`);
    const size = Buffer.byteLength(f.content, "utf8");
    if (size > MAX_FILE_BYTES) throw new Error(`"${f.path}" is over ${MAX_FILE_BYTES / 1024} KB.`);
    total += size;
  }
  if (total > MAX_TOTAL_BYTES) throw new Error(`The files add up to more than ${MAX_TOTAL_BYTES / 1024} KB.`);
  if (kind === "SKILL") {
    if (!files.some(f => f.path === "SKILL.md")) throw new Error("A skill needs a SKILL.md at the top of its folder.");
    return files;
  }
  if (files.length !== 1 || files[0].path.includes("/")) throw new Error(`A ${KIND_NAMES[kind]} is a single file.`);
  if (kind === "INSTRUCTIONS" && !INSTRUCTION_FILES.has(files[0].path)) throw new Error("Instructions are shared as CLAUDE.md, AGENTS.md or GEMINI.md.");
  if (kind === "RULE" ? !/\.mdc?$/.test(files[0].path) : !/\.md$/.test(files[0].path)) throw new Error(kind === "RULE" ? "A Cursor rule is an .mdc or .md file." : `A ${KIND_NAMES[kind]} is a .md file.`);
  return files;
}

// Shaped credentials, same set the workspace refuses. Reported by file and line only.
const CREDENTIALS: Array<{ kind: string; re: RegExp }> = [
  { kind: "private key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { kind: "API key", re: /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|beam_app_[\w-]{20,})\b/ },
  { kind: "access token", re: /\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36})\b/ },
  { kind: "credential in a URL", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]{6,}@/i },
];
export type CredentialHit = { file: string; line: number; kind: string };
export function findCredentials(files: ShareFile[]): CredentialHit[] {
  const hits: CredentialHit[] = [];
  for (const f of files) f.content.split(/\r?\n/).forEach((line, i) => {
    const found = CREDENTIALS.find(c => c.re.test(line));
    if (found) hits.push({ file: f.path, line: i + 1, kind: found.kind });
  });
  return hits;
}

async function isDirectory(path: string) { try { return (await stat(path)).isDirectory(); } catch { return false; } }

/** What a path is, from where it lives and what it's called. null: ask with --kind. */
export async function detectKind(target: string): Promise<ShareKind | null> {
  const full = resolve(target);
  if (await isDirectory(full)) return (await stat(join(full, "SKILL.md")).then(s => s.isFile(), () => false)) ? "SKILL" : null;
  const name = basename(full);
  const parts = full.split(sep);
  if (name === "SKILL.md") return "SKILL";
  if (INSTRUCTION_FILES.has(name)) return "INSTRUCTIONS";
  if (name.endsWith(".mdc") || parts.slice(-3, -1).join("/") === ".cursor/rules") return "RULE";
  if (parts.at(-2) === "commands") return "COMMAND";
  if (parts.at(-2) === "agents") return "SUBAGENT";
  return null;
}

export type CollectedShare = { root: string; files: ShareFile[]; skipped: string[]; defaultName: string };

// Reads exactly what would be shared. Hidden files and folders, node_modules, symlinks and
// non-text files are left out (and listed, so nothing is dropped silently).
export async function collectShareFiles(target: string, kind: ShareKind): Promise<CollectedShare> {
  let full = resolve(target);
  if (kind === "SKILL" && basename(full) === "SKILL.md") full = dirname(full);
  const skipped: string[] = [];
  if (kind !== "SKILL") {
    if ((await lstat(full)).isSymbolicLink()) throw new Error(`${target} is a symlink; share the file it points to.`);
    const content = await readFile(full, "utf8");
    return { root: dirname(full), files: validateShareFiles(kind, [{ path: basename(full), content }]), skipped, defaultName: basename(full).replace(/\.mdc?$/, "") };
  }
  const files: ShareFile[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const abs = join(dir, entry.name);
      const rel = relative(full, abs).split(sep).join("/");
      if (entry.isSymbolicLink()) { skipped.push(`${rel} (symlink)`); continue; }
      if (entry.name.startsWith(".") || SKIP_DIR.has(entry.name)) { skipped.push(`${rel}${entry.isDirectory() ? "/" : ""} (hidden or generated)`); continue; }
      if (entry.isDirectory()) { await walk(abs); continue; }
      if (!entry.isFile()) continue;
      const problem = pathProblem(rel);
      if (problem) { skipped.push(`${rel} (${problem})`); continue; }
      if ((await stat(abs)).size > MAX_FILE_BYTES) { skipped.push(`${rel} (over ${MAX_FILE_BYTES / 1024} KB)`); continue; }
      const content = await readFile(abs, "utf8");
      if (content.includes("\u0000")) { skipped.push(`${rel} (binary)`); continue; }
      files.push({ path: rel, content });
      if (files.length > MAX_FILES) throw new Error(`${target} has more than ${MAX_FILES} files to share.`);
    }
  };
  await walk(full);
  const frontmatterName = files.find(f => f.path === "SKILL.md")?.content.match(/^---[\s\S]*?^name:\s*["']?([^"'\n]+)["']?\s*$/m)?.[1]?.trim();
  return { root: full, files: validateShareFiles(kind, files), skipped, defaultName: frontmatterName || basename(full) };
}

// --- workspace API ------------------------------------------------------------------------

export type SharedListing = {
  slug: string; name: string; description: string; kind: ShareKind; author: string | null; mine: boolean; installs: number; updatedAt: string;
  version: number | null; contentHash: string | null; score: number | null;
  pending: { version: number; status: string; note: string | null } | null;
};
export type PublishResult = { slug: string; version: number; status: "APPROVED" | "PENDING_REVIEW"; unchanged: boolean; score: number; level: string; findings: Array<{ id: string; title: string; severity: string; file: string; line: number }> };
export type Download = { slug: string; name: string; kind: ShareKind; description: string; version: number; contentHash: string; score: number; files: ShareFile[] };

async function call<T>(identity: Identity, method: string, path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${identity.apiBase}${path}`, {
      method,
      headers: { Authorization: `Bearer ${identity.deviceSecret}`, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new Error(`Could not reach ${identity.apiBase}.`);
  }
  let json: { error?: string } & Record<string, unknown> = {};
  try { json = await response.json() as typeof json; } catch { /* non-JSON error page */ }
  if (response.status === 401) throw new Error("This device's credentials were revoked. Run 'beam setup' again.");
  if (!response.ok) {
    if (response.status === 404 && !json.error) throw new Error("This workspace doesn't have the team library yet.");
    throw new Error(json.error ?? `The workspace answered ${response.status}.`);
  }
  return json as T;
}

export const listShares = (identity: Identity, kind?: ShareKind) =>
  call<{ sharing: string; assets: SharedListing[] }>(identity, "GET", `/v1/shares${kind ? `?kind=${kind}` : ""}`);
export const publishShare = (identity: Identity, input: { kind: ShareKind; name: string; slug: string; description: string; changelog: string; files: ShareFile[] }) =>
  call<PublishResult>(identity, "POST", "/v1/shares", input);
export const deleteShare = (identity: Identity, slug: string) => call<{ slug: string }>(identity, "DELETE", `/v1/shares/${encodeURIComponent(slug)}`);
async function downloadShare(identity: Identity, slug: string, version?: number): Promise<Download> {
  if (!SLUG.test(slug)) throw new Error(`"${slug}" isn't a valid share name.`);
  return call<Download>(identity, "POST", `/v1/shares/${slug}/install${version ? `?version=${version}` : ""}`);
}

// --- installing -----------------------------------------------------------------------------

export type InstallOptions = { version?: number; agent?: string[]; allAgents?: boolean; global?: boolean; force?: boolean; cwd?: string; home?: string };
type LockEntry = { slug: string; kind: ShareKind; version: number; contentHash: string; localHash: string; installedAt: string };
type Lock = Record<string, LockEntry>; // keyed by the installed path

const lockFile = () => join(getDataDirectory(), "shared-installs.json");
export async function readLock(): Promise<Lock> {
  try { return JSON.parse(await readFile(lockFile(), "utf8")) as Lock; } catch { return {}; }
}
async function writeLock(lock: Lock) {
  await mkdir(getDataDirectory(), { recursive: true, mode: 0o700 });
  const temp = `${lockFile()}.tmp`;
  await writeFile(temp, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o600 });
  await rename(temp, lockFile());
}

const GLOBAL_INSTRUCTIONS: Record<string, string> = { "CLAUDE.md": ".claude/CLAUDE.md", "AGENTS.md": ".codex/AGENTS.md", "GEMINI.md": ".gemini/GEMINI.md" };

/** Where a share goes: one folder per agent for a skill, one file for everything else. */
export function installTargets(kind: ShareKind, slug: string, fileName: string, options: InstallOptions = {}): string[] {
  const base = options.global ? (options.home ?? homedir()) : (options.cwd ?? process.cwd());
  if (kind === "SKILL") {
    const agents = options.allAgents ? Object.keys(SKILL_TARGETS) : options.agent?.length ? options.agent : ["claude-code"];
    for (const a of agents) if (!SKILL_TARGETS[a]) throw new Error(`Unknown agent "${a}". Choose from: ${Object.keys(SKILL_TARGETS).join(", ")}.`);
    return [...new Set(agents.map(a => join(base, SKILL_TARGETS[a][options.global ? "global" : "project"], slug)))];
  }
  if (kind === "INSTRUCTIONS") return [join(base, options.global ? GLOBAL_INSTRUCTIONS[fileName] ?? fileName : fileName)];
  if (kind === "COMMAND") return [join(base, ".claude/commands", `${slug}.md`)];
  if (kind === "SUBAGENT") return [join(base, ".claude/agents", `${slug}.md`)];
  if (options.global) throw new Error("Cursor rules are per project; run without -g inside the project.");
  return [join(base, ".cursor/rules", `${slug}${fileName.endsWith(".mdc") ? ".mdc" : ".md"}`)];
}

async function exists(path: string) { try { await lstat(path); return true; } catch { return false; } }

/** Hash of what's on disk at an install path, to tell "still as we installed it" from "edited locally". */
async function localHash(path: string): Promise<string | null> {
  try {
    const info = await lstat(path);
    if (info.isFile()) return sha256(await readFile(path, "utf8"));
    if (!info.isDirectory()) return null;
    const files: ShareFile[] = [];
    const walk = async (dir: string): Promise<void> => {
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        const abs = join(dir, entry.name);
        if (entry.isDirectory()) await walk(abs);
        else if (entry.isFile()) files.push({ path: relative(path, abs).split(sep).join("/"), content: await readFile(abs, "utf8") });
      }
    };
    await walk(path);
    return contentHash(files);
  } catch { return null; }
}

// Writes into `target` only: every path is re-validated and must resolve inside it.
async function writeTree(target: string, files: ShareFile[]) {
  await mkdir(target, { recursive: true, mode: 0o755 });
  for (const f of files) {
    if (pathProblem(f.path)) throw new Error(`Refusing unsafe path "${f.path}".`);
    const dest = resolve(target, f.path);
    if (!dest.startsWith(resolve(target) + sep)) throw new Error(`Refusing path outside the install folder: "${f.path}".`);
    await mkdir(dirname(dest), { recursive: true, mode: 0o755 });
    await writeFile(dest, f.content, { mode: 0o644 }); // never executable
  }
}

export type InstallResult = { slug: string; name: string; kind: ShareKind; version: number; installed: string[]; backups: string[]; scan: SkillScan; blocked: boolean; conflicts: string[] };

async function placeDownload(download: Download, dests: string[], force: boolean): Promise<InstallResult> {
  // Never trust the response: same validation as an upload, and the hash must match the workspace's.
  const files = validateShareFiles(download.kind, download.files.map(f => ({ path: String(f.path), content: String(f.content) })));
  if (contentHash(files) !== download.contentHash) throw new Error(`The download of "${download.slug}" doesn't match its content hash. Nothing was installed.`);

  const staging = await mkdtemp(join(tmpdir(), "beam-share-"));
  try {
    const stagedRoot = join(staging, download.slug);
    await writeTree(stagedRoot, files);
    // beam's own full skill scan on this machine, on top of the workspace's.
    const scan = download.kind === "SKILL" ? await scanSkillDir(stagedRoot, download.slug) : await scanSkillFile(join(stagedRoot, files[0].path));
    const result: InstallResult = { slug: download.slug, name: download.name, kind: download.kind, version: download.version, installed: [], backups: [], scan, blocked: false, conflicts: [] };
    if (isBlocked(scan) && !force) { result.blocked = true; return result; }

    const lock = await readLock();
    for (const dest of dests) {
      if (await exists(dest)) {
        if ((await lstat(dest)).isSymbolicLink()) throw new Error(`${dest} is a symlink; refusing to write through it.`);
        const ours = lock[dest];
        const untouched = ours && ours.slug === download.slug && (await localHash(dest)) === ours.localHash;
        if (!untouched && !force) { result.conflicts.push(dest); continue; }
        if (!untouched) {
          const backup = `${dest}.beam-backup-${new Date().toISOString().replace(/[:.]/g, "-")}`;
          await rename(dest, backup);
          result.backups.push(backup);
        }
      }
      await mkdir(dirname(dest), { recursive: true });
      // Write beside the destination, then swap it in, so a failure never leaves half a skill.
      const temp = `${dest}.beam-tmp-${randomBytes(4).toString("hex")}`;
      try {
        if (download.kind === "SKILL") await writeTree(temp, files);
        else await writeFile(temp, files[0].content, { mode: 0o644 });
        await rm(dest, { recursive: true, force: true });
        await rename(temp, dest);
      } finally {
        await rm(temp, { recursive: true, force: true });
      }
      lock[dest] = { slug: download.slug, kind: download.kind, version: download.version, contentHash: download.contentHash, localHash: (await localHash(dest)) ?? "", installedAt: new Date().toISOString() };
      result.installed.push(dest);
    }
    await writeLock(lock);
    return result;
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

export async function installShare(identity: Identity, slug: string, options: InstallOptions = {}): Promise<InstallResult> {
  const download = await downloadShare(identity, slug, options.version);
  const fileName = download.files[0]?.path ?? "";
  return placeDownload(download, installTargets(download.kind, download.slug, fileName, options), Boolean(options.force));
}

export type UpdateReport = { updated: InstallResult[]; current: string[]; removed: Array<{ slug: string; paths: string[] }> };

/** Brings every installed share (or one) up to its newest approved version, in the places it was installed. */
export async function updateShares(identity: Identity, options: { slug?: string; force?: boolean } = {}): Promise<UpdateReport> {
  const lock = await readLock();
  const bySlug = new Map<string, string[]>();
  for (const [path, entry] of Object.entries(lock)) if (!options.slug || entry.slug === options.slug) bySlug.set(entry.slug, [...(bySlug.get(entry.slug) ?? []), path]);
  if (options.slug && !bySlug.size) throw new Error(`"${options.slug}" isn't installed on this device. Install it with 'beam share install ${options.slug}'.`);
  const { assets } = await listShares(identity);
  const latest = new Map(assets.map(a => [a.slug, a.version]));
  const report: UpdateReport = { updated: [], current: [], removed: [] };
  for (const [slug, paths] of bySlug) {
    const available = latest.get(slug);
    if (available === undefined) { report.removed.push({ slug, paths }); continue; }
    if (available === null || paths.every(p => lock[p].version >= available)) { report.current.push(slug); continue; }
    report.updated.push(await placeDownload(await downloadShare(identity, slug), paths, Boolean(options.force)));
  }
  return report;
}
