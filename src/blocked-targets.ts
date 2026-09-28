import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { getDataDirectory } from "./config.js";

// A global, human-maintained denylist -- the "Block always" choice on a warn prompt writes here.
// Lives under the data directory, same as trusted-paths.json: isBeamSelfProtectionTarget() already
// blocks an agent from writing to this directory, so only a human choosing it interactively (or
// running the CLI) can add an entry, never the agent whose own action got blocked.
export function blockedTargetsFile(): string { return join(getDataDirectory(), "blocked-targets.json"); }

export async function readBlockedTargets(): Promise<string[]> {
  try {
    const parsed = JSON.parse(await readFile(blockedTargetsFile(), "utf8"));
    return Array.isArray(parsed) ? parsed.filter((p): p is string => typeof p === "string" && p.trim().length > 0) : [];
  } catch {
    return [];
  }
}

async function writeBlockedTargets(targets: string[]): Promise<void> {
  const dir = getDataDirectory();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const file = blockedTargetsFile();
  const temp = `${file}.tmp`;
  await writeFile(temp, JSON.stringify(targets, null, 2) + "\n", { mode: 0o600 });
  await rename(temp, file);
}

function normalizeEntry(target: string): string {
  return isAbsolute(target) ? resolve(target) : target.trim();
}

export async function addBlockedTarget(target: string): Promise<string[]> {
  const entry = normalizeEntry(target);
  const current = await readBlockedTargets();
  if (current.includes(entry)) return current;
  const next = [...current, entry];
  await writeBlockedTargets(next);
  return next;
}

export async function removeBlockedTarget(target: string): Promise<string[]> {
  const entry = normalizeEntry(target);
  const next = (await readBlockedTargets()).filter(t => t !== entry);
  await writeBlockedTargets(next);
  return next;
}

// Path-glob semantics: "*" matches within one path segment, "**" crosses "/".
function pathGlobMatch(entry: string, value: string): boolean {
  const escaped = entry.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "§§").replace(/\*/g, "[^/]*").replace(/§§/g, ".*");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

// Command-glob semantics: a command line has no path-segment structure, so "*" matches anything,
// including "/" -- otherwise `rm -rf *` would never match `rm -rf /tmp/build`.
function commandGlobMatch(entry: string, value: string): boolean {
  const escaped = entry.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

// Absolute-path entries (the common case -- a file/dir path a user chose "Block always" on) match
// by equality, subdirectory containment, or glob against the current action's path. Anything else
// was recorded from a command line with no clear path (e.g. a risky shell command), so it matches
// as a glob/substring against the current command instead.
export function isTargetBlocked(ctx: { path?: string; command?: string }, blocked: string[]): boolean {
  return blocked.some(entry => {
    if (isAbsolute(entry)) {
      if (!ctx.path) return false;
      const target = resolve(ctx.path);
      if (target === entry) return true;
      const rel = relative(entry, target);
      return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
    }
    if (ctx.command) {
      if (entry.includes("*")) { if (commandGlobMatch(entry, ctx.command)) return true; }
      else if (ctx.command.toLowerCase().includes(entry.toLowerCase())) return true;
    }
    if (ctx.path && entry.includes("*") && pathGlobMatch(entry, ctx.path)) return true;
    return false;
  });
}
