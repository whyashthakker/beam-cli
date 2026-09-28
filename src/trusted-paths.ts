import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { getDataDirectory } from "./config.js";

// A global, human-maintained allowlist of outside-workspace paths/globs that should stop
// triggering Beam's "This action accesses a path outside the current workspace" ask. Lives
// under the data directory -- the same directory isBeamSelfProtectionTarget() already protects
// from agent writes -- so only a human running `beam trust` from a real shell can add to it, not
// an agent trying to approve its own escape.
export function trustedPathsFile(): string { return join(getDataDirectory(), "trusted-paths.json"); }

export async function readTrustedPaths(): Promise<string[]> {
  try {
    const parsed = JSON.parse(await readFile(trustedPathsFile(), "utf8"));
    return Array.isArray(parsed) ? parsed.filter((p): p is string => typeof p === "string" && p.trim().length > 0) : [];
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    return [];
  }
}

async function writeTrustedPaths(paths: string[]): Promise<void> {
  const dir = getDataDirectory();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const file = trustedPathsFile();
  const temp = `${file}.tmp`;
  await writeFile(temp, JSON.stringify(paths, null, 2) + "\n", { mode: 0o600 });
  await rename(temp, file);
}

export async function addTrustedPath(path: string): Promise<string[]> {
  const resolved = resolve(path);
  const current = await readTrustedPaths();
  if (current.includes(resolved)) return current;
  const next = [...current, resolved];
  await writeTrustedPaths(next);
  return next;
}

export async function removeTrustedPath(path: string): Promise<string[]> {
  const resolved = resolve(path);
  const next = (await readTrustedPaths()).filter(p => p !== resolved);
  await writeTrustedPaths(next);
  return next;
}

// A candidate path is trusted if it equals a trusted entry or sits under one (directory trust).
// Entries may also be globs (containing `*`) matched against the candidate.
export function isPathTrusted(candidate: string, trusted: string[]): boolean {
  const target = resolve(candidate);
  return trusted.some(entry => {
    if (entry.includes("*")) {
      const escaped = entry.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "§§").replace(/\*/g, "[^/]*").replace(/§§/g, ".*");
      return new RegExp(`^${escaped}$`).test(target);
    }
    if (target === entry) return true;
    const rel = relative(entry, target);
    return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
  });
}
