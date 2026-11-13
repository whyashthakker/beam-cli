// Walks the filesystem for git repositories so the audit can check every project on the machine,
// not just the one you happen to run it from.
import { readdirSync, lstatSync } from "node:fs";
import { join } from "node:path";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".cache", "coverage",
  "Library", "Applications", ".Trash", ".npm", ".nvm", ".cargo", ".rustup",
  "venv", ".venv", "__pycache__", ".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100",
]);

export function discoverRepos(roots: string[], options: { maxDepth?: number; maxRepos?: number } = {}): string[] {
  const maxDepth = options.maxDepth ?? 6;
  const maxRepos = options.maxRepos ?? 500;
  const repos: string[] = [];
  const seen = new Set<string>();

  function walk(dir: string, depth: number): void {
    if (repos.length >= maxRepos || depth > maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    if (entries.includes(".git")) {
      if (!seen.has(dir)) { seen.add(dir); repos.push(dir); }
      return;
    }
    for (const entry of entries) {
      if (entry.startsWith(".") && entry !== ".git") continue;
      if (SKIP_DIRS.has(entry)) continue;
      const full = join(dir, entry);
      let st;
      try {
        st = lstatSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(full, depth + 1);
    }
  }

  for (const root of roots) walk(root, 0);
  return repos;
}
