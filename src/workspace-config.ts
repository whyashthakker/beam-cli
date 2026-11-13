import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

/** Find the closest Git root, including worktrees whose .git is a file. */
export function workspaceRoot(cwd = process.cwd()): string | undefined {
  let directory = resolve(cwd);
  for (;;) {
    if (existsSync(join(directory, ".git"))) return directory;
    const parent = dirname(directory);
    if (parent === directory) return undefined;
    directory = parent;
  }
}

export function workspacePolicyPath(cwd = process.cwd()): string | undefined {
  const root = workspaceRoot(cwd);
  return root ? join(root, ".beam", "policy.json") : undefined;
}

/** Create once; an empty review object inherits global/organization requirements. */
export function ensureWorkspaceConfig(cwd = process.cwd()): string | undefined {
  const root = workspaceRoot(cwd);
  if (!root) return undefined;
  const directory = join(root, ".beam");
  const file = join(directory, ".config");
  mkdirSync(directory, { recursive: true });
  try {
    writeFileSync(file, JSON.stringify({ review: {} }, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  return file;
}
