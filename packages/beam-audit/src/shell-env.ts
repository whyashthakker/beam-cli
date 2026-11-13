// Shared helper: shell startup files, read once per check rather than duplicated per module.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const RC_FILES = [".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"];

export function readShellRcFiles(home: string): Array<{ path: string; text: string }> {
  const out: Array<{ path: string; text: string }> = [];
  for (const name of RC_FILES) {
    const path = join(home, name);
    if (!existsSync(path)) continue;
    try {
      out.push({ path, text: readFileSync(path, "utf8") });
    } catch { /* unreadable */ }
  }
  return out;
}
