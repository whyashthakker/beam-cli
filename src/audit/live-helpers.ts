// Shared helper for every live (real API call) check: the workspace folder VS Code's Claude
// extension is actually, currently connected to. Per-agent binary lookup and prompt execution now
// live in live-agent-adapters.ts.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AuditContext } from "./types.js";

export function connectedVsCodeWorkspace(ctx: AuditContext): string | null {
  const dir = join(ctx.home, ".claude", "ide");
  if (!existsSync(dir)) return null;
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".lock")) continue;
    try {
      const data = JSON.parse(readFileSync(join(dir, file), "utf8"));
      const folder = data?.workspaceFolders?.[0];
      if (data?.ideName && folder) return folder;
    } catch { /* stale lock file */ }
  }
  return null;
}
