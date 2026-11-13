// Shared helpers for every live (real API call) check: finding the installed `claude` binary and
// the workspace folder VS Code's extension is actually, currently connected to.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import type { AuditContext } from "./types.js";

export function findClaudeBinary(ctx: AuditContext): string | null {
  const res = spawnSync(ctx.platform === "win32" ? "where" : "which", ["claude"], { encoding: "utf8", timeout: 5_000 });
  if (res.status !== 0 || typeof res.stdout !== "string") return null;
  return res.stdout.trim().split("\n")[0] || null;
}

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

export interface ClaudeJsonResult { result?: string; subtype?: string; permission_denials?: unknown[] }

export function runClaudeJson(claudeBin: string, args: string[], cwd: string): ClaudeJsonResult | null {
  const res = spawnSync(claudeBin, args, { cwd, encoding: "utf8", timeout: 60_000, maxBuffer: 8 * 1024 * 1024 });
  if (res.error || typeof res.stdout !== "string" || !res.stdout.trim()) return null;
  try {
    const parsed = JSON.parse(res.stdout) as ClaudeJsonResult;
    if (parsed.subtype && parsed.subtype !== "success") return null;
    return parsed;
  } catch {
    return null;
  }
}
