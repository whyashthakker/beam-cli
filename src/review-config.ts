import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { getBeamHome } from "./config.js";
import { ensureWorkspaceConfig, workspaceRoot } from "./workspace-config.js";
import { parseRemoteUrl } from "./repo-remote.js";
import type { PolicyBundle } from "./policy.js";

export interface ReviewRequirements {
  edits?: boolean;
  commits?: boolean;
  commands?: boolean;
  securityPaths?: string[];
  isolatedPaths?: string[];
}
function read(path: string): Record<string, unknown> | undefined {
  try {
    const value = JSON.parse(readFileSync(path, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected object");
    return value;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new Error(`Invalid review config: ${path}`);
  }
}
function validate(value: unknown): ReviewRequirements {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("review must be an object");
  const r = value as Record<string, unknown>;
  for (const key of Object.keys(r)) {
    if (["edits", "commits", "commands"].includes(key)) { if (typeof r[key] !== "boolean") throw new Error(`${key} must be boolean`); }
    else if (["securityPaths", "isolatedPaths"].includes(key)) { if (!Array.isArray(r[key]) || (r[key] as unknown[]).some(p => typeof p !== "string" || !p.trim())) throw new Error(`${key} must contain paths`); }
    else throw new Error(`Unknown review setting: ${key}`);
  }
  return r as ReviewRequirements;
}
export function repositoryIdentity(cwd: string): string | undefined {
  const root = workspaceRoot(cwd);
  if (!root) return undefined;
  const result = spawnSync("git", ["-C", root, "remote", "get-url", "origin"], { encoding: "utf8", timeout: 3000 });
  const remote = result.status === 0 ? parseRemoteUrl(result.stdout.trim()) : undefined;
  return remote ? `${remote.host.toLowerCase()}/${remote.path}` : undefined;
}
/** Trusted organization settings are applied after repository-owned settings. */
export function applyReviewConfig(bundle: PolicyBundle | null, cwd: string): PolicyBundle | null {
  try {
    const config = ensureWorkspaceConfig(cwd);
    const local = config ? read(config) : undefined;
    const org = read(join(getBeamHome(), ".config"));
    const id = repositoryIdentity(cwd);
    const repositories = org?.repositories;
    if (repositories !== undefined && (!repositories || typeof repositories !== "object" || Array.isArray(repositories))) throw new Error("repositories must be an object");
    const scoped = id && repositories ? (repositories as Record<string, unknown>)[id] : undefined;
    const merged: ReviewRequirements = {};
    for (const source of [local?.review, org?.review, scoped]) {
      if (source === undefined) continue;
      const r = validate(source);
      for (const key of ["edits", "commits", "commands"] as const) if (r[key] !== undefined) merged[key] = Boolean(merged[key] || r[key]);
      for (const key of ["securityPaths", "isolatedPaths"] as const) if (r[key]) merged[key] = [...new Set([...(merged[key] ?? []), ...r[key]!])];
    }
    if (!Object.keys(merged).length) return bundle;
    return { version: 0, notAfter: null, ...bundle, rules: { mode: "observe", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [], ...bundle?.rules, review: merged } };
  } catch (error) {
    return { version: 0, notAfter: null, ...bundle, errors: [...(bundle?.errors ?? []), String(error)], rules: { mode: "enforce", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [], ...bundle?.rules } };
  }
}
