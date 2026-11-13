// Policy 3.5 Prohibited Configurations: "Use of unofficial, forked, or third-party Claude Code
// clients not distributed by Anthropic is explicitly prohibited." Checked via package.json
// dependency names rather than inspecting the installed binary, since a name that isn't the official
// package but matches "claude-code" is the clearest static signal this scanner can reach without
// shelling out to npm registry lookups for every scanned repo.
import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { AuditContext, Check } from "../types.js";

const OFFICIAL_PACKAGE = "@anthropic-ai/claude-code";

function readJson(path: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

export function unofficialClientCheck(ctx: AuditContext): Check {
  const suspicious: string[] = [];
  for (const repo of ctx.repos) {
    const pkg = readJson(join(repo, "package.json"));
    if (!pkg) continue;
    const deps = { ...(pkg.dependencies as Record<string, string> ?? {}), ...(pkg.devDependencies as Record<string, string> ?? {}) };
    for (const [name, version] of Object.entries(deps)) {
      if (name === OFFICIAL_PACKAGE) continue;
      if (/claude-code/i.test(name)) suspicious.push(`${relative(ctx.home, repo)}/package.json: "${name}": "${version}"`);
    }
  }
  return {
    id: "3.5-unofficial-client",
    policySection: "3.5 (Prohibited Configurations)",
    title: "No unofficial/forked Claude Code client referenced",
    status: suspicious.length > 0 ? "warn" : "pass",
    detail: suspicious.length > 0
      ? `${suspicious.length} dependency reference(s) look like a Claude Code fork rather than the official ${OFFICIAL_PACKAGE} package. This can be a legitimate unrelated package that merely has "claude-code" in its name -- verify before treating it as a violation.`
      : "No package.json dependencies resembling an unofficial Claude Code client were found.",
    evidence: suspicious.slice(0, 50),
    fix: suspicious.length > 0 ? `Confirm each listed dependency is not a Claude Code fork; the only permitted client is ${OFFICIAL_PACKAGE} installed from the official npm registry.` : undefined,
  };
}
