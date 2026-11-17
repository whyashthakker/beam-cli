// Policy 3.5 Prohibited Configurations: "Use of unofficial, forked, or third-party [agent] clients
// not distributed by the vendor is explicitly prohibited." Checked via package.json dependency names
// rather than inspecting the installed binary, since a name that isn't the official package but
// matches a known agent's naming pattern is the clearest static signal this scanner can reach without
// shelling out to a registry lookup for every scanned repo. Covers every agent in the known registry,
// not just Claude Code.
import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { AuditContext, Check } from "../types.js";

// Agent name -> { officialPackage, forkPattern }. forkPattern matches the family of names a fork of
// this client would plausibly carry; officialPackage is excluded from that match.
const KNOWN_CLIENTS: Array<{ agent: string; officialPackage: string; forkPattern: RegExp }> = [
  { agent: "Claude Code", officialPackage: "@anthropic-ai/claude-code", forkPattern: /claude-code/i },
  { agent: "Codex", officialPackage: "@openai/codex", forkPattern: /\bcodex\b/i },
  { agent: "Gemini CLI", officialPackage: "@google/gemini-cli", forkPattern: /gemini-cli/i },
  { agent: "GitHub Copilot CLI", officialPackage: "@github/copilot", forkPattern: /copilot-cli|github-copilot/i },
  { agent: "OpenCode", officialPackage: "opencode-ai", forkPattern: /opencode/i },
  { agent: "Continue", officialPackage: "@continuedev/cli", forkPattern: /\bcontinue-cli\b|continuedev/i },
  { agent: "Aider", officialPackage: "aider-chat", forkPattern: /\baider\b/i },
];

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
      for (const client of KNOWN_CLIENTS) {
        if (name === client.officialPackage) continue;
        if (client.forkPattern.test(name)) { suspicious.push(`${relative(ctx.home, repo)}/package.json: "${name}": "${version}" (looks like a ${client.agent} fork)`); break; }
      }
    }
  }
  return {
    id: "3.5-unofficial-client",
    policySection: "3.5 (Prohibited Configurations)",
    title: "No unofficial/forked agent client referenced",
    status: suspicious.length > 0 ? "warn" : "pass",
    detail: suspicious.length > 0
      ? `${suspicious.length} dependency reference(s) look like a fork of a known agent client rather than its official package (checked against ${KNOWN_CLIENTS.length} known agents: ${KNOWN_CLIENTS.map(c => c.agent).join(", ")}). This can be a legitimate unrelated package that merely matches the name pattern -- verify before treating it as a violation.`
      : `No package.json dependencies resembling an unofficial client fork were found, checked against ${KNOWN_CLIENTS.length} known agents (${KNOWN_CLIENTS.map(c => c.agent).join(", ")}). Agents without a recognizable npm fork-naming pattern (e.g. GUI-only editors distributed outside npm) are not covered by this specific check.`,
    evidence: suspicious.slice(0, 50),
    fix: suspicious.length > 0 ? "Confirm each listed dependency is not an agent-client fork; only the vendor's official package, installed from the official registry, is permitted." : undefined,
  };
}
