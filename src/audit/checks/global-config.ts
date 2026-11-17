// Policy 4.2: is there anything in the user's Claude Code configuration -- global or per-repo --
// that would stop prohibited data (credentials, PII, PHI, customer data, trade secrets, network
// topology) from reaching a prompt? Pure config inspection: no network calls, nothing executed.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { AuditContext, Check } from "../types.js";

function readJson(path: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

function hooksEvents(settings: Record<string, unknown> | null): string[] {
  const hooks = settings?.hooks as Record<string, unknown> | undefined;
  return hooks ? Object.keys(hooks) : [];
}

/** Any PreToolUse/UserPromptSubmit hook command is a candidate for something that could redact or
 * block sensitive content before it reaches the model -- we can't tell what a third-party hook
 * actually does, only that one exists on the events that matter for this policy clause. */
function hasPromptOrToolHook(settings: Record<string, unknown> | null): boolean {
  const events = hooksEvents(settings);
  return events.includes("PreToolUse") || events.includes("UserPromptSubmit");
}

export function globalConfigCheck(ctx: AuditContext): Check[] {
  const checks: Check[] = [];
  const globalSettingsPath = join(ctx.home, ".claude", "settings.json");
  const globalSettings = readJson(globalSettingsPath);

  if (!existsSync(globalSettingsPath)) {
    checks.push({
      id: "global-no-settings",
      policySection: "4.2",
      title: "Global Claude Code configuration",
      status: "warn",
      detail: "No global Claude settings file found. Global prompt/tool hook protection could not be verified; project or managed controls may exist.",
      fix: "Install a guardrail (e.g. `npm i -g @agent-beam/beam && beam setup`) so prompts and tool calls are scanned before they leave the machine.",
      evidence: [globalSettingsPath],
    });
  } else {
    const hooked = hasPromptOrToolHook(globalSettings);
    checks.push({
      id: "global-hook-present",
      policySection: "4.2",
      title: "Global Claude Code configuration",
      status: hooked ? "pass" : "warn",
      detail: hooked
        ? `~/.claude/settings.json has a hook on ${hooksEvents(globalSettings).join(", ")}.`
        : `~/.claude/settings.json exists but has no PreToolUse or UserPromptSubmit hook, in this file. Other policy layers were not evaluated.`,
      fix: hooked ? undefined : "Add a PreToolUse/UserPromptSubmit hook (e.g. via `beam setup`) that scans for credentials, PII, PHI and internal network info before a prompt or tool call reaches the model.",
      evidence: [globalSettingsPath],
    });
  }

  // Per-repo settings override or add to the global ones; a repo with none relies entirely on
  // whatever (if anything) is configured globally, which the check above already covered.
  const repoHookCoverage: string[] = [];
  const repoNoHook: string[] = [];
  for (const repo of ctx.repos) {
    const repoSettingsPath = join(repo, ".claude", "settings.json");
    if (!existsSync(repoSettingsPath)) continue; // falls back to global, already assessed
    const settings = readJson(repoSettingsPath);
    if (hasPromptOrToolHook(settings)) repoHookCoverage.push(repo);
    else repoNoHook.push(repo);
  }
  if (repoNoHook.length > 0) {
    checks.push({
      id: "repo-settings-override-no-hook",
      policySection: "4.2",
      title: "Per-repository Claude Code hook declarations",
      status: "warn",
      detail: `${repoNoHook.length} repositories have a .claude/settings.json that does NOT include a PreToolUse/UserPromptSubmit hook. If the global config has one, Claude Code's settings merge rules may still mean the repo-level file adds no extra protection -- but nothing in that repo's own config does.`,
      evidence: repoNoHook.slice(0, 50),
      fix: "Review effective merged global, project, local, and managed settings; verify the required hook actually runs.",
    });
  }

  return checks;
}

/** 5.5-adjacent, but in scope for 4.2: persistent memory can carry forward sensitive content a user
 * typed in a previous session into a new one, outside the user's control at prompt time. */
export function memorySurfaceCheck(ctx: AuditContext): Check {
  const dir = join(ctx.home, ".claude", "projects");
  let hasMemory = false;
  try {
    hasMemory = existsSync(dir) && readdirSync(dir).some(p => existsSync(join(dir, p, "memory")));
  } catch { /* unreadable, treat as absent */ }
  return {
    id: "persistent-memory-surface",
    policySection: "4.2 / 5.5",
    title: "Persistent cross-session memory",
    status: hasMemory ? "warn" : "pass",
    detail: hasMemory
      ? "Cross-session memory files exist under ~/.claude/projects/*/memory. Anything sensitive written there by Claude is carried into future sessions without being re-typed, which widens the data this policy must cover."
      : "No cross-session memory directories found.",
    fix: hasMemory ? "Review ~/.claude/projects/*/memory for sensitive content; disable the feature if the data categories in policy 4.2 could have been captured there." : undefined,
  };
}
