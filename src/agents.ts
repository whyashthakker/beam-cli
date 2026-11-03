import { HOOK_CATALOG, hookKind } from "./hook-catalog.js";
import { mergeHookSpec, unmergeHookSpec } from "./hook-config.js";
import { join } from "node:path";

export type Obj = Record<string, unknown>;

export interface AgentDefinition {
  id: string;
  name: string;
  /** Paths (relative to home) checked for config presence during discovery. */
  configs: string[];
  /** Paths (relative to home) checked for session/transcript artifacts during discovery. */
  artifacts: string[];
  /** Path (relative to home) beam writes the hook configuration into. */
  hookConfigPath: string | null;
  pluginPath?: string | null;
  /** Event name this agent's hook contract uses for a pre-action gate (documented casing). */
  hookEventName: string | null;
  hookEvents?: string[];
  /**
   * Merge beam's hook entry into this agent's existing hook config (parsed JSON, or {} if the
   * file didn't exist yet). Must be idempotent — safe to call repeatedly without duplicating.
   */
  mergeHookConfig: ((existing: Obj, command: string) => Obj) | null;
  /**
   * Reverse of mergeHookConfig — strips beam's hook entry back out, leaving any other hooks the
   * agent or the user configured untouched. Must be idempotent — safe to call on a config that
   * never had beam installed (a no-op). Takes a predicate rather than an exact command string:
   * a hook's command embeds the absolute path to whichever beam install wrote it (see
   * resolveHookCommand in install.ts), which differs between a global npm install, a local dev
   * checkout, or the same install after 'beam update' changes its resolved path. An uninstall
   * running from a *different* beam install than the one that wrote the entry must still
   * recognize and remove it -- matching only one exact string silently leaves it in place (and
   * beam fully monitoring/enforcing) instead. See isOwnHookCommand in install.ts.
   */
  unmergeHookConfig: ((existing: Obj, isOwnCommand: (command: string) => boolean) => Obj) | null;
  /** Payload adapter id used by src/hook-adapters.ts to normalize this agent's stdin JSON. */
  adapter: "passthrough" | "copilot-camel" | "generic" | "gemini" | "pre-tool-alias";
  /** Whether the AGENT ITSELF (not just this entry's payload verification) is unverified — the
   * ecosystem around it is too new or too fragmented (e.g. many competing third-party CLIs with
   * no single canonical hook contract) to trust as a merge target yet. Detection-only. */
  unverifiedEcosystem?: boolean;
  /** Whether the adapter above was verified against vendor documentation (vs. best-effort). */
  verifiedPayload: boolean;
  notes: string;
  /** Agents whose hook is not a mergeable JSON file; src/agent-installers.ts installs them. */
  customInstall?: boolean;
}

export const AGENTS: AgentDefinition[] = HOOK_CATALOG.map(spec => ({
  id: spec.id, name: spec.name, configs: spec.id === "copilot-cli" ? [".copilot/config.json"] : [spec.detect], artifacts: ({ "claude-code": [".claude/projects"], codex: [".codex/sessions", ".codex/archived_sessions"], cursor: [".cursor/projects"], "copilot-cli": [".copilot/session-state"], gemini: [".gemini/tmp"], opencode: [".local/share/opencode"] } as Record<string, string[]>)[spec.id] ?? [],
  hookConfigPath: spec.format === "plugin" ? null : spec.path,
  pluginPath: spec.format === "plugin" ? spec.path : null,
  hookEventName: spec.events.find(e => hookKind(e) === "pre") ?? null,
  hookEvents: spec.events,
  customInstall: true,
  mergeHookConfig: (existing, command) => mergeHookSpec(spec, existing, command),
  unmergeHookConfig: (existing, own) => unmergeHookSpec(spec, existing, own),
  adapter: ["claude-code", "codex", "cursor"].includes(spec.id) ? "passthrough" : spec.id === "hermes" ? "pre-tool-alias" : spec.id === "copilot-cli" || spec.id === "vscode" ? "copilot-camel" : spec.id === "gemini" ? "gemini" : "generic",
  verifiedPayload: ["claude-code", "codex", "cursor", "copilot-cli", "gemini", "hermes"].includes(spec.id),
  notes: "Configuration and payload mapping based on Numbat's host contracts; validate with a live session on your agent version. See docs/agent-hooks.md.",
}));
AGENTS.push(
{
    id: "jev", name: "Jev (TypeSafe AI)",
    // TypeSafe's own Jev tooling and at least half a dozen independent third-party CLIs
    // (jev-cli, jev-axi, jev-guard, ...) each pick their own config layout, so unlike the
    // agents above there's no single vendor-documented directory or hook contract to target.
    // These are the paths seen across that ecosystem as of Sept 2026; treat as best-effort.
    configs: [".config/jev", ".config/jev-axi", ".jev"], artifacts: [".config/jev-axi/stats"],
    hookConfigPath: null, hookEventName: null,
    mergeHookConfig: null, unmergeHookConfig: null,
    adapter: "generic", verifiedPayload: false, unverifiedEcosystem: true,
    notes: "Jev is TypeSafe AI's non-generative 'System One' judgment model (launched 2026-09-15), " +
      "increasingly wired into other agents' tool-call gating (e.g. jev-guard) rather than run as " +
      "a coding agent itself. No single vendor hook contract exists yet across the many third-party " +
      "CLIs wrapping it, so this entry is discovery-only (config/artifact presence), not installable."
  });

export function findAgent(id: string): AgentDefinition | undefined {
  return AGENTS.find(a => a.id === id);
}

export function hookConfigFullPath(agent: AgentDefinition, home: string): string {
  if (!agent.hookConfigPath) throw new Error(`${agent.name} has no supported hook config file yet.`);
  return join(home, agent.hookConfigPath);
}
