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
  /** Event name this agent's hook contract uses for a pre-action gate (documented casing). */
  hookEventName: string | null;
  /**
   * Merge beam's hook entry into this agent's existing hook config (parsed JSON, or {} if the
   * file didn't exist yet). Must be idempotent — safe to call repeatedly without duplicating.
   */
  mergeHookConfig: ((existing: Obj, command: string) => Obj) | null;
  /**
   * Reverse of mergeHookConfig — strips beam's hook entry back out, leaving any other hooks the
   * agent or the user configured untouched. Must be idempotent — safe to call on a config that
   * never had beam installed (a no-op).
   */
  unmergeHookConfig: ((existing: Obj, command: string) => Obj) | null;
  /** Payload adapter id used by src/hook-adapters.ts to normalize this agent's stdin JSON. */
  adapter: "passthrough" | "copilot-camel" | "generic";
  /** Whether the adapter above was verified against vendor documentation (vs. best-effort). */
  verifiedPayload: boolean;
  notes: string;
}

function obj(v: unknown): Obj { return v && typeof v === "object" && !Array.isArray(v) ? v as Obj : {}; }
function arr(v: unknown): unknown[] { return Array.isArray(v) ? v : []; }

// Claude Code, Codex, and Cursor all install into a `hooks.<Event>` array of
// `{ matcher, hooks: [{ type: "command", command }] }` entries (Claude Code's own shape).
function mergeClaudeStyleHooks(event: string) {
  return (existing: Obj, command: string): Obj => {
    const hooks = obj(existing.hooks);
    const list = arr(hooks[event]).map(obj);
    const alreadyInstalled = list.some(entry => arr(entry.hooks).map(obj).some(h => h.command === command));
    if (!alreadyInstalled) list.push({ matcher: "", hooks: [{ type: "command", command }] });
    return { ...existing, hooks: { ...hooks, [event]: list } };
  };
}

// Cursor's own hooks.json instead nests `{ command, matcher }` directly under the event array.
function mergeCursorHooks(event: string) {
  return (existing: Obj, command: string): Obj => {
    const hooks = obj(existing.hooks);
    const list = arr(hooks[event]).map(obj);
    if (!list.some(entry => entry.command === command)) list.push({ command, matcher: ".*" });
    return { version: existing.version ?? 1, ...existing, hooks: { ...hooks, [event]: list } };
  };
}

// Copilot CLI's dedicated hook file uses `{ type: "command", bash, timeoutSec }` entries.
function mergeCopilotHooks(event: string) {
  return (existing: Obj, command: string): Obj => {
    const hooks = obj(existing.hooks);
    const list = arr(hooks[event]).map(obj);
    if (!list.some(entry => entry.bash === command)) list.push({ type: "command", bash: command, timeoutSec: 30 });
    return { version: existing.version ?? 1, ...existing, hooks: { ...hooks, [event]: list } };
  };
}

// Reverse of mergeClaudeStyleHooks: drops beam's command out of each entry's inner hooks array
// (rather than the whole entry), so a user-added hook sharing the same matcher is left alone.
function unmergeClaudeStyleHooks(event: string) {
  return (existing: Obj, command: string): Obj => {
    const hooks = obj(existing.hooks);
    if (!(event in hooks)) return existing;
    const list = arr(hooks[event]).map(obj)
      .map(entry => ({ ...entry, hooks: arr(entry.hooks).map(obj).filter(h => h.command !== command) }))
      .filter(entry => arr(entry.hooks).length > 0);
    return { ...existing, hooks: { ...hooks, [event]: list } };
  };
}

// Reverse of mergeCursorHooks.
function unmergeCursorHooks(event: string) {
  return (existing: Obj, command: string): Obj => {
    const hooks = obj(existing.hooks);
    if (!(event in hooks)) return existing;
    const list = arr(hooks[event]).map(obj).filter(entry => entry.command !== command);
    return { ...existing, hooks: { ...hooks, [event]: list } };
  };
}

// Reverse of mergeCopilotHooks.
function unmergeCopilotHooks(event: string) {
  return (existing: Obj, command: string): Obj => {
    const hooks = obj(existing.hooks);
    if (!(event in hooks)) return existing;
    const list = arr(hooks[event]).map(obj).filter(entry => entry.bash !== command);
    return { ...existing, hooks: { ...hooks, [event]: list } };
  };
}

export const AGENTS: AgentDefinition[] = [
  {
    id: "claude-code", name: "Claude Code",
    configs: [".claude/settings.json"], artifacts: [".claude/projects"],
    hookConfigPath: ".claude/settings.json", hookEventName: "PreToolUse",
    mergeHookConfig: mergeClaudeStyleHooks("PreToolUse"), unmergeHookConfig: unmergeClaudeStyleHooks("PreToolUse"),
    adapter: "passthrough", verifiedPayload: true,
    notes: "Payload verified against code.claude.com/docs/en/hooks."
  },
  {
    id: "codex", name: "Codex",
    configs: [".codex/config.toml"], artifacts: [".codex/sessions", ".codex/archived_sessions"],
    hookConfigPath: ".codex/hooks.json", hookEventName: "PreToolUse",
    mergeHookConfig: mergeClaudeStyleHooks("PreToolUse"), unmergeHookConfig: unmergeClaudeStyleHooks("PreToolUse"),
    adapter: "passthrough", verifiedPayload: true,
    notes: "Same hooks.json shape and stdin payload fields as Claude Code (session_id, cwd, hook_event_name, tool_name, tool_input, tool_use_id)."
  },
  {
    id: "cursor", name: "Cursor",
    // ".cursor/hooks.json" is the file beam itself writes on install, so it can never be used to
    // detect a pre-existing Cursor install (circular). The bare ".cursor" directory is what
    // Cursor itself creates just from being used, so it's a real presence signal.
    configs: [".cursor"], artifacts: [".cursor/projects"],
    hookConfigPath: ".cursor/hooks.json", hookEventName: "preToolUse",
    mergeHookConfig: mergeCursorHooks("preToolUse"), unmergeHookConfig: unmergeCursorHooks("preToolUse"),
    adapter: "passthrough", verifiedPayload: true,
    notes: "Payload verified against cursor.com/docs/hooks; extra fields (model, conversation_id, ...) are ignored, not misread."
  },
  {
    id: "copilot-cli", name: "GitHub Copilot CLI",
    // Same circularity as Cursor above: ".copilot/hooks/beam.json" is our own output.
    // ".copilot/config.json" is what the real Copilot CLI writes on its own first run.
    configs: [".copilot/config.json"], artifacts: [".copilot/session-state"],
    hookConfigPath: ".copilot/hooks/beam.json", hookEventName: "preToolUse",
    mergeHookConfig: mergeCopilotHooks("preToolUse"), unmergeHookConfig: unmergeCopilotHooks("preToolUse"),
    adapter: "copilot-camel", verifiedPayload: true,
    notes: "Payload verified against docs.github.com Copilot hooks reference (camelCase: sessionId, cwd, toolName, toolArgs)."
  },
  {
    id: "gemini", name: "Gemini CLI",
    // settings.json only exists once hooks/other settings are configured; the bare ".gemini"
    // directory (created by any use of the Gemini CLI, e.g. mcp_config.json, projects/) is the
    // reliable presence signal.
    configs: [".gemini", ".gemini/settings.json"], artifacts: [".gemini/tmp"],
    hookConfigPath: ".gemini/settings.json", hookEventName: "BeforeTool",
    mergeHookConfig: mergeClaudeStyleHooks("BeforeTool"), unmergeHookConfig: unmergeClaudeStyleHooks("BeforeTool"),
    adapter: "generic", verifiedPayload: false,
    notes: "Config wiring only. Gemini CLI's BeforeTool stdin schema is not published; capture uses a best-effort generic field adapter and may miss fields."
  },
  {
    id: "opencode", name: "OpenCode",
    configs: [".config/opencode/opencode.json", ".config/opencode/opencode.jsonc"], artifacts: [".local/share/opencode"],
    hookConfigPath: null, hookEventName: null,
    mergeHookConfig: null, unmergeHookConfig: null, adapter: "generic", verifiedPayload: false,
    notes: "OpenCode uses a generated TypeScript plugin, not a JSON hook file; beam does not generate plugin code yet. Discovery only."
  },
];

export function findAgent(id: string): AgentDefinition | undefined {
  return AGENTS.find(a => a.id === id);
}

export function hookConfigFullPath(agent: AgentDefinition, home: string): string {
  if (!agent.hookConfigPath) throw new Error(`${agent.name} has no supported hook config file yet.`);
  return join(home, agent.hookConfigPath);
}
