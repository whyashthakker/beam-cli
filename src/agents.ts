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
  adapter: "passthrough" | "copilot-camel" | "generic" | "gemini";
  /** Whether the adapter above was verified against vendor documentation (vs. best-effort). */
  verifiedPayload: boolean;
  notes: string;
}

function obj(v: unknown): Obj { return v && typeof v === "object" && !Array.isArray(v) ? v as Obj : {}; }
function arr(v: unknown): unknown[] { return Array.isArray(v) ? v : []; }

// Claude Code, Codex, Cursor, and Gemini CLI all install into a `hooks.<Event>` array of
// `{ matcher, hooks: [{ type: "command", command }] }` entries (Claude Code's own shape, which
// Gemini CLI's settings.json also uses verbatim per geminicli.com/docs/hooks/reference).
// A handful of events -- UserPromptSubmit (Claude/Codex) and BeforeAgent (Gemini) among them --
// have no matcher concept at all (they always fire); the docs' own examples omit the field there
// entirely rather than sending an empty string, so this does the same to avoid relying on an
// "ignored" field being tolerated rather than rejected.
const CLAUDE_STYLE_EVENTS_WITHOUT_MATCHER = new Set(["UserPromptSubmit", "BeforeAgent"]);
function mergeClaudeStyleHooks(event: string) {
  const supportsMatcher = !CLAUDE_STYLE_EVENTS_WITHOUT_MATCHER.has(event);
  return (existing: Obj, command: string): Obj => {
    const hooks = obj(existing.hooks);
    const list = arr(hooks[event]).map(obj);
    const alreadyInstalled = list.some(entry => arr(entry.hooks).map(obj).some(h => h.command === command));
    if (!alreadyInstalled) list.push({ ...(supportsMatcher ? { matcher: "" } : {}), hooks: [{ type: "command", command }] });
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

// Installs beam into more than one hook event (e.g. the tool-call gate *and* the prompt-submit
// gate) by folding each single-event merger over the config in turn. A disabled agent only ever
// reliably stops at the pre-action gate if that agent never calls a tool in a turn (pure chat) --
// registering the prompt-submit event too means a disabled agent's policy.disabledAgents block
// (see policy.ts's evaluate()) fires before the prompt is even processed, not just before a tool
// call that may never come.
function mergeAll(mergers: Array<(existing: Obj, command: string) => Obj>) {
  return (existing: Obj, command: string): Obj => mergers.reduce((acc, merge) => merge(acc, command), existing);
}
function unmergeAll(unmergers: Array<(existing: Obj, command: string) => Obj>) {
  return (existing: Obj, command: string): Obj => unmergers.reduce((acc, unmerge) => unmerge(acc, command), existing);
}

export const AGENTS: AgentDefinition[] = [
  {
    id: "claude-code", name: "Claude Code",
    configs: [".claude/settings.json"], artifacts: [".claude/projects"],
    hookConfigPath: ".claude/settings.json", hookEventName: "PreToolUse",
    mergeHookConfig: mergeAll([mergeClaudeStyleHooks("PreToolUse"), mergeClaudeStyleHooks("UserPromptSubmit")]),
    unmergeHookConfig: unmergeAll([unmergeClaudeStyleHooks("PreToolUse"), unmergeClaudeStyleHooks("UserPromptSubmit")]),
    adapter: "passthrough", verifiedPayload: true,
    notes: "Payload verified against code.claude.com/docs/en/hooks. Also installs UserPromptSubmit (same hookSpecificOutput.permissionDecision contract, just hookEventName: \"UserPromptSubmit\") so a disabled agent is stopped before the prompt is processed, not only at its first tool call."
  },
  {
    id: "codex", name: "Codex",
    configs: [".codex/config.toml"], artifacts: [".codex/sessions", ".codex/archived_sessions"],
    hookConfigPath: ".codex/hooks.json", hookEventName: "PreToolUse",
    mergeHookConfig: mergeAll([mergeClaudeStyleHooks("PreToolUse"), mergeClaudeStyleHooks("UserPromptSubmit")]),
    unmergeHookConfig: unmergeAll([unmergeClaudeStyleHooks("PreToolUse"), unmergeClaudeStyleHooks("UserPromptSubmit")]),
    adapter: "passthrough", verifiedPayload: true,
    notes: "Same hooks.json shape and stdin payload fields as Claude Code (session_id, cwd, hook_event_name, tool_name, tool_input, tool_use_id). Also installs UserPromptSubmit for the same disabled-agent-at-prompt-time reason."
  },
  {
    id: "cursor", name: "Cursor",
    // ".cursor/hooks.json" is the file beam itself writes on install, so it can never be used to
    // detect a pre-existing Cursor install (circular). The bare ".cursor" directory is what
    // Cursor itself creates just from being used, so it's a real presence signal.
    configs: [".cursor"], artifacts: [".cursor/projects"],
    hookConfigPath: ".cursor/hooks.json", hookEventName: "preToolUse",
    mergeHookConfig: mergeAll([mergeCursorHooks("preToolUse"), mergeCursorHooks("beforeSubmitPrompt")]),
    unmergeHookConfig: unmergeAll([unmergeCursorHooks("preToolUse"), unmergeCursorHooks("beforeSubmitPrompt")]),
    adapter: "passthrough", verifiedPayload: true,
    notes: "Payload verified against cursor.com/docs/hooks; extra fields (model, conversation_id, ...) are ignored, not misread. Also installs beforeSubmitPrompt -- unlike preToolUse's permission field, that event's block contract is {continue: false, user_message} (see client.ts emitDeny)."
  },
  {
    id: "copilot-cli", name: "GitHub Copilot CLI",
    // Same circularity as Cursor above: ".copilot/hooks/beam.json" is our own output.
    // ".copilot/config.json" is what the real Copilot CLI writes on its own first run.
    configs: [".copilot/config.json"], artifacts: [".copilot/session-state"],
    hookConfigPath: ".copilot/hooks/beam.json", hookEventName: "preToolUse",
    mergeHookConfig: mergeAll([mergeCopilotHooks("preToolUse"), mergeCopilotHooks("userPromptSubmitted")]),
    unmergeHookConfig: unmergeAll([unmergeCopilotHooks("preToolUse"), unmergeCopilotHooks("userPromptSubmitted")]),
    adapter: "copilot-camel", verifiedPayload: true,
    notes: "Payload verified against docs.github.com Copilot hooks reference (camelCase: sessionId, cwd, toolName, toolArgs). userPromptSubmitted is also installed for observation/audit only -- GitHub's docs state its stdout is ignored (no blocking contract), so a disabled agent is only actually stopped at its first preToolUse call."
  },
  {
    id: "gemini", name: "Gemini CLI",
    // ".gemini/settings.json" is our own write target (circular, like Cursor/Copilot above); the
    // bare ".gemini" directory (created by any use of the Gemini CLI, e.g. mcp_config.json,
    // projects/) is the reliable presence signal instead.
    configs: [".gemini"], artifacts: [".gemini/tmp"],
    hookConfigPath: ".gemini/settings.json", hookEventName: "BeforeTool",
    // BeforeTool/BeforeAgent use the exact same {matcher, hooks: [{type, command}]} array shape
    // as Claude Code's PreToolUse/UserPromptSubmit (geminicli.com/docs/hooks/reference) --
    // beam previously targeted ".agents/hooks.json" with a "pre_tool_execution" event and a
    // "beam-security" wrapper, which is actually the unrelated Gemini API "Managed Agents"
    // sandbox hook contract (ai.google.dev/gemini-api/docs/agent-hooks), not Gemini CLI's own.
    mergeHookConfig: mergeAll([mergeClaudeStyleHooks("BeforeTool"), mergeClaudeStyleHooks("BeforeAgent")]),
    unmergeHookConfig: unmergeAll([unmergeClaudeStyleHooks("BeforeTool"), unmergeClaudeStyleHooks("BeforeAgent")]),
    adapter: "gemini", verifiedPayload: true,
    notes: "Payload verified against geminicli.com/docs/hooks/reference: stdin is flat (session_id, cwd, hook_event_name, tool_name, tool_input, prompt), not the nested tool_call shape the \"gemini\" adapter also tolerates as a defensive fallback. Also installs BeforeAgent so a disabled agent is stopped before the prompt reaches the model, not only at its first tool call; both events accept {decision: \"deny\", reason} and both also honor exit code 2 (see client.ts's EXIT_2_FAILS_CLOSED)."
  },
  {
    id: "opencode", name: "OpenCode",
    configs: [".config/opencode/opencode.json", ".config/opencode/opencode.jsonc"], artifacts: [".local/share/opencode"],
    hookConfigPath: null, pluginPath: ".opencode/plugins/beam.ts", hookEventName: "tool.execute.before",
    mergeHookConfig: null, unmergeHookConfig: null, adapter: "passthrough", verifiedPayload: true,
    notes: "Uses OpenCode's native tool.execute.before plugin hook."
  },
];

export function findAgent(id: string): AgentDefinition | undefined {
  return AGENTS.find(a => a.id === id);
}

export function hookConfigFullPath(agent: AgentDefinition, home: string): string {
  if (!agent.hookConfigPath) throw new Error(`${agent.name} has no supported hook config file yet.`);
  return join(home, agent.hookConfigPath);
}
