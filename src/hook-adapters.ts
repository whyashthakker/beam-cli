import { findAgent, type Obj } from "./agents.js";

// Claude Code, Codex, and Cursor all send tool_name/tool_input/session_id/cwd/hook_event_name
// (core.normalize already reads exactly these fields, case-insensitively for hook_event_name).
function passthrough(raw: Obj): Obj {
  return raw;
}

// GitHub Copilot CLI's preToolUse payload is camelCase and has no hook_event_name field —
// it's implied by which hooks.json array the handler is registered under.
function copilotCamel(raw: Obj): Obj {
  return {
    ...raw,
    session_id: raw.sessionId ?? raw.session_id,
    cwd: raw.cwd,
    tool_name: raw.toolName ?? raw.tool_name,
    tool_input: raw.toolArgs ?? raw.tool_input,
    hook_event_name: raw.hook_event_name ?? "PreToolUse",
  };
}

// Best-effort fallback for agents whose stdin schema is not (yet) verified against vendor docs.
function generic(raw: Obj): Obj {
  return {
    ...raw,
    session_id: raw.session_id ?? raw.sessionId ?? raw.session,
    cwd: raw.cwd ?? raw.project_path ?? raw.workingDirectory ?? raw.working_directory,
    tool_name: raw.tool_name ?? raw.toolName ?? raw.tool,
    tool_input: raw.tool_input ?? raw.toolArgs ?? raw.toolInput ?? raw.input,
    hook_event_name: raw.hook_event_name ?? raw.hookEventName ?? raw.event,
  };
}

const adapters = { passthrough, "copilot-camel": copilotCamel, generic };

export function adaptHookPayload(sourceAgent: string, raw: Obj): Obj {
  const agent = findAgent(sourceAgent);
  const adapter = adapters[agent?.adapter ?? "generic"];
  return adapter(raw);
}
