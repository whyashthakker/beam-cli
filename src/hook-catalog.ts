// Event names and host configuration shapes cross-checked against the local Numbat
// installers. See docs/agent-hooks.md for upstream references and coverage limits.
export type HookFormat = "claude" | "cursor" | "copilot" | "vscode" | "windsurf" | "toml" | "scripts" | "auggie" | "kiro" | "goose" | "project" | "flat" | "antigravity" | "top" | "yaml" | "plugin";
export interface HookSpec { id: string; name: string; path: string; format: HookFormat; detect: string; events: string[] }
export const HOOK_CATALOG: HookSpec[] = [
  {
    "id": "claude-code",
    "name": "Claude Code",
    "path": ".claude/settings.json",
    "format": "claude",
    "detect": ".claude",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "PostToolUseFailure",
      "PermissionRequest",
      "PermissionDenied",
      "Stop",
      "SessionEnd",
      "SubagentStart",
      "SubagentStop"
    ]
  },
  {
    "id": "codex",
    "name": "Codex",
    "path": ".codex/hooks.json",
    "format": "claude",
    "detect": ".codex",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "PermissionRequest",
      "SubagentStart",
      "SubagentStop",
      "Stop"
    ]
  },
  {
    "id": "cursor",
    "name": "Cursor",
    "path": ".cursor/hooks.json",
    "format": "cursor",
    "detect": ".cursor",
    "events": [
      "beforeSubmitPrompt",
      "preToolUse",
      "beforeReadFile",
      "postToolUse",
      "postToolUseFailure",
      "stop",
      "sessionStart",
      "sessionEnd",
      "subagentStart",
      "subagentStop"
    ]
  },
  {
    "id": "copilot-cli",
    "name": "GitHub Copilot CLI",
    "path": ".copilot/hooks/beam.json",
    "format": "copilot",
    "detect": ".copilot",
    "events": [
      "sessionStart",
      "userPromptSubmitted",
      "preToolUse",
      "postToolUse",
      "postToolUseFailure",
      "permissionRequest",
      "agentStop",
      "subagentStart",
      "subagentStop",
      "sessionEnd"
    ]
  },
  {
    "id": "gemini",
    "name": "Gemini CLI",
    "path": ".gemini/settings.json",
    "format": "claude",
    "detect": ".gemini",
    "events": [
      "SessionStart",
      "BeforeAgent",
      "BeforeTool",
      "AfterTool",
      "AfterAgent",
      "SessionEnd"
    ]
  },
  {
    "id": "windsurf",
    "name": "Windsurf / Devin Desktop",
    "path": ".codeium/windsurf/hooks.json",
    "format": "windsurf",
    "detect": ".windsurf",
    "events": [
      "pre_user_prompt",
      "pre_read_code",
      "post_read_code",
      "pre_write_code",
      "post_write_code",
      "pre_run_command",
      "post_run_command",
      "pre_mcp_tool_use",
      "post_mcp_tool_use",
      "post_cascade_response"
    ]
  },
  {
    "id": "vscode",
    "name": "VS Code Copilot Chat",
    "path": ".copilot/hooks/beam.json",
    "format": "vscode",
    "detect": ".vscode",
    "events": [
      "sessionStart",
      "userPromptSubmitted",
      "preToolUse",
      "postToolUse",
      "postToolUseFailure",
      "permissionRequest",
      "agentStop",
      "subagentStart",
      "subagentStop",
      "sessionEnd"
    ]
  },
  {
    "id": "kimi",
    "name": "Kimi Code",
    "path": ".kimi-code/config.toml",
    "format": "toml",
    "detect": ".kimi-code",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "PostToolUseFailure",
      "PermissionRequest",
      "PermissionResult",
      "Stop",
      "SessionEnd",
      "SubagentStart",
      "SubagentStop"
    ]
  },
  {
    "id": "qwen",
    "name": "Qwen Code",
    "path": ".qwen/settings.json",
    "format": "claude",
    "detect": ".qwen",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "PostToolUseFailure",
      "PermissionRequest",
      "PermissionDenied",
      "Stop",
      "SessionEnd",
      "SubagentStart",
      "SubagentStop"
    ]
  },
  {
    "id": "cline",
    "name": "Cline CLI",
    "path": ".cline/hooks",
    "format": "scripts",
    "detect": ".cline",
    "events": [
      "TaskStart",
      "TaskResume",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "TaskComplete",
      "TaskCancel",
      "TaskError",
      "SessionShutdown"
    ]
  },
  {
    "id": "auggie",
    "name": "Auggie",
    "path": ".augment/settings.json",
    "format": "auggie",
    "detect": ".augment",
    "events": [
      "SessionStart",
      "PreToolUse",
      "PostToolUse",
      "Stop",
      "SessionEnd"
    ]
  },
  {
    "id": "kiro",
    "name": "Kiro",
    "path": ".kiro/hooks/beam.json",
    "format": "kiro",
    "detect": ".kiro",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "Stop",
      "SessionEnd"
    ]
  },
  {
    "id": "goose",
    "name": "Goose",
    "path": ".agents/plugins/beam/hooks/hooks.json",
    "format": "goose",
    "detect": ".config/goose",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "PostToolUseFailure",
      "Stop",
      "SessionEnd"
    ]
  },
  {
    "id": "openhands",
    "name": "OpenHands",
    "path": ".openhands/hooks.json",
    "format": "project",
    "detect": ".openhands",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "Stop",
      "SessionEnd"
    ]
  },
  {
    "id": "crush",
    "name": "Crush",
    "path": ".config/crush/crush.json",
    "format": "flat",
    "detect": ".config/crush",
    "events": [
      "PreToolUse"
    ]
  },
  {
    "id": "junie",
    "name": "Junie CLI",
    "path": ".junie/config.json",
    "format": "claude",
    "detect": ".junie",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "Stop",
      "SessionEnd"
    ]
  },
  {
    "id": "antigravity",
    "name": "Antigravity",
    "path": ".gemini/config/hooks.json",
    "format": "antigravity",
    "detect": ".gemini/antigravity",
    "events": [
      "PreToolUse",
      "PostToolUse",
      "Stop"
    ]
  },
  {
    "id": "factory",
    "name": "Factory Droid",
    "path": ".factory/hooks.json",
    "format": "top",
    "detect": ".factory",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "Stop",
      "SubagentStop",
      "SessionEnd"
    ]
  },
  {
    "id": "grok",
    "name": "Grok Build",
    "path": ".grok/hooks/beam.json",
    "format": "top",
    "detect": ".grok",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "PostToolUseFailure",
      "PermissionDenied",
      "SubagentStart",
      "SubagentStop",
      "Stop",
      "SessionEnd"
    ]
  },
  {
    "id": "devin",
    "name": "Devin CLI",
    "path": ".config/devin/config.json",
    "format": "claude",
    "detect": ".config/devin",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PermissionRequest",
      "PostToolUse",
      "Stop",
      "SessionEnd"
    ]
  },
  {
    "id": "hermes",
    "name": "Hermes Agent",
    "path": ".hermes/config.yaml",
    "format": "yaml",
    "detect": ".hermes",
    "events": [
      "on_session_start",
      "pre_llm_call",
      "post_llm_call",
      "pre_tool_call",
      "post_tool_call",
      "pre_approval_request",
      "post_approval_response",
      "subagent_start",
      "subagent_stop",
      "on_session_finalize"
    ]
  },
  {
    "id": "muse",
    "name": "Muse Code",
    "path": ".config/muse/settings.json",
    "format": "claude",
    "detect": ".config/muse",
    "events": [
      "SessionStart",
      "UserPromptSubmit",
      "PreToolUse",
      "PostToolUse",
      "PostToolUseFailure",
      "SubagentStart",
      "SubagentStop",
      "Stop",
      "SessionEnd"
    ]
  },
  {
    "id": "opencode",
    "name": "OpenCode",
    "path": ".config/opencode/plugins/beam.ts",
    "format": "plugin",
    "detect": ".config/opencode",
    "events": [
      "chat.message",
      "tool.execute.before",
      "tool.execute.after",
      "session.created",
      "session.deleted",
      "message.updated"
    ]
  },
  {
    "id": "kilo",
    "name": "Kilo Code",
    "path": ".config/kilo/plugin/beam.ts",
    "format": "plugin",
    "detect": ".config/kilo",
    "events": [
      "chat.message",
      "tool.execute.before",
      "tool.execute.after",
      "session.created",
      "session.deleted",
      "message.updated"
    ]
  },
  {
    "id": "pi",
    "name": "Pi",
    "path": ".pi/agent/extensions/beam.ts",
    "format": "plugin",
    "detect": ".pi/agent",
    "events": [
      "session_start",
      "before_agent_start",
      "tool_call",
      "tool_result",
      "message_end",
      "session_shutdown"
    ]
  },
  {
    "id": "amp",
    "name": "Amp",
    "path": ".config/amp/plugins/beam.ts",
    "format": "plugin",
    "detect": ".config/amp",
    "events": [
      "session.start",
      "agent.start",
      "tool.call",
      "tool.result",
      "agent.end"
    ]
  },
  {
    "id": "openclaw",
    "name": "OpenClaw",
    "path": "",
    "format": "plugin",
    "detect": ".openclaw",
    "events": [
      "before_tool_call",
      "after_tool_call",
      "session_start",
      "session_end",
      "message_received",
      "message_sent",
      "subagent_spawned",
      "subagent_ended"
    ]
  }
];

export function hookSpec(id: string): HookSpec | undefined { return HOOK_CATALOG.find(s => s.id === id); }
const key = (event: string) => event.toLowerCase().replace(/[._-]/g, "");
export function hookKind(event: string): "pre" | "post" | "failure" | "prompt" | "permission" | "session" | "assistant" | "other" {
  const name = key(event);
  if (["pretooluse", "beforetool", "pretoolcall", "beforetoolcall", "toolcall", "toolexecutebefore", "prereadcode", "prewritecode", "preruncommand", "premcptooluse", "beforereadfile"].includes(name)) return "pre";
  if (name.includes("failure") || name === "toolerror") return "failure";
  if (["posttooluse", "aftertool", "posttoolcall", "aftertoolcall", "toolresult", "toolexecuteafter", "postreadcode", "postwritecode", "postruncommand", "postmcptooluse"].includes(name)) return "post";
  if (["userpromptsubmit", "userpromptsubmitted", "beforesubmitprompt", "beforeagent", "beforeagentstart", "preuserprompt", "chatmessage", "agentstart", "prellmcall", "messagereceived"].includes(name)) return "prompt";
  if (/permission|approval/.test(name)) return "permission";
  if (/session|subagent|task/.test(name)) return "session";
  if (["stop", "agentstop", "agentend", "afteragent", "postllmcall", "postcascaderesponse", "messageend", "messageupdated", "messagesent"].includes(name)) return "assistant";
  return "other";
}
