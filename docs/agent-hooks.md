# Agent hook coverage

Beam has 27 native hook/plugin integrations (19 added to the original eight). Jev remains discovery-only. `beam agent list --events` prints each integration's installed event set. The event catalog is the source of truth: `src/hook-catalog.ts`.

Install or upgrade detected agents with `beam agent install-all`, or use `beam agent install <id>` for one agent. Restart the affected agents and approve the changed hooks where the host requires trust. VS Code and Copilot share one hook file, so installing either updates both. OpenClaw requires its plugin registration and a Gateway restart. These commands configure agent installations; the local Beam collector must be running to display live activity.

OpenHands is repository-scoped and excluded from automatic installation:

```sh
beam agent install openhands --settings /repo/.openhands/hooks.json
beam agent uninstall openhands --settings /repo/.openhands/hooks.json
```

## Events by agent

The table lists events Beam registers, including prompts, tools, results, failures, permissions and lifecycle boundaries where supported. Plugin events are forwarded by generated TypeScript integrations.

| Agent / CLI ID | Events | Default configuration |
|---|---|---|
| Claude Code (`claude-code`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PermissionRequest`, `PermissionDenied`, `Stop`, `SessionEnd`, `SubagentStart`, `SubagentStop` | `.claude/settings.json` |
| Codex (`codex`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PermissionRequest`, `SubagentStart`, `SubagentStop`, `Stop` | `.codex/hooks.json` |
| Cursor (`cursor`) | `beforeSubmitPrompt`, `preToolUse`, `beforeReadFile`, `postToolUse`, `postToolUseFailure`, `stop`, `sessionStart`, `sessionEnd`, `subagentStart`, `subagentStop` | `.cursor/hooks.json` |
| GitHub Copilot CLI (`copilot-cli`) | `sessionStart`, `userPromptSubmitted`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `permissionRequest`, `agentStop`, `subagentStart`, `subagentStop`, `sessionEnd` | `.copilot/hooks/beam.json` |
| Gemini CLI (`gemini`) | `SessionStart`, `BeforeAgent`, `BeforeTool`, `AfterTool`, `AfterAgent`, `SessionEnd` | `.gemini/settings.json` |
| Windsurf / Devin Desktop (`windsurf`) | `pre_user_prompt`, `pre_read_code`, `post_read_code`, `pre_write_code`, `post_write_code`, `pre_run_command`, `post_run_command`, `pre_mcp_tool_use`, `post_mcp_tool_use`, `post_cascade_response` | `.codeium/windsurf/hooks.json` |
| VS Code Copilot Chat (`vscode`) | `sessionStart`, `userPromptSubmitted`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `permissionRequest`, `agentStop`, `subagentStart`, `subagentStop`, `sessionEnd` | `.copilot/hooks/beam.json` |
| Kimi Code (`kimi`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PermissionRequest`, `PermissionResult`, `Stop`, `SessionEnd`, `SubagentStart`, `SubagentStop` | `.kimi-code/config.toml` |
| Qwen Code (`qwen`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PermissionRequest`, `PermissionDenied`, `Stop`, `SessionEnd`, `SubagentStart`, `SubagentStop` | `.qwen/settings.json` |
| Cline CLI (`cline`) | `TaskStart`, `TaskResume`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `TaskComplete`, `TaskCancel`, `TaskError`, `SessionShutdown` | `.cline/hooks` |
| Auggie (`auggie`) | `SessionStart`, `PreToolUse`, `PostToolUse`, `Stop`, `SessionEnd` | `.augment/settings.json` |
| Kiro (`kiro`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `SessionEnd` | `.kiro/hooks/beam.json` |
| Goose (`goose`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `Stop`, `SessionEnd` | `.agents/plugins/beam/hooks/hooks.json` |
| OpenHands (`openhands`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `SessionEnd` | `<repository>/.openhands/hooks.json (explicit --settings required)` |
| Crush (`crush`) | `PreToolUse` | `.config/crush/crush.json` |
| Junie CLI (`junie`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `Stop`, `SessionEnd` | `.junie/config.json` |
| Antigravity (`antigravity`) | `PreToolUse`, `PostToolUse`, `Stop` | `.gemini/config/hooks.json` |
| Factory Droid (`factory`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `SubagentStop`, `SessionEnd` | `.factory/hooks.json` |
| Grok Build (`grok`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PermissionDenied`, `SubagentStart`, `SubagentStop`, `Stop`, `SessionEnd` | `.grok/hooks/beam.json` |
| Devin CLI (`devin`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `Stop`, `SessionEnd` | `.config/devin/config.json` |
| Hermes Agent (`hermes`) | `on_session_start`, `pre_llm_call`, `post_llm_call`, `pre_tool_call`, `post_tool_call`, `pre_approval_request`, `post_approval_response`, `subagent_start`, `subagent_stop`, `on_session_finalize` | `.hermes/config.yaml` |
| Muse Code (`muse`) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `SubagentStart`, `SubagentStop`, `Stop`, `SessionEnd` | `.config/muse/settings.json` |
| OpenCode (`opencode`) | `chat.message`, `tool.execute.before`, `tool.execute.after`, `session.created`, `session.deleted`, `message.updated` | `.config/opencode/plugins/beam.ts` |
| Kilo Code (`kilo`) | `chat.message`, `tool.execute.before`, `tool.execute.after`, `session.created`, `session.deleted`, `message.updated` | `.config/kilo/plugin/beam.ts` |
| Pi (`pi`) | `session_start`, `before_agent_start`, `tool_call`, `tool_result`, `message_end`, `session_shutdown` | `.pi/agent/extensions/beam.ts` |
| Amp (`amp`) | `session.start`, `agent.start`, `tool.call`, `tool.result`, `agent.end` | `.config/amp/plugins/beam.ts` |
| OpenClaw (`openclaw`) | `before_tool_call`, `after_tool_call`, `session_start`, `session_end`, `message_received`, `message_sent`, `subagent_spawned`, `subagent_ended` | `Beam-managed OpenClaw plugin registered through its CLI` |

## Captured activity

Normalized events include an `activity` object. Studio's action drawer displays it, and workspace forwarding includes it alongside existing event fields.

- `hookEvent`, `toolCallId`, and parent/session identity preserve the originating callback and correlate tool requests with results.
- `prompt` stores the redacted user text supplied by a prompt hook. Allowed prompts are captured as well as denied prompts. This changes Beam's previous behavior, which omitted prompt text and skipped allowed prompt events.
- `input` and `output` retain bounded, redacted tool arguments and results. Unknown/MCP tools retain generic arguments instead of disappearing.
- `paths` identifies supplied file and directory targets, including multi-file arguments and patch targets.
- `searchTerms` retains supplied search terms and patterns; `urls` retains explicitly supplied HTTP(S) destinations. URL query parameters remain redacted by Beam's standard redactor.
- `edits` retains supplied old/new text, edit lists, or patches. Existing added/removed line counts remain available.
- `details`, `status`, and `error` retain selected lifecycle/permission fields and reported failures.
- `truncated` marks size/depth limits. The projection has a shared 48,000-character content budget, up to 12,000 characters per string, depth eight, and at most 100 entries per object/array. Target lists are limited to 25 entries each. Hook stdin is limited to 2 MB.

Credential patterns, sensitive structured field names, session entities and configured custom detectors are redacted before transport or offline queuing. Redaction cannot recognize every secret or private source fragment. The stored content is the supplied payload, not an independent audit of the filesystem or browser.

A proposed tool call has phase `proposed`; a successful callback has `completed hook`; a failure callback or explicit tool error has `failed hook`. Completion means the host reported a tool result, not proof that every requested side effect succeeded. Native IDs are scoped to the agent/session so concurrent agents do not erase one another's actions.

## Policy and delivery

Policy, skill approvals and optional action judges run at pre-action gates. Post-tool, failure, permission and lifecycle notifications are captured without running those gates. Observing a permission callback does not approve it; Junie's `PermissionRequest` is deliberately omitted because a successful monitor callback can auto-approve the host's permission request. Muse's permission callback is also omitted, following the reference integration. Cline receives its native `cancel` response, and Antigravity retains its `ask` permission behavior.

If the collector is unreachable, redacted projected events are written atomically as mode-0600 files in `<Beam data directory>/hook-spool`. The collector replays them at startup and every five seconds, deleting each file only after successful local storage. Collector event IDs make retries idempotent. Workspace upload still follows the existing forwarding behavior; the hook queue is for local collector outages.

Installers preserve foreign hook entries and settings, back up the original file once as `.beam-backup`, and use atomic replacement. JSONC input is parsed but rewritten as formatted JSON; the pristine backup retains comments. YAML comments are preserved by the YAML document editor. Kimi TOML is extended through a marked block. Existing unowned Cline scripts/plugins cause an explicit error rather than being overwritten. Host trust, active profiles and custom config roots still determine whether an agent executes installed callbacks.

## Limits and validation

Hooks cover actions the host actually emits. Hosted tools, some IDE/cloud modes, external child processes, browser actions inside scripts and shell side effects may bypass semantic hooks. Search terms or destinations hidden inside code remain generic tool input. Shell edits cannot provide exact file diffs unless the host supplies them. This does not capture hidden reasoning, read arbitrary referenced files, or prove which pages a user viewed. Antigravity and Crush expose fewer events than other agents, so their missing prompt/post-tool coverage is not fabricated.

The new integrations are checked through temporary-home installer tests, native payload fixtures and execution of generated plugin callbacks against simulated host APIs. They have not all been exercised in installed vendor runtimes. Validate the required host/version with a real session before treating its coverage as established. New agents remain marked as best-effort payload mappings in `beam agent list`.

The implementation references the local [Numbat source](https://github.com/perplexityai/numbat) at revision `ebb511ff5b4d9ed4b1c732460e128a8601091fed` (Apache-2.0) for event names, payload fields and configuration shapes. Beam uses its own TypeScript capture and policy pipeline. Agent configuration contracts can change between host releases.
