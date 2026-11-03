import { hookSpec, hookKind } from './hook-catalog.js';
import type { Obj } from './agents.js';
const obj = (v: unknown): Obj => v && typeof v === 'object' && !Array.isArray(v) ? v as Obj : {};
function parseArgs(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value); } catch { return value; }
}
function text(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(p => text(obj(p).text ?? obj(p).content) ?? '').filter(Boolean).join('\n');
  if (value && typeof value === 'object') return text(obj(value).content ?? obj(value).text);
}
export function adaptHookPayload(sourceAgent: string, raw: Obj, suppliedEvent?: string): Obj {
  let fields = raw;
  if (sourceAgent === 'windsurf') fields = Object.keys(obj(raw.tool_info)).length ? obj(raw.tool_info) : raw;
  if (sourceAgent === 'antigravity') fields = Object.keys(obj(raw.toolCall)).length ? obj(raw.toolCall) : raw;
  if (sourceAgent === 'cline') {
    for (const name of ['preToolUse','postToolUse','userPromptSubmit','taskStart','taskResume','taskCancel','taskComplete','taskError','sessionShutdown']) if (raw[name] && typeof raw[name] === 'object') { fields = obj(raw[name]); break; }
  }
  const kindName = suppliedEvent ?? raw.hook_event_name ?? raw.hookEventName ?? raw.hookName ?? raw.event;
  const event = String(kindName ?? (typeof raw.prompt === 'string' && !(raw.toolName ?? raw.tool_name) ? 'UserPromptSubmit' : hookSpec(sourceAgent)?.events.find(e => hookKind(e) === 'pre') ?? ''));
  const kind = hookKind(event);
  const nested = obj(raw.tool_call);
  let tool = fields.tool_name ?? fields.toolName ?? fields.tool ?? fields.name ?? nested.name;
  if (sourceAgent === 'windsurf' && !tool) tool = /read_code/.test(event) ? 'Read' : /write_code/.test(event) ? 'Edit' : /run_command/.test(event) ? 'Bash' : /mcp/.test(event) ? fields.mcp_tool_name : undefined;
  if (event === 'beforeReadFile') tool = tool ?? 'Read';
  const inputValue = fields.tool_input ?? fields.toolArgs ?? fields.toolInput ?? fields.tool_args ?? fields.mcp_tool_arguments ?? fields.parameters ?? fields.arguments ?? fields.input ?? fields.args ?? nested.args;
  const parsed = parseArgs(inputValue);
  const toolInput = parsed === undefined ? (['windsurf', 'antigravity', 'cline'].includes(sourceAgent) ? { ...fields } : {}) : parsed;
  const args = obj(toolInput);
  const workspaceRoots = raw.workspace_roots ?? raw.workspaceRoots ?? raw.workspacePaths;
  const roots = Array.isArray(workspaceRoots) ? workspaceRoots : [];
  const prompt = text(raw.prompt ?? raw.user_prompt ?? raw.userPrompt ?? obj(raw.extra).user_message ?? fields.prompt ?? fields.userMessage ?? fields.message ?? (kind === 'prompt' ? raw.message ?? raw.input : undefined));
  const isVSCode = ['copilot-cli','vscode'].includes(sourceAgent) && ((raw.hookEventName !== undefined && /^[A-Z]/.test(String(raw.hookEventName))) || (raw.tool_name !== undefined && raw.toolName === undefined && /^[A-Z]/.test(String(raw.hook_event_name ?? ''))));
  return {
    ...raw,
    source_agent: isVSCode ? 'vscode' : sourceAgent,
    session_id: (sourceAgent === "codex" ? raw.agent_id : undefined) ?? raw.session_id ?? raw.sessionId ?? raw.sessionID ?? raw.conversation_id ?? raw.conversationId ?? raw.trajectory_id ?? raw.taskId ?? raw.execution_id ?? raw.session ?? raw.environment_id,
    parent_session_id: raw.parent_session_id ?? raw.parentSessionId ?? (sourceAgent === "codex" && raw.agent_id ? raw.session_id : undefined),
    cwd: sourceAgent === 'junie' ? raw.project_path ?? raw.cwd : raw.cwd ?? raw.project_path ?? raw.workingDirectory ?? raw.working_directory ?? raw.working_dir ?? fields.cwd ?? roots[0],
    tool_name: tool,
    tool_input: toolInput,
    tool_use_id: fields.tool_use_id ?? fields.toolUseId ?? fields.tool_call_id ?? fields.toolCallId ?? fields.callID ?? raw.tool_use_id ?? raw.tool_call_id ?? raw.call_id,
    tool_response: raw.tool_response ?? raw.tool_result ?? raw.toolResult ?? raw.tool_output ?? raw.toolOutput ?? raw.result ?? raw.output ?? raw.metadata ?? fields.result ?? fields.output,
    hook_event_name: event,
    timestamp: typeof raw.timestamp === 'number' && Number.isFinite(raw.timestamp) ? new Date(raw.timestamp < 100000000000 ? raw.timestamp * 1000 : raw.timestamp).toISOString() : raw.timestamp,
    command: raw.command ?? fields.command ?? fields.commandLine ?? fields.command_line ?? args.command ?? args.command_line ?? args.cmd,
    file_path: raw.file_path ?? fields.file_path ?? fields.filePath ?? fields.path ?? args.file_path ?? args.filePath ?? args.path,
    ...(prompt !== undefined ? { prompt } : {}),
    ...(kind === 'prompt' ? { event_type: 'prompt.submit', tool_name: tool ?? event } : {}),
    ...(kind === 'permission' ? { event_type: /denied/i.test(event) ? 'permission.denied' : /result|response/i.test(event) ? 'permission.result' : 'permission.requested' } : {}),
    ...(kind === 'session' ? { event_type: /stop|end|finalize|shutdown|complete|cancel|error|deleted/i.test(event) ? 'session.end' : 'session.start' } : {}),
    ...(kind === 'assistant' ? { event_type: 'message.assistant', assistant_text: text(raw.assistant_text ?? raw.last_assistant_message ?? obj(raw.extra).assistant_message ?? raw.response ?? raw.text ?? raw.message) } : {}),
  };
}
