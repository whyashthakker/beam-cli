import type { HookTarget } from './agent-installers.js';
export const PLUGIN_MARKER = '// beam-managed: generated agent activity integration';

export function pluginSource(target: HookTarget): string {
  const id = target.agentId;
  const common = `${PLUGIN_MARKER}
import { spawn, spawnSync } from "node:child_process";
const NODE = ${JSON.stringify(target.nodePath)};
const CLI = ${JSON.stringify(target.cliPath)};
const AGENT = ${JSON.stringify(id)};
function payload(event: string, data: any) { return { ...data, hook_event_name: event, source_agent: AGENT, source_type: "hook" }; }
function forward(event: string, data: any) {
  try {
    const child = spawn(NODE, [CLI, "hook", AGENT, "--event", event], { stdio: ["pipe", "ignore", "ignore"], detached: true });
    child.on("error", () => {}); child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(payload(event, data))); child.unref();
  } catch {}
}
function gate(event: string, data: any): any {
  const result = spawnSync(NODE, [CLI, "hook", AGENT, "--event", event], { input: JSON.stringify(payload(event, data)), encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
  let response: any = {}; try { response = JSON.parse(result.stdout || "{}"); } catch {}
  if (result.error || result.status !== 0 || response.decision === "deny" || response.block === true || response.action === "reject-and-continue") return { reason: response.reason || response.message || response.blockReason || "Beam could not approve this tool call." };
}
`;
  if (id === 'opencode' || id === 'kilo') return common + `
const server = async ({ directory }: any) => ({
  "chat.message": async (input: any, output: any) => forward("chat.message", { session_id: input?.sessionID, cwd: directory, prompt: (output?.parts ?? []).filter((p: any) => p.type === "text").map((p: any) => p.text).join("\\n") }),
  "tool.execute.before": async (input: any, output: any) => {
    const deny = gate("tool.execute.before", { tool_name: input?.tool, tool_input: output?.args, tool_use_id: input?.callID, session_id: input?.sessionID, cwd: directory });
    if (deny) throw new Error(deny.reason);
  },
  "tool.execute.after": async (input: any, output: any) => forward("tool.execute.after", { tool_name: input?.tool, tool_input: input?.args, tool_response: output?.output, metadata: output?.metadata, tool_use_id: input?.callID, session_id: input?.sessionID, cwd: directory }),
  event: async ({ event }: any) => {
    const info = event?.properties?.info;
    if (event?.type === "session.created" || event?.type === "session.deleted") forward(event.type, { session_id: info?.id, cwd: info?.directory || directory });
    if (event?.type === "message.updated" && info?.role === "assistant" && info?.time?.completed) forward("message.updated", { session_id: info?.sessionID, cwd: directory, model: info?.modelID });
  },
});
${id === 'kilo' ? 'export default { id: "beam", server };' : 'export const BeamPlugin = server;'}
`;
  if (id === 'pi') return common + `
export default function(pi: any) {
  const body = (ctx: any, event: any) => ({ session_id: ctx?.sessionManager?.getSessionId?.(), cwd: ctx?.cwd, model: ctx?.model?.id, ...event });
  pi.on("session_start", async (e: any, ctx: any) => forward("session_start", body(ctx, { reason: e.reason })));
  pi.on("before_agent_start", async (e: any, ctx: any) => forward("before_agent_start", body(ctx, { prompt: e.prompt })));
  pi.on("tool_call", async (e: any, ctx: any) => { const deny = gate("tool_call", body(ctx, { tool_name: e.toolName, tool_input: e.input, tool_use_id: e.toolCallId })); if (deny) return { block: true, reason: deny.reason }; });
  pi.on("tool_result", async (e: any, ctx: any) => forward("tool_result", body(ctx, { tool_name: e.toolName, tool_input: e.input, tool_use_id: e.toolCallId, tool_response: { content: e.content, details: e.details }, is_error: e.isError })));
  pi.on("message_end", async (e: any, ctx: any) => { if (e.message?.role === "assistant") forward("message_end", body(ctx, { assistant_text: (e.message.content ?? []).filter((p: any) => p.type === "text").map((p: any) => p.text).join("\\n") })); });
  pi.on("session_shutdown", async (e: any, ctx: any) => forward("session_shutdown", body(ctx, { reason: e.reason })));
}
`;
  if (id === 'amp') return common + `
export default function(amp: any) {
  const cwd = amp.system.workspaceRoot ? amp.helpers.filePathFromURI(amp.system.workspaceRoot) : undefined;
  const body = (e: any) => ({ session_id: e.thread?.id, cwd });
  amp.on("session.start", async (e: any) => forward("session.start", body(e)));
  amp.on("agent.start", async (e: any) => forward("agent.start", { ...body(e), prompt: e.message }));
  amp.on("tool.call", async (e: any) => { const deny = gate("tool.call", { ...body(e), tool_name: e.tool, tool_input: e.input, tool_use_id: e.toolUseID }); return deny ? { action: "reject-and-continue", message: deny.reason } : { action: "allow" }; });
  amp.on("tool.result", async (e: any) => forward("tool.result", { ...body(e), tool_name: e.tool, tool_input: e.input, tool_use_id: e.toolUseID, tool_response: e.output, status: e.status, error: e.error }));
  amp.on("agent.end", async (e: any) => forward("agent.end", body(e)));
}
`;
  throw new Error(`No generated plugin for ${id}`);
}
