import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";

export type Obj = Record<string, unknown>;

// Forensic extraction reads an agent's own existing session/transcript files -- no hook
// required, and it can see activity from before beam was ever installed. Bounded generously so
// a huge or pathological transcript directory can't exhaust memory or flood the collector.
const MAX_FILE_SIZE = 50_000_000; // 50 MB per transcript file
const MAX_RECORDS_PER_FILE = 20_000; // parsed JSONL lines kept per file
const MAX_FILES = 2000; // transcript files walked per extraction run

function obj(v: unknown): Obj { return v && typeof v === "object" && !Array.isArray(v) ? v as Obj : {}; }
function str(v: unknown): string { return typeof v === "string" ? v : ""; }
function arr(v: unknown): unknown[] { return Array.isArray(v) ? v : []; }
function isFinitePastTimestamp(v: string): boolean { return v.length > 0 && Number.isFinite(Date.parse(v)); }

async function walk(dir: string, out: string[] = []): Promise<string[]> {
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    if (out.length >= MAX_FILES) break;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await walk(full, out);
    else if (entry.isFile() && entry.name.endsWith(".jsonl")) out.push(full);
  }
  return out;
}

async function readJsonlRows(path: string): Promise<Obj[]> {
  try { if ((await stat(path)).size > MAX_FILE_SIZE) return []; } catch { return []; }
  let content: string;
  try { content = await readFile(path, "utf8"); } catch { return []; }
  const rows: Obj[] = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try { rows.push(JSON.parse(trimmed) as Obj); } catch { /* skip a malformed line, not the whole file */ }
    if (rows.length >= MAX_RECORDS_PER_FILE) break;
  }
  return rows;
}

// ~/.claude/projects/<encoded-project-path>/<session-uuid>.jsonl -- an "assistant" line's
// message.content array carries tool_use blocks alongside prose/thinking blocks.
export async function extractClaudeCode(home: string): Promise<Obj[]> {
  const files = await walk(join(home, ".claude", "projects"));
  const records: Obj[] = [];
  for (const file of files) {
    for (const row of await readJsonlRows(file)) {
      if (row.type !== "assistant") continue;
      const message = obj(row.message);
      const timestamp = str(row.timestamp);
      if (!isFinitePastTimestamp(timestamp)) continue;
      for (const item of arr(message.content)) {
        const block = obj(item);
        if (block.type !== "tool_use") continue;
        const eventId = str(block.id);
        records.push({
          ...(eventId ? { event_id: eventId } : {}),
          tool_name: block.name,
          tool_input: block.input,
          session_id: str(row.session_id) || str(row.sessionId),
          project_path: str(row.cwd),
          timestamp,
          model: str(message.model),
          source_agent: "claude-code",
          source_type: "extract",
        });
      }
    }
  }
  return records;
}

// ~/.codex/{sessions,archived_sessions}/rollout-*.jsonl -- a leading "session_meta" record
// carries session_id/cwd; "response_item" records of payload.type "function_call" (shell/exec
// tools; arguments is a JSON *string*) or "custom_tool_call" (e.g. apply_patch; input is raw
// text, not JSON) are the actions. Everything else (message/reasoning/output records) is
// conversation, not an action -- skipped, matching what a live PreToolUse hook would ever see.
export async function extractCodex(home: string): Promise<Obj[]> {
  const roots = [join(home, ".codex", "sessions"), join(home, ".codex", "archived_sessions")];
  const records: Obj[] = [];
  for (const root of roots) {
    for (const file of await walk(root)) {
      let sessionId = ""; let cwd = "";
      for (const row of await readJsonlRows(file)) {
        if (row.type === "session_meta") {
          const payload = obj(row.payload);
          sessionId = str(payload.session_id) || str(payload.id);
          cwd = str(payload.cwd);
          continue;
        }
        if (row.type !== "response_item") continue;
        const timestamp = str(row.timestamp);
        if (!isFinitePastTimestamp(timestamp)) continue;
        const payload = obj(row.payload);
        const callId = str(payload.call_id);
        const base = { ...(callId ? { event_id: callId } : {}), session_id: sessionId, project_path: cwd, timestamp, source_agent: "codex", source_type: "extract" };
        if (payload.type === "function_call") {
          let args: Obj = {};
          try { args = JSON.parse(str(payload.arguments)) as Obj; } catch { /* arguments wasn't JSON */ }
          records.push({ ...base, tool_name: payload.name, command: args.cmd ?? args.command, tool_input: args });
        } else if (payload.type === "custom_tool_call") {
          const input = payload.input;
          records.push({ ...base, tool_name: payload.name, content_preview: typeof input === "string" ? input : JSON.stringify(input ?? {}) });
        }
      }
    }
  }
  return records;
}

export type ExtractorId = "claude-code" | "codex";
const extractors: Record<ExtractorId, (home: string) => Promise<Obj[]>> = { "claude-code": extractClaudeCode, codex: extractCodex };

export function supportsExtraction(agentId: string): agentId is ExtractorId {
  return Object.prototype.hasOwnProperty.call(extractors, agentId);
}

export async function extractAgent(agentId: string, home: string): Promise<Obj[]> {
  if (!supportsExtraction(agentId)) throw new Error(`Forensic extraction isn't built for '${agentId}' yet. Supported: ${Object.keys(extractors).join(", ")}.`);
  return extractors[agentId](home);
}
