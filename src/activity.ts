import { hookKind } from './hook-catalog.js';
import type { Obj } from './agents.js';
export interface Activity {
  hookEvent: string; toolCallId?: string; parentSession?: string;
  input?: unknown; output?: unknown; prompt?: string; assistant?: string;
  paths?: string[]; urls?: string[]; searchTerms?: string[]; edits?: unknown;
  status?: string; error?: string; details?: unknown; truncated: boolean;
}
const object = (v: unknown): Obj => v && typeof v === 'object' && !Array.isArray(v) ? v as Obj : {};
export function activityType(raw: Obj, fallback: string): string {
  const tool = String(raw.tool_name ?? raw.tool ?? '').toLowerCase();
  const input = object(raw.tool_input ?? raw.input);
  if (/^(bash|shell|exec_command|shell_command|exec|terminal|run_shell_command|execute_command|run_command|run_terminal_cmd|runterminalcommand|runinterminal|powershell)$/.test(tool)) return 'command.exec';
  if (/^(read|readfile|read_file|read_text_file|view|view_file)$/.test(tool)) return 'file.read';
  if (/^(write|edit|write_file|edit_file|str_replace_editor|str_replace|apply_patch|replace|replace_in_file|multiedit|write_to_file|editfile|editfiles|createfile|create_file|create|writefile|replace_string_in_file|insert_edit_into_file|multi_replace_string_in_file)$/.test(tool)) return 'file.write';
  if (/^(ls|list_dir|list_directory|list_files|readdir|directory_tree|listdirectory|listdir)$/.test(tool)) return 'directory.read';
  if (/^(glob|grep|search_files|file_search|find_files|rg)$/.test(tool)) return 'file.search';
  if (/web.?search|search.?web/.test(tool) || input.search_query !== undefined) return 'web.search';
  if (/web.?fetch|fetch_url|fetch.?web|browse|navigate|open_url/.test(tool) || input.open !== undefined) return 'browser.navigate';
  return fallback;
}
// A bounded, field-aware projection prevents arbitrary envelopes, histories and credentials
// from entering activity telemetry. No referenced files or browser pages are read here.
export function activityFor(raw: Obj, redact: (text: string) => string): Activity | undefined {
  if (!raw.hook_event_name && raw.source_type !== 'hook') return undefined;
  let budget = 48000, truncated = raw.capture_truncated === true;
  function clean(value: unknown, depth = 0, key = ''): unknown {
    if (/password|secret|authorization|cookie|credential|api[_-]?key|access[_-]?token|refresh[_-]?token/i.test(key)) return '[REDACTED]';
    if (budget <= 0 || depth > 8) { truncated = true; return '[TRUNCATED]'; }
    if (typeof value === 'string') { const redacted = redact(value); const limit = Math.min(12000, budget); const out = redacted.slice(0, limit); budget -= out.length; if (out.length < redacted.length) truncated = true; return out; }
    if (Array.isArray(value)) { if (value.length > 100) truncated = true; return value.slice(0,100).map(v => clean(v, depth + 1)); }
    if (value && typeof value === 'object') { const entries = Object.entries(value); if (entries.length > 100) truncated = true; return Object.fromEntries(entries.slice(0,100).map(([k,v]) => [k, clean(v, depth + 1, k)])); }
    return value;
  }
  const input = raw.tool_input ?? raw.input;
  const paths = new Set<string>(), urls = new Set<string>(), searchTerms = new Set<string>();
  function targets(value: unknown, depth = 0) {
    if (depth > 6 || !value || typeof value !== 'object') return;
    for (const [key, v] of Object.entries(value).slice(0,100)) {
      if (typeof v === 'string') {
        if (/^(?:path|file_path|filePath|directory|directory_path|dir|target_file|filename|file|workdir)$/.test(key)) paths.add(redact(v).slice(0,2000));
        if (/^(?:url|uri|ref_id|website|endpoint)$/.test(key) && /^https?:\/\//i.test(v)) urls.add(redact(v).slice(0,2000));
        if (/^(?:q|query|search_term|search_query|searchQuery|pattern)$/.test(key)) searchTerms.add(redact(v).slice(0,2000));
        if (/^(?:patch|patchText|patch_text|diff|command)$/.test(key) && /^\*\*\* (?:Update|Add|Delete) File:/m.test(v)) for (const match of v.matchAll(/^\*\*\* (?:Update|Add|Delete) File:\s*(.+)$/gm)) paths.add(redact(match[1]).slice(0,2000));
      } else {
        if (Array.isArray(v) && /^(files|paths|directories)$/.test(key)) for (const p of v.slice(0,100)) if (typeof p === 'string') paths.add(redact(p).slice(0,2000));
        targets(v, depth + 1);
      }
    }
  }
  if (typeof input === 'string') for (const match of input.matchAll(/^\*\*\* (?:Update|Add|Delete) File:\s*(.+)$/gm)) paths.add(redact(match[1]).slice(0,2000));
  targets(input); targets({ file_path: raw.file_path, url: raw.url });
  const args = object(input);
  const before = args.old_string ?? args.old_str ?? args.oldString ?? args.oldText ?? args.old_text;
  const after = args.new_string ?? args.new_str ?? args.newString ?? args.newText ?? args.new_text;
  const patch = args.patch ?? args.patchText ?? args.patch_text ?? args.diff;
  const hookEvent = String(raw.hook_event_name ?? '');
  const kind = hookKind(hookEvent);
  const a: Activity = {
    hookEvent: String(clean(hookEvent)),
    ...(raw.tool_use_id ? { toolCallId: String(clean(raw.tool_use_id)) } : {}),
    ...(raw.parent_session_id ? { parentSession: String(clean(raw.parent_session_id)) } : {}),
    ...(kind === 'prompt' && typeof raw.prompt === 'string' ? { prompt: String(clean(raw.prompt)) } : {}),
    ...(raw.assistant_text ? { assistant: String(clean(raw.assistant_text)) } : {}),
    ...(input !== undefined ? { input: clean(input) } : {}),
    ...(raw.tool_response !== undefined ? { output: clean(raw.tool_response) } : {}),
    ...(paths.size ? { paths: [...paths].slice(0,25) } : {}),
    ...(urls.size ? { urls: [...urls].slice(0,25) } : {}),
    ...(searchTerms.size ? { searchTerms: [...searchTerms].slice(0,25) } : {}),
    ...(typeof input === 'string' && /^(?:\*\*\* Begin Patch|diff --git|--- )/m.test(input) ? { edits: clean({ patch: input }) } : {}),
    ...((args.edits ?? raw.edits ?? patch ?? before ?? after) !== undefined ? { edits: clean(args.edits ?? raw.edits ?? { old: before, new: after, patch }) } : {}),
    ...(raw.status ? { status: String(clean(raw.status)) } : kind === 'failure' || raw.is_error ? { status: 'failed' } : {}),
    ...(raw.error ? { error: String(clean(raw.error)) } : {}),
    details: clean(Object.fromEntries(['reason','decision','permission_decision','permissionDecision','approval','approved','agent_id','agent_type','subagent_id','child_session_id','exit_code','exitCode','duration_ms'].filter(k => raw[k] !== undefined).map(k => [k, raw[k]]))),
    truncated: false,
  };
  a.truncated = truncated || paths.size > 25 || urls.size > 25 || searchTerms.size > 25; return a;
}
