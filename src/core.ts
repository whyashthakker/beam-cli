import { createHash, randomUUID } from "node:crypto";
import { changedLines, type LineChanges } from "./edit-stats.js";
import { builtinRules, type Rule, type Severity } from "./rule-catalog.js";
export { builtinRulesById, type Rule, type RuleCategory, type Severity } from "./rule-catalog.js";

export type Finding = { id: string; title: string; severity: Severity; explanation: string; evidence: string; line?: number };
export type Event = {
  id: string; timestamp: string; receivedAt: string; agent: string; session: string; lines?: LineChanges; sessionTitle?: string; sessionTitleSource?: "prompt" | "agent"; turn?: { n: number; topic: string; shift: boolean };
  type: string; tool: string; summary: string; project: string; source: string;
  endpoint: string; model: string; phase: string; findings: Finding[];
  mcp?: { server: string; tool?: string; resource?: string; requestType?: "tool" | "resource" | "prompt" | "unknown" };
  provenance?: { recordId: string; schemaVersion: string; citedEventIds: string[]; tags: string[]; evidence: string };
  inputTokens?: number; outputTokens?: number; costUsd?: number;
};
export type Scan = { id: string; name: string; kind: "skill" | "mcp"; timestamp: string; hash: string; findings: Finding[]; lines: number };
export const severityRank: Record<Severity, number> = { critical: 3, high: 2, medium: 1, info: 0 };
export function risk(findings: Finding[]): Severity {
  return findings.reduce<Severity>((s, f) => severityRank[f.severity] > severityRank[s] ? f.severity : s, "info");
}
export function redact(text: string): string {
  return text
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, "[REDACTED PRIVATE KEY]")
    .replace(/\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,}|beam_app_[\w-]{20,})\b/g, "[REDACTED TOKEN]")
    .replace(/(bearer\s+)[A-Za-z0-9._~+\/-]{8,}/gi, "$1[REDACTED]")
    .replace(/((?:[\w-]*(?:api[_-]?key|token|secret|password|authorization)[\w-]*)["']?\s*[:=]\s*)["']?[^\s,"';&}\]]+/gi, "$1[REDACTED]")
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(/(https?:\/\/[^\s?#"']+)\?[^\s"']*/gi, "$1?[REDACTED QUERY]");
}

// Loaded from disk at startup (see custom-rules.ts); empty until loadCustomRules() runs.
let customRules: Rule[] = [];
export function setCustomRules(rules: Rule[]): void { customRules = rules; }
function activeRules(): Rule[] { return [...builtinRules, ...customRules]; }

export function ruleCatalog(): Omit<Rule, "match">[] {
  return activeRules().map(({ match: _, ...rule }) => rule);
}
export function detect(text: string): Finding[] {
  return activeRules().filter(r => r.match(text)).map(r => ({ id: r.id, title: r.title, severity: r.severity, explanation: r.explanation, evidence: redact(text).slice(0, 600) }));
}
export function scanText(name: string, content: string, kind: "skill" | "mcp"): Scan {
  if (!content.trim() || content.length > 500_000) throw new Error("Provide non-empty text, up to 500 KB.");
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);
  // Windows of three lines capture adjacent credential + delivery instructions.
  for (let i = 0; i < lines.length; i++) {
    for (const f of detect(lines.slice(i, i + 3).join("\n"))) {
      if (!findings.some(old => old.id === f.id)) findings.push({ ...f, line: i + 1 });
    }
  }
  if (kind === "mcp") {
    let config: unknown;
    try { config = JSON.parse(content); } catch { throw new Error("MCP input must be valid JSON (configuration or tool descriptions)."); }
    if (!config || typeof config !== "object") throw new Error("MCP input must be a JSON object or tool array.");
    if (/"(?:command|args)"\s*:/.test(content) && /\bnpx\b/.test(content) && !/@\d+\.\d+/.test(content)) {
      findings.push({ id: "mcp.unpinned", title: "Unpinned MCP executable", severity: "medium", explanation: "Pin the package to a reviewed version; an unpinned install can change between runs.", evidence: "npx configuration without an explicit numeric package version" });
    }
  }
  return { id: randomUUID(), name: redact(name).slice(0, 200) || "Untitled scan", kind, timestamp: new Date().toISOString(), hash: createHash("sha256").update(content).digest("hex"), findings, lines: lines.length };
}
type Obj = Record<string, unknown>;
function obj(v: unknown): Obj { return v && typeof v === "object" && !Array.isArray(v) ? v as Obj : {}; }
function str(v: unknown, fallback = ""): string { return typeof v === "string" && v.length > 0 ? v : fallback; }
function number(v: unknown): number | undefined { const n = typeof v === "number" || typeof v === "string" ? Number(v) : NaN; return Number.isFinite(n) && n >= 0 ? n : undefined; }
function attributes(v: unknown): Obj {
  return Array.isArray(v) ? Object.fromEntries(v.map(a => { const row = obj(a); const value = obj(row.value); return [str(row.key), value.stringValue ?? value.intValue ?? value.doubleValue ?? value.boolValue]; })) : {};
}
export function parseInput(input: string, otlp = false): Obj[] {
  if (input.length > 2_000_000) throw new Error("Import exceeds 2 MB. Split into smaller batches.");
  if (otlp) {
    const doc = obj(JSON.parse(input));
    if (!Array.isArray(doc.resourceLogs)) throw new Error("Expected OTLP JSON resourceLogs. Protobuf is not supported.");
    const records: Obj[] = [];
    for (const r of doc.resourceLogs) {
      const resource = obj(r);
      for (const s of Array.isArray(resource.scopeLogs) ? resource.scopeLogs : []) {
        for (const l of Array.isArray(obj(s).logRecords) ? obj(s).logRecords as unknown[] : []) {
          const log = obj(l); const a = { ...attributes(obj(resource.resource).attributes), ...attributes(log.attributes) };
          const body = obj(log.body).stringValue;
          let bodyObj: Obj = {};
          if (typeof body === "string") { try { bodyObj = obj(JSON.parse(body)); } catch { /* prose is not an action */ } }
          const nanos = number(log.timeUnixNano);
          records.push({ ...bodyObj, ...a, source_type: "otlp", source_agent: a["service.name"] ?? bodyObj.source_agent,
            session_id: a["session.id"] ?? a["gen_ai.conversation.id"] ?? bodyObj.session_id,
            event_type: a["event.name"] ?? bodyObj.event_type ?? "telemetry.log",
            input_tokens: a["gen_ai.usage.input_tokens"] ?? bodyObj.input_tokens,
            output_tokens: a["gen_ai.usage.output_tokens"] ?? bodyObj.output_tokens,
            timestamp: nanos ? new Date(nanos / 1e6).toISOString() : undefined });
        }
      }
    }
    return records;
  }
  let parsed: unknown;
  try { parsed = JSON.parse(input); }
  catch { parsed = input.split(/\r?\n/).filter(l => l.trim()).map((line, i) => { try { return JSON.parse(line); } catch { throw new Error(`Invalid JSON at line ${i + 1}. Nothing was imported.`); } }); }
  const records = Array.isArray(parsed) ? parsed : [parsed];
  if (!records.length || records.length > 2000 || records.some(r => !r || typeof r !== "object" || Array.isArray(r))) throw new Error("Expected 1–2,000 event objects.");
  return records as Obj[];
}
export function normalize(raw: Obj): Event {
  if (JSON.stringify(raw).length > 100_000) throw new Error("One record exceeds 100 KB.");
  const input = obj(raw.tool_input ?? raw.input);
  const tool = str(raw.tool_name ?? raw.tool);
  const command = str(raw.command ?? raw.observed_command ?? input.command);
  const path = str(raw.file_path ?? input.file_path ?? input.path);
  const url = str(raw.url ?? input.url);
  let type = str(raw.event_type ?? raw.observed_event_type);
  if (!type) {
    if (["Bash", "bash", "Shell", "shell", "exec_command", "shell_command", "exec"].includes(tool) && command) type = "command.exec";
    else if (["Read", "read_file"].includes(tool)) type = "file.read";
    else if (["Write", "Edit", "write_file", "apply_patch"].includes(tool)) type = "file.write";
    else if (["browser.navigate", "browser_navigate"].includes(tool)) type = "browser.navigate";
    else if (tool) type = "tool.call";
    else if (raw.record_type === "finding") type = "finding";
    else throw new Error("Record needs event_type or tool_name. Raw transcripts are not supported; normalize them first.");
  }
  const detail = command || path || url || str(raw.content_preview ?? raw.observed_content_preview ?? raw.summary) || tool || type;
  const findings = /(?:result|message|telemetry)/.test(type) ? [] : detect(detail);
  if (raw.record_type === "finding") {
    findings.push({ id: str(raw.rule_id, "imported.finding"), title: redact(str(raw.title, "Imported finding")), severity: ["critical", "high", "medium", "info"].includes(str(raw.severity)) ? raw.severity as Severity : "medium", explanation: "Imported rule match. It indicates a pattern, not proof of compromise or action completion.", evidence: redact(detail).slice(0, 600) });
  }
  const timestamp = str(raw.timestamp, new Date().toISOString());
  if (!Number.isFinite(Date.parse(timestamp))) throw new Error("Invalid event timestamp.");
  const clean = (s: string) => redact(s).slice(0, 500);
  const stableId = str(raw.event_id ?? raw.finding_id ?? raw.id);
  // A hook's own tool_use_id (Claude Code's "toolu_...", Codex's call_id, Cursor's tool_use_id --
  // all verified to carry this field, see agents.ts notes) identifies one physical tool call
  // regardless of which hook config observed it. That matters when the *same* Claude Code CLI
  // invocation is wrapped by more than one installed hook -- e.g. run from inside Cursor's own
  // agent/IDE, which spawns Claude Code as a subprocess but also fires its own preToolUse hook for
  // the same tool call beam already installed into .claude/settings.json. Deliberately left out of
  // the source_agent-namespaced stableId branch below (unlike event_id/finding_id, which come from
  // independent import sources that legitimately could reuse the same id) so both hook firings
  // collapse into a single event instead of duplicating on the dashboard.
  const toolUseId = str(raw.tool_use_id ?? raw.toolUseId);
  const usage = obj(raw.usage ?? raw.token_usage ?? raw.tokenUsage);
  const inputTokens = number(raw.input_tokens ?? raw.inputTokens ?? usage.input_tokens ?? usage.inputTokens ?? usage.prompt_tokens ?? usage.promptTokens);
  const outputTokens = number(raw.output_tokens ?? raw.outputTokens ?? usage.output_tokens ?? usage.outputTokens ?? usage.completion_tokens ?? usage.completionTokens);
  const costUsd = number(raw.cost_usd ?? raw.costUsd ?? usage.cost_usd ?? usage.costUsd);
  const mcpRaw = obj(raw.mcp ?? raw.mcp_request ?? raw.mcpRequest);
  const explicitMcpServer = str(raw.mcp_server ?? raw.mcpServer ?? mcpRaw.server ?? mcpRaw.server_name ?? mcpRaw.serverName);
  const explicitMcpTool = str(raw.mcp_tool ?? raw.mcpTool ?? mcpRaw.tool ?? mcpRaw.tool_name ?? mcpRaw.toolName);
  const explicitMcpResource = str(raw.mcp_resource ?? raw.mcpResource ?? mcpRaw.resource ?? mcpRaw.resource_uri ?? mcpRaw.resourceUri);
  const toolParts = tool.match(/^mcp[.:/]([^.:/]+)[.:/]([^.:/]+)$/i);
  const mcpServer = explicitMcpServer || (toolParts ? toolParts[1] : "");
  const mcpTool = explicitMcpTool || (toolParts ? toolParts[2] : "");
  const mcpRequestType = explicitMcpResource ? "resource" : mcpTool ? "tool" : "unknown";
  const phase = (() => { const event = str(raw.hook_event_name).toLowerCase(); return event === "pretooluse" ? "proposed" : event === "posttooluse" ? "completed hook" : "observed"; })();
  return {
    id: createHash("sha256").update(
      stableId ? `${str(raw.source_agent)}:${str(obj(raw.endpoint).hostname)}:${stableId}`
      : toolUseId ? `tool_use:${str(obj(raw.endpoint).hostname)}:${phase}:${toolUseId}`
      : JSON.stringify(raw)
    ).digest("hex"),
    timestamp: new Date(timestamp).toISOString(), receivedAt: new Date().toISOString(), agent: clean(str(raw.source_agent ?? raw.agent, "custom")),
    session: clean(str(raw.session_id ?? raw.sessionId ?? raw.session, "unassigned")),
    ...(str(raw.session_title) ? { sessionTitle: clean(str(raw.session_title)).slice(0, 100), sessionTitleSource: raw.session_title_source === "agent" ? "agent" as const : "prompt" as const } : {}),
    ...(number(raw.turn) ? { turn: { n: Math.floor(number(raw.turn) as number), topic: clean(str(raw.turn_topic)).slice(0, 100), shift: raw.turn_shift === true } } : {}), type: clean(type), tool: clean(tool), summary: redact(detail).slice(0, 4000),
    project: clean(str(raw.project_path ?? raw.cwd)), source: clean(str(raw.source_type, raw.hook_event_name ? "hook" : "import")),
    endpoint: clean(str(obj(raw.endpoint).hostname ?? raw.hostname, "local")), model: clean(str(raw.model)),
    phase,
    provenance: { recordId: clean(stableId || toolUseId), schemaVersion: clean(str(raw.schema_version)),
      citedEventIds: Array.isArray(raw.cited_event_ids) ? raw.cited_event_ids.filter((v): v is string => typeof v === "string").slice(0, 100).map(clean) : [],
      tags: Array.isArray(raw.tags) ? raw.tags.filter((v): v is string => typeof v === "string").slice(0, 100).map(clean) : [],
      evidence: redact(JSON.stringify(raw.evidence_refs ?? raw.evidence ?? {})).slice(0, 8000) },
    ...(mcpServer || explicitMcpTool || explicitMcpResource ? { mcp: { server: clean(mcpServer || "unknown"), ...(mcpTool ? { tool: clean(mcpTool) } : {}), ...(explicitMcpResource ? { resource: clean(explicitMcpResource) } : {}), requestType: mcpRequestType } } : {}),
    ...(type === "file.write" && changedLines(raw.tool_input ?? raw.input) ? { lines: changedLines(raw.tool_input ?? raw.input) } : {}),
    findings, inputTokens, outputTokens, costUsd,
  };
}
