import { createHash, randomUUID } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "info";
export type Finding = { id: string; title: string; severity: Severity; explanation: string; evidence: string; line?: number };
export type Event = {
  id: string; timestamp: string; receivedAt: string; agent: string; session: string;
  type: string; tool: string; summary: string; project: string; source: string;
  endpoint: string; model: string; phase: string; findings: Finding[];
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
    .replace(/\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,})\b/g, "[REDACTED TOKEN]")
    .replace(/(bearer\s+)[A-Za-z0-9._~+\/-]{8,}/gi, "$1[REDACTED]")
    .replace(/((?:[\w-]*(?:api[_-]?key|token|secret|password|authorization)[\w-]*)["']?\s*[:=]\s*)["']?[^\s,"';&}\]]+/gi, "$1[REDACTED]")
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(/(https?:\/\/[^\s?#"']+)\?[^\s"']*/gi, "$1?[REDACTED QUERY]");
}
export type RuleCategory = "exec" | "exfil" | "impact" | "integrity" | "persistence" | "privilege" | "recon" | "secrets" | "source_control" | "custom";
export type Rule = { id: string; title: string; severity: Severity; category: RuleCategory; explanation: string; match: (s: string) => boolean };

const secret = /(?:\.env(?:\b|[./])|\.ssh[\\/]|id_rsa|id_ed25519|\.aws[\\/]credentials|(?:api[_-]?key|access[_-]?token|password|secret)\b)/i;
const egress = /(?:https?:\/\/|\bcurl\b|\bwget\b|\bupload\b|\bwebhook\b|\bsend\b|\bexfiltrat\w*)/i;
const builtinRules: Rule[] = [
  { id: "destructive.delete", title: "Destructive operation", severity: "high", category: "impact", explanation: "Review the target and backups before allowing a recursive delete or destructive data operation.", match: s => /\brm\s+[^\n]*(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive)|\b(?:drop\s+(?:table|database)|truncate\s+(?:table\s+)?\w+)|\bRemove-Item\b[^\n]*(?:-Recurse|-Force)|\bgit\s+(?:reset\s+--hard|clean\s+-[^\n]*f)/i.test(s) },
  { id: "credentials.access", title: "Sensitive credential reference", severity: "medium", category: "secrets", explanation: "This action or instruction references a credential location. Confirm the agent needs access.", match: s => secret.test(s) },
  { id: "credentials.egress", title: "Possible credential exposure", severity: "critical", category: "exfil", explanation: "Credential references and outbound delivery appear together. Inspect the destination and data before running this.", match: s => secret.test(s) && egress.test(s) },
  { id: "execution.remote", title: "Remote code execution pattern", severity: "high", category: "exec", explanation: "Downloaded content is piped directly into a shell without review.", match: s => /\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|fi)?sh\b/i.test(s) },
  { id: "execution.obfuscated", title: "Encoded execution", severity: "high", category: "exec", explanation: "Encoded content is decoded for execution. Review the decoded payload separately; Beam never executes it.", match: s => /\bbase64\b[^\n]*(?:-d|--decode)[^\n]*\|\s*(?:ba)?sh|\b(?:powershell|pwsh)\b[^\n]*-(?:enc|encodedcommand)\b/i.test(s) },
  { id: "recon.network_sweep", title: "Network sweep", severity: "medium", category: "recon", explanation: "A scanner targets a network range. Verify scope and authorization before the agent probes other systems (ATT&CK T1046).", match: s => /\b(?:nmap|masscan|rustscan)\b/i.test(s) && /(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}|(?:\d{1,3}\.){3}\d{1,3}-\d{1,3}/.test(s) },
  { id: "privilege.elevation", title: "Elevated privileges", severity: "medium", category: "privilege", explanation: "The action requests elevated privileges or broad write permissions.", match: s => /\bsudo\s|\bchmod\s+(?:-R\s+)?777\b/i.test(s) },
  { id: "network.metadata", title: "Cloud metadata access", severity: "high", category: "secrets", explanation: "Cloud metadata endpoints can expose temporary instance credentials.", match: s => /169\.254\.169\.254|metadata\.google\.internal/i.test(s) },
  { id: "persistence.config", title: "Security-sensitive configuration", severity: "high", category: "persistence", explanation: "A persistence or agent configuration target is referenced. Check the intended change and trust boundary.", match: s => /authorized_keys|\bcrontab\b|LaunchAgents[\\/]|ANTHROPIC_BASE_URL/i.test(s) },
  { id: "network.reverse-shell", title: "Reverse shell pattern", severity: "critical", category: "exec", explanation: "This pattern can connect a command shell to another machine.", match: s => /\/dev\/tcp\/|\bnc\b[^\n]*\s-e\s|socket[\s\S]{0,200}subprocess/i.test(s) },
  { id: "instructions.override", title: "Instruction override attempt", severity: "high", category: "integrity", explanation: "Instructions attempt to override existing safeguards or conceal activity from the user.", match: s => /ignore\s+(?:all\s+)?(?:previous|prior|system|safety)\s+(?:instructions|rules|prompts)|(?:do not|don't|never)\s+(?:tell|inform|notify)\s+(?:the\s+)?user|disable\s+(?:security|safety|logging|audit)/i.test(s) },
  { id: "source_control.history_rewrite", title: "Git history rewrite", severity: "medium", category: "source_control", explanation: "Force-pushing or rewriting shared history can silently discard other people's commits. Confirm the branch isn't shared before proceeding.", match: s => /\bgit\s+push\s+[^\n]*(?:--force(?:-with-lease)?|-f\b)|\bgit\s+filter-(?:branch|repo)\b/i.test(s) },
  { id: "integrity.tls_bypass", title: "Certificate or signature verification disabled", severity: "medium", category: "integrity", explanation: "Disabling TLS/certificate verification removes protection against a tampered or impersonated destination.", match: s => /\bcurl\b[^\n]*(?:-k\b|--insecure)|\bwget\b[^\n]*--no-check-certificate|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|\bgit\b[^\n]*-c\s+http\.sslVerify=false/i.test(s) },
];

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
  return {
    id: createHash("sha256").update(stableId ? `${str(raw.source_agent)}:${str(obj(raw.endpoint).hostname)}:${stableId}` : JSON.stringify(raw)).digest("hex"),
    timestamp: new Date(timestamp).toISOString(), receivedAt: new Date().toISOString(), agent: clean(str(raw.source_agent ?? raw.agent, "custom")),
    session: clean(str(raw.session_id ?? raw.session, "unassigned")), type: clean(type), tool: clean(tool), summary: redact(detail).slice(0, 4000),
    project: clean(str(raw.project_path ?? raw.cwd)), source: clean(str(raw.source_type, raw.hook_event_name ? "hook" : "import")),
    endpoint: clean(str(obj(raw.endpoint).hostname ?? raw.hostname, "local")), model: clean(str(raw.model)),
    phase: (() => { const event = str(raw.hook_event_name).toLowerCase(); return event === "pretooluse" ? "proposed" : event === "posttooluse" ? "completed hook" : "observed"; })(),
    provenance: { recordId: clean(stableId), schemaVersion: clean(str(raw.schema_version)),
      citedEventIds: Array.isArray(raw.cited_event_ids) ? raw.cited_event_ids.filter((v): v is string => typeof v === "string").slice(0, 100).map(clean) : [],
      tags: Array.isArray(raw.tags) ? raw.tags.filter((v): v is string => typeof v === "string").slice(0, 100).map(clean) : [],
      evidence: redact(JSON.stringify(raw.evidence_refs ?? raw.evidence ?? {})).slice(0, 8000) },
    findings, inputTokens: number(raw.input_tokens), outputTokens: number(raw.output_tokens), costUsd: number(raw.cost_usd),
  };
}
