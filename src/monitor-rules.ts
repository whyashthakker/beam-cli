// Detection rules for `beam monitor`: attacks against a running application, seen in its logs and
// HTTP access logs. Separate from the agent-hook catalog in core.ts on purpose -- application logs
// are full of words like "env", "token" and "production" that would drown those rules -- but a few
// built-in rules that mean the same thing anywhere (reverse shells, piped remote code, cloud
// metadata access, prompt injection) are reused as-is. Heuristic, like everything else in Beam.
import { builtinRulesById, type RuleCategory } from "./core.js";
import type { CustomDetector } from "./data-detectors.js";
import type { MonitorSeverity } from "./monitor-client.js";

export type LineSource = "log" | "http";
export interface MonitorRule {
  id: string; title: string; severity: MonitorSeverity; category: RuleCategory | "exploit";
  /** Restricts the rule to access-log lines; omitted means every line. */
  sources?: LineSource[];
  /** `decoded` is URL-decoded (twice, for double encoding); `raw` is the line as written. */
  match: (decoded: string, raw: string) => boolean;
}

// Trailing boundary for shell commands, so `| id=5` in a log line isn't read as running `id`.
const END = String.raw`(?=$|[\s;'"&|)\x60])`;
const commandInjection = new RegExp(String.raw`(?:[;|\x60]|\$\(|&&)\s*(?:id|whoami|uname\s+-a|cat\s+/etc/(?:passwd|shadow)|(?:curl|wget)\s+\S+|nc\s+-\w|bash\s+-[ic]|sh\s+-c|ping\s+-c\s*\d+)${END}`, "i");

const appRules: MonitorRule[] = [
  { id: "web.jndi_injection", title: "JNDI lookup (Log4Shell-style) injection", severity: "critical", category: "exploit",
    match: s => /\$\{\s*jndi\s*:|\$\{\s*\$\{\s*(?:::-|lower:|upper:|env:)/i.test(s) },
  { id: "web.path_traversal", title: "Path traversal attempt", severity: "high", category: "exploit",
    match: s => /(?:\.\.[/\\]){2,}|\/etc\/(?:passwd|shadow)\b|\bwin\.ini\b|\/proc\/self\/(?:environ|cmdline)/i.test(s) },
  { id: "web.sql_injection", title: "SQL injection attempt", severity: "high", category: "exploit",
    match: s => /\bunion\b[\s(]+(?:all\s+)?select\b|'\s*(?:or|and)\s+'?\d+'?\s*=\s*'?\d+|\b(?:or|and)\s+1\s*=\s*1\b|\b(?:sleep|pg_sleep)\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+|\bwaitfor\s+delay\s+'|\binformation_schema\b|\bxp_cmdshell\b/i.test(s) },
  { id: "web.command_injection", title: "Command injection attempt", severity: "high", category: "exploit",
    match: s => commandInjection.test(s) },
  { id: "web.template_injection", title: "Server-side template injection probe", severity: "high", category: "exploit",
    match: s => /\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=?\s*\d+\s*\*\s*\d+\s*%>|__class__\.__mro__|__globals__\[|\{\{\s*(?:config|self|request)\.[a-z_]/i.test(s) },
  { id: "web.webshell", title: "Web shell access", severity: "high", category: "persistence",
    match: s => /\/(?:c99|r57|wso|b374k|webshell|cmd|shell)\.(?:php|jsp|aspx?)\b|[?&](?:cmd|exec|command)=(?:whoami|id|ls|uname|cat)\b/i.test(s) },
  { id: "web.deserialization", title: "Serialized object payload", severity: "high", category: "exploit",
    match: s => /\brO0AB[A-Za-z0-9+/=]{8,}|\bO:\d+:"[A-Za-z_\\]+":\d+:\{/.test(s) },
  { id: "app.secret_in_log", title: "Credential written to logs", severity: "high", category: "secrets",
    match: (_s, raw) => /-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,}|AIza[0-9A-Za-z_-]{35}|beam_app_[\w-]{20,})\b|\bauthorization:\s*bearer\s+[A-Za-z0-9._~+/-]{20,}/i.test(raw) },
  { id: "web.xss", title: "Cross-site scripting attempt", severity: "medium", category: "exploit",
    match: s => /<script[\s>]|javascript:\s*[a-z(]|<(?:img|svg|body|iframe)\b[^>]{0,200}\son(?:error|load)\s*=|\bdocument\.cookie\b/i.test(s) },
  { id: "web.prototype_pollution", title: "Prototype pollution attempt", severity: "medium", category: "exploit",
    match: s => /\b__proto__\b\s*[\]["'=:.]|constructor\s*\[\s*["']?prototype/i.test(s) },
  { id: "web.sensitive_file_probe", title: "Probe for secrets or config files", severity: "medium", category: "recon", sources: ["http"],
    match: s => /\/(?:\.env(?:\.[\w-]+)?|\.git\/(?:config|HEAD)|\.aws\/credentials|\.ssh\/id_\w+|wp-config\.php(?:\.bak)?|\.htpasswd|server-status|actuator\/(?:env|heapdump)|\.DS_Store)(?=[\s?"'#]|$)/i.test(s) },
  { id: "web.scanner", title: "Known attack tool", severity: "medium", category: "recon", sources: ["http"],
    match: s => /\b(?:sqlmap|nikto|nuclei|masscan|zgrab|acunetix|nessus|wpscan|dirbuster|gobuster|feroxbuster|ffuf|hydra|openvas|commix|xsstrike)\b/i.test(s) },
];

const sharedRules: MonitorRule[] = builtinRulesById(["network.reverse-shell", "execution.remote", "execution.obfuscated", "network.metadata", "instructions.override"])
  .map(r => ({ id: r.id, title: r.title, severity: r.severity === "info" ? "medium" : r.severity, category: r.category, match: (s: string) => r.match(s) }));

export const monitorRules: MonitorRule[] = [...appRules, ...sharedRules];

const HTTP_LINE = /"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE) \S+ HTTP\/[\d.]+"|^\S+ \S+ \S+ \[[^\]]+\] "|"(?:method|http_method|request_method)"\s*:\s*"[A-Z]+"/;
export function lineSource(line: string): LineSource {
  return HTTP_LINE.test(line) ? "http" : "log";
}

function percentDecode(s: string): string {
  try { return decodeURIComponent(s); } catch { return s.replace(/%[0-9a-f]{2}/gi, m => String.fromCharCode(parseInt(m.slice(1), 16))); }
}
/** URL-decodes up to twice so `%252e%252e%252f` (double-encoded `../`) is matched too. */
export function decodeForMatch(line: string): string {
  let s = line.length > 16_384 ? line.slice(0, 16_384) : line;
  for (let i = 0; i < 2; i++) {
    const next = percentDecode(s.replace(/\+/g, " "));
    if (next === s) break;
    s = next;
  }
  return s;
}

export function matchLine(line: string, source: LineSource = lineSource(line)): MonitorRule[] {
  const decoded = decodeForMatch(line);
  const raw = line.length > 16_384 ? line.slice(0, 16_384) : line;
  return monitorRules.filter(r => (!r.sources || r.sources.includes(source)) && r.match(decoded, raw));
}

/**
 * Redaction for evidence that leaves the machine. Unlike the agent-hook redaction it keeps query
 * strings -- for an access log the query usually *is* the attack -- but removes credentials,
 * bearer tokens, URL userinfo, email addresses and the policy's custom detector matches.
 */
export function redactLine(line: string, custom: CustomDetector[] = []): string {
  let out = line.slice(0, 4000)
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, "[REDACTED PRIVATE KEY]")
    .replace(/\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,}|AIza[0-9A-Za-z_-]{35}|beam_app_[\w-]{20,})\b/g, "[REDACTED TOKEN]")
    .replace(/(bearer\s+)[A-Za-z0-9._~+/-]{8,}/gi, "$1[REDACTED]")
    .replace(/(\b(?:[\w-]*(?:api[_-]?key|token|secret|password|passwd|pwd|authorization|session|cookie)[\w-]*)["']?\s*[:=]\s*)["']?[^\s,"';&}\]]+/gi, "$1[REDACTED]")
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[EMAIL]");
  for (const detector of custom) {
    try { out = out.replace(new RegExp(detector.pattern, "g"), detector.replacement); } catch { /* reported by policy validation */ }
  }
  return out.slice(0, 600);
}

// JSON access logs (Railway, Vercel, Caddy, ALB/CloudFront exports, app loggers) name the client field.
const JSON_CLIENT_IP = /"(?:srcIp|src_ip|clientIp|client_ip|remoteAddr|remote_addr|remoteIp|remote_ip|ip|client|x_forwarded_for|xForwardedFor|http_x_forwarded_for)"\s*:\s*"\[?([0-9a-fA-F:.]{3,45})/;
const LEADING_IP = /^\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)\]?\s/;
// Not preceded by a word character, "/" or "." so version strings like "Chrome/120.0.0.0" aren't read as addresses.
const BARE_IPV4 = /(?<![\w/.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/;
/**
 * The client address in an access-log line: a named field in JSON logs, the first token in
 * nginx/Apache/Caddy common log format, otherwise the first standalone IPv4 address.
 */
export function clientIp(line: string): string | undefined {
  return line.match(JSON_CLIENT_IP)?.[1] ?? line.match(LEADING_IP)?.[1] ?? line.match(BARE_IPV4)?.[0];
}

const AUTH_PATH = /\/(?:login|signin|sign-in|auth|oauth|token|session|api\/v\d+\/auth|wp-login\.php|admin)\b/i;
const AUTH_FAIL_TEXT = /\b(?:login|authentication|auth|sign[- ]?in)\s+(?:failed|failure|denied)|\binvalid\s+(?:password|credentials|username or password|api key|token)|\bfailed\s+password\b|\bincorrect\s+password\b|\bunauthori[sz]ed\b/i;
/** A failed sign-in: a 401/403 on an auth path in an access log, or an app's own "login failed" line. */
export function isAuthFailure(line: string, source: LineSource): boolean {
  if (source === "http") return (/"\s(?:401|403)\s/.test(line) || /"(?:status|httpStatus|status_code|statusCode|response_status)"\s*:\s*"?(?:401|403)\b/.test(line)) && AUTH_PATH.test(line);
  return AUTH_FAIL_TEXT.test(line);
}
