// Detection rules for `beam monitor`: attacks against a running application, seen in its logs and
// HTTP access logs. Separate from the agent-hook catalog in core.ts on purpose -- application logs
// are full of words like "env", "token" and "production" that would drown those rules -- but a few
// built-in rules that mean the same thing anywhere (reverse shells, piped remote code, cloud
// metadata access) are reused as-is. Attacks on LLM features (prompt injection and friends) come
// from prompt-attacks.ts. Heuristic, like everything else in Beam.
import { builtinRulesById, type RuleCategory } from "./rule-catalog.js";
import type { CustomDetector } from "./data-detectors.js";
import type { MonitorSeverity } from "./monitor-client.js";
import { promptAttack, revealHidden } from "./prompt-attacks.js";
import { foreignTo, pathFamilies, stackRules, type Stack } from "./monitor-stacks.js";

/** log/http: lines from log files and traffic. prompt/output: text going into, or coming out of, an LLM (SDK). */
export type LineSource = "log" | "http" | "prompt" | "output";
export interface MonitorRule {
  id: string; title: string; severity: MonitorSeverity; category: RuleCategory | "exploit" | "llm";
  /** Where the rule applies; omitted means log and http lines (never prompts or model output). */
  sources?: LineSource[];
  /** `decoded` is URL-decoded (twice, for double encoding); `raw` is the line as written. */
  match: (decoded: string, raw: string) => boolean;
}

// Trailing boundary for shell commands, so `| id=5` in a log line isn't read as running `id`.
const END = String.raw`(?=$|[\s;'"&|)\x60])`;
const commandInjection = new RegExp(String.raw`(?:[;|\x60]|\$\(|&&)\s*(?:id|whoami|uname\s+-a|cat\s+/etc/(?:passwd|shadow)|(?:curl|wget)\s+\S+|nc\s+-\w|bash\s+-[ic]|sh\s+-c|ping\s+-c\s*\d+)${END}`, "i");
// A URL-like parameter pointing the server at itself, its network or its cloud metadata, or a
// scheme only an attacker wants fetched. LLM agents with browsing or fetch tools are a common way
// in. Parameters are split and checked one by one: as one regex this backtracked quadratically on
// long hostile query strings, and it runs inside customer apps.
const SSRF_NAME = /url|uri|link|src|dest|target|redirect|callback|webhook|feed|host|endpoint|proxy|image|fetch|next|return/i;
const SSRF_SCHEME = /^(?:gopher|dict|ldap|tftp|jar|netdoc):\/\//i;
const SSRF_INTERNAL = /^(?:(?:https?|ftp):\/\/(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|0x7f\w*|2130706433|\[::(?:1|ffff:[^\]]{0,40})?\]|10\.\d+\.\d+\.\d+|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|100\.100\.100\.200|metadata\.google\.internal)|file:\/)/i;
function ssrf(s: string): boolean {
  const query = s.indexOf("?");
  if (query < 0) return false;
  let seen = 0;
  for (const param of s.slice(query + 1).split(/[&?\s"]/)) {
    const eq = param.indexOf("=");
    if (eq < 0) continue;
    if (++seen > 100) break;
    const name = param.slice(0, eq);
    const value = param.slice(eq + 1);
    if (SSRF_SCHEME.test(value) || (name.length <= 64 && SSRF_NAME.test(name) && SSRF_INTERNAL.test(value))) return true;
  }
  return false;
}
// Credentials, by format. Case-sensitive, as the real prefixes are. The bare "sk-" family also has
// to look random, because "sk-" turns up in ordinary text: a URL slug like
// /blog/samsung-sk-hynix-upgrade-china-nand-plants-2026 is not an OpenAI key.
const KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk-(?:proj-|ant-|or-v1-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,}|AIza[0-9A-Za-z_-]{35}|gsk_[A-Za-z0-9]{40,}|hf_[A-Za-z0-9]{30,}|r8_[A-Za-z0-9]{30,}|xai-[A-Za-z0-9]{40,}|pplx-[A-Za-z0-9]{40,}|beam_app_[\w-]{20,})\b/g;
const BEARER = /\bauthorization:\s*bearer\s+[A-Za-z0-9._~+/-]{20,}/i;
/** A matched credential, or text that only looks like one (an sk- slug, a sentence). */
export function keyLike(match: string): boolean {
  if (!match.startsWith("sk-")) return true;
  const body = match.replace(/^sk-(?:proj-|ant-|or-v1-|svcacct-|admin-)?/, "");
  // Lowercase words joined by hyphens or underscores: a slug or a name, never a key.
  if (/^[a-z0-9]+(?:[-_][a-z0-9]+){2,}$/.test(body) && /[a-z]{3,}[-_][a-z]{3,}/.test(body)) return false;
  const digits = body.replace(/\D/g, "").length;
  const mixedCase = /[a-z]/.test(body) && /[A-Z]/.test(body);
  // Real keys: mixed case with digits (OpenAI, Anthropic), or long hex (DeepSeek, OpenRouter).
  return (mixedCase && digits >= 2) || /^[a-f0-9]{32,}$/.test(body);
}
/** Whether the text holds something that looks like a real credential. */
export function hasSecret(text: string): boolean {
  if (BEARER.test(text)) return true;
  for (const [match] of text.matchAll(KEY)) if (keyLike(match)) return true;
  return false;
}
const XSS = /<script[\s>]|javascript:\s*[a-z(]|<(?:img|svg|body|iframe)\b[^>]{0,200}\son(?:error|load)\s*=|\bdocument\.cookie\b/i;
const EVERYWHERE: LineSource[] = ["log", "http", "prompt", "output"];
const SENSITIVE_FILE = /\/(?:\.env(?:\.[\w-]+)?|\.git\/(?:config|HEAD)|\.aws\/credentials|\.ssh\/id_\w+|wp-config\.php(?:\.bak)?|\.htpasswd|server-status|actuator\/(?:env|heapdump)|\.DS_Store)(?=[\s?"'#]|$)/i;
const ACCESS_STATUS = /"[A-Z]+ \S+ HTTP\/[\d.]+" (\d{3})\b|"(?:status|httpStatus|status_code|statusCode|response_status)"\s*:\s*"?(\d{3})\b/;
/** The response status in an access-log line was 2xx. */
function isSuccess(line: string): boolean {
  const m = line.match(ACCESS_STATUS);
  return (m?.[1] ?? m?.[2] ?? "").startsWith("2");
}

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
  { id: "web.ssrf", title: "Server-side request forgery attempt", severity: "high", category: "exploit", sources: ["http"],
    match: s => ssrf(s) },
  { id: "app.secret_in_log", title: "Credential written to logs", severity: "high", category: "secrets",
    match: (_s, raw) => hasSecret(raw) },
  { id: "web.xss", title: "Cross-site scripting attempt", severity: "medium", category: "exploit",
    match: s => XSS.test(s) },
  { id: "web.prototype_pollution", title: "Prototype pollution attempt", severity: "medium", category: "exploit",
    match: s => /\b__proto__\b\s*[\]["'=:.]|constructor\s*\[\s*["']?prototype/i.test(s) },
  // Bots ask every site for /.env all day, so a probe alone is medium. One that got a 2xx back
  // may have handed over the app's keys: high. (An app that answers 200 to every path, like a
  // single-page app's catch-all, can trip the second.)
  { id: "web.sensitive_file_probe", title: "Probe for secrets or config files", severity: "medium", category: "recon", sources: ["http"],
    match: s => SENSITIVE_FILE.test(s) },
  { id: "web.secret_file_exposed", title: "Secret or config file served to a client", severity: "high", category: "secrets", sources: ["http"],
    match: (s, raw) => SENSITIVE_FILE.test(s) && isSuccess(raw) },
  { id: "web.scanner", title: "Known attack tool", severity: "medium", category: "recon", sources: ["http"],
    match: s => /\b(?:sqlmap|nikto|nuclei|masscan|zgrab|acunetix|nessus|wpscan|dirbuster|gobuster|feroxbuster|ffuf|hydra|openvas|commix|xsstrike)\b/i.test(s) },
];

// Attacks on the app's LLM features. Prompt-side rules also read traffic and logs, because
// prompts arrive in query strings and apps log them; forged chat markers only count where a
// client wrote them (a model server's own logs are full of its template).
const llmRules: MonitorRule[] = [
  { id: "llm.prompt_injection", title: "Prompt injection attempt", severity: "high", category: "llm", sources: EVERYWHERE,
    match: s => promptAttack.override(s) },
  { id: "llm.reviewer_manipulation", title: "Attempt to sway an AI reviewer", severity: "high", category: "llm", sources: EVERYWHERE,
    match: s => promptAttack.reviewer(s) },
  { id: "llm.hidden_instructions", title: "Hidden instructions in invisible Unicode", severity: "high", category: "llm", sources: EVERYWHERE,
    match: s => promptAttack.hidden(s) },
  { id: "llm.chat_template_injection", title: "Forged system or chat-template markers", severity: "high", category: "llm", sources: ["http", "prompt"],
    match: s => promptAttack.chatTemplate(s) },
  { id: "llm.secret_extraction", title: "Attempt to extract API keys or secrets", severity: "high", category: "llm", sources: ["log"],
    match: s => promptAttack.secretRequest(s) },
  { id: "llm.secret_extraction", title: "Attempt to extract API keys or secrets", severity: "high", category: "llm", sources: ["http", "prompt"],
    match: s => promptAttack.secretRequest(s) || promptAttack.secretCommand(s) },
  { id: "llm.jailbreak", title: "Jailbreak attempt", severity: "medium", category: "llm", sources: ["log", "http", "prompt"],
    match: s => promptAttack.jailbreak(s) },
  { id: "llm.prompt_extraction", title: "System prompt or data extraction attempt", severity: "medium", category: "llm", sources: ["log", "http", "prompt"],
    match: s => promptAttack.extraction(s) },
  { id: "llm.output_exfiltration", title: "Data exfiltration link in model output", severity: "high", category: "llm", sources: ["log"],
    match: (_s, raw) => promptAttack.markdownExfil(raw) },
  { id: "llm.output_exfiltration", title: "Data exfiltration link in model output", severity: "high", category: "llm", sources: ["output"],
    match: (_s, raw) => promptAttack.htmlExfil(raw) },
  { id: "llm.output_secret", title: "Credential in model output", severity: "high", category: "llm", sources: ["output"],
    match: (_s, raw) => hasSecret(raw) || promptAttack.envSecret(raw) },
  { id: "llm.output_script", title: "Script or active HTML in model output", severity: "medium", category: "llm", sources: ["output"],
    match: (_s, raw) => XSS.test(raw) },
];

const sharedRules: MonitorRule[] = builtinRulesById(["network.reverse-shell", "execution.remote", "execution.obfuscated", "network.metadata"])
  .map(r => ({
    id: r.id, title: r.title, severity: r.severity === "info" ? "medium" : r.severity, category: r.category, match: (s: string) => r.match(s),
    // An agent asked to fetch the metadata endpoint is the same attack as a request for it.
    ...(r.id === "network.metadata" ? { sources: EVERYWHERE } : {}),
  }));

export const monitorRules: MonitorRule[] = [...appRules, ...llmRules, ...sharedRules, ...stackRules];
const CLASSIC: LineSource[] = ["log", "http"];

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

/** The rules a line matches. Prompts and model output aren't URL-decoded: they aren't URLs. */
export function matchLine(line: string, source: LineSource = lineSource(line), extra: MonitorRule[] = []): MonitorRule[] {
  const raw = line.length > 16_384 ? line.slice(0, 16_384) : line;
  const decoded = source === "prompt" || source === "output" ? raw : decodeForMatch(line);
  return [...monitorRules, ...extra].filter(r => (r.sources ?? CLASSIC).includes(source) && r.match(decoded, raw));
}

/**
 * Redaction for evidence that leaves the machine. Unlike the agent-hook redaction it keeps query
 * strings -- for an access log the query usually *is* the attack -- but removes credentials,
 * bearer tokens, URL userinfo, email addresses and the policy's custom detector matches.
 */
export function redactLine(line: string, custom: CustomDetector[] = []): string {
  // Hidden Unicode text is made readable first, so it is redacted like the rest and a reviewer can see it.
  let out = revealHidden(line.slice(0, 4000))
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, "[REDACTED PRIVATE KEY]")
    .replace(/\b(?:sk-(?:proj-|ant-|or-v1-|svcacct-|admin-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,}|AIza[0-9A-Za-z_-]{35}|gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|r8_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,}|pplx-[A-Za-z0-9]{20,}|beam_app_[\w-]{20,})\b/g, m => (keyLike(m) ? "[REDACTED TOKEN]" : m))
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
const REQUEST_LINE = /"([A-Z]+) (\S+) HTTP\/[\d.]+"/;
const JSON_METHOD = /"(?:method|http_method|request_method)"\s*:\s*"([A-Z]+)"/;
const JSON_PATH = /"(?:path|uri|url|request_uri|requestPath)"\s*:\s*"([^"]+)"/;
const LLM_PATH = /\/(?:chat|completions?|generate|llm|ai|assistant|agents?|ask|prompt|inference|copilot)(?:[/?#]|$)|\/v1\/(?:messages|responses|embeddings)(?:[/?#]|$)/i;
/** A POST to what looks like an LLM endpoint (chat, completions, generate…), each one a paid model call. */
export function isLlmRequest(line: string): boolean {
  const request = line.match(REQUEST_LINE);
  const method = request?.[1] ?? line.match(JSON_METHOD)?.[1];
  const path = request?.[2] ?? line.match(JSON_PATH)?.[1];
  return method === "POST" && Boolean(path && LLM_PATH.test(path.split("?")[0]!));
}

/**
 * What an access-log line says about the request and its response, for the finding (and the
 * dashboard's attack analytics). Every field is optional: log formats differ, and a request seen
 * by the SDK in middleware has no response yet.
 */
export interface RequestMeta {
  method?: string; path?: string; host?: string; status?: number; bytes?: number; durationMs?: number;
  userAgent?: string; referer?: string; country?: string; asn?: number;
  /** The Web Bot Auth key directory the client named (Signature-Agent), e.g. "https://chatgpt.com". A claim until verified. */
  signatureAgent?: string;
  /** What else the client sent about itself (SDK only, beside the line); see ClientSignals. */
  signals?: ClientSignals;
}
/**
 * Hints about the client beyond its user agent, as the SDK reads them from headers and the CDN:
 * which headers were present (never their values), whether the request carried an HTTP message
 * signature, the MCP protocol version, and Cloudflare's bot verdict when the app runs behind it.
 */
export interface ClientSignals {
  /** Signature and Signature-Input headers were both present (RFC 9421). */
  signed?: boolean;
  /** Accept-Language, Sec-Fetch-Mode and Sec-CH-UA were present. Real browsers send all three. */
  acceptLanguage?: boolean; secFetch?: boolean; clientHints?: boolean;
  /** The MCP-Protocol-Version header (or "unknown" when only Mcp-Session-Id was sent). */
  mcp?: string;
  /** Cloudflare Bot Management: verified bot, Web Bot Auth signed agent, score 1-99, category, JA4 TLS fingerprint. */
  cfVerifiedBot?: boolean; cfSignedAgent?: boolean; cfBotScore?: number; cfBotCategory?: string; ja4?: string;
}
/** "https://chatgpt.com" from a Signature-Agent value in any of its forms ("…", g="…", bare). */
export function signatureAgentOrigin(value: string | undefined | null): string | undefined {
  const url = value?.slice(0, 500).match(/https?:\/\/[A-Za-z0-9.-]{1,200}(?::\d{1,5})?/)?.[0];
  return url?.toLowerCase();
}
// nginx/Apache combined: "GET /x HTTP/1.1" 404 512 "referer" "agent"
const COMBINED = /"([A-Z]+) (\S+) HTTP\/[\d.]+" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;
const jsonField = (names: string, number = false) =>
  new RegExp(`"(?:${names})"\\s*:\\s*${number ? String.raw`"?(\d{1,12}(?:\.\d+)?)` : String.raw`"((?:[^"\\]|\\.){0,2000})"`}`);
const J_HOST = jsonField("host|hostname|http_host|domain|requestHost");
const J_UA = jsonField("clientUa|userAgent|user_agent|http_user_agent|ua|requestUserAgent");
const J_REFERER = jsonField("referer|referrer|http_referer");
const J_COUNTRY = jsonField("country|geo_country|cf_ipcountry|clientCountry|ipCountry|countryCode");
const J_STATUS = jsonField("status|httpStatus|status_code|statusCode|response_status|responseStatusCode", true);
const J_BYTES = jsonField("bytes|body_bytes_sent|bytes_sent|responseBytes|response_size|responseSize", true);
const J_DURATION = jsonField("durationMs|duration_ms|responseTimeMs|response_time_ms|latencyMs", true);
const J_ASN = jsonField("asn|as_number|clientAsn|asNumber", true);
const J_SIG_AGENT = jsonField("signatureAgent|signature_agent|http_signature_agent");
const unescape = (s: string | undefined) => (s === undefined ? undefined : s.replace(/\\(["\\/])/g, "$1"));
const num = (s: string | undefined, max: number) => {
  const n = s === undefined ? NaN : Number(s);
  return Number.isFinite(n) && n >= 0 && n <= max ? n : undefined;
};

/** Method, path, status, size, client agent and so on, from a combined-format or JSON access-log line. */
export function requestMeta(line: string): RequestMeta {
  const text = line.length > 16_384 ? line.slice(0, 16_384) : line;
  const c = text.match(COMBINED);
  const request = c ? null : text.match(REQUEST_LINE);
  const status = num(c?.[3] ?? text.match(J_STATUS)?.[1], 599);
  const country = unescape(text.match(J_COUNTRY)?.[1])?.toUpperCase();
  const meta: RequestMeta = {
    method: c?.[1] ?? request?.[1] ?? text.match(JSON_METHOD)?.[1],
    path: c?.[2] ?? request?.[2] ?? unescape(text.match(JSON_PATH)?.[1]),
    host: unescape(text.match(J_HOST)?.[1]),
    status: status !== undefined && status >= 100 ? Math.floor(status) : undefined,
    bytes: num(c?.[4] === "-" ? undefined : (c?.[4] ?? text.match(J_BYTES)?.[1]), 1e12),
    durationMs: num(text.match(J_DURATION)?.[1], 3_600_000),
    userAgent: c?.[6] ?? unescape(text.match(J_UA)?.[1]),
    referer: c?.[5] && c[5] !== "-" ? c[5] : unescape(text.match(J_REFERER)?.[1]),
    country: country && /^[A-Z]{2}$/.test(country) ? country : undefined,
    asn: num(text.match(J_ASN)?.[1], 4_294_967_295),
    // Only lines that carry one pay for this lookup (nginx: "signature_agent":"$http_signature_agent").
    signatureAgent: text.includes("ignature") ? signatureAgentOrigin(unescape(text.match(J_SIG_AGENT)?.[1])) : undefined,
  };
  for (const key of Object.keys(meta) as (keyof RequestMeta)[]) if (meta[key] === undefined || meta[key] === "") delete meta[key];
  return meta;
}

/**
 * What became of a flagged request.
 * - served: 2xx, the app answered it (the payload may have worked; needs a look)
 * - blocked: 3xx or 4xx, refused, not found or sent elsewhere
 * - failed: 5xx, the app errored (sometimes a sign the payload reached the code)
 * - not_applicable: no response yet, but it targets software this app doesn't run (PHP or
 *   WordPress against a JavaScript app), so it can't work here
 * - unknown: no status to go on
 */
export type RequestOutcome = "served" | "blocked" | "failed" | "not_applicable" | "unknown";
/**
 * With no status, a path only another stack serves (PHP, WordPress, ASP.NET, Java, a Vite dev
 * server...) can't have worked on an app that declares its stack. `javascriptApp` is the SDK's
 * older switch, the same as stack "node".
 */
export function requestOutcome(meta: RequestMeta, options: { javascriptApp?: boolean; stack?: Stack } = {}): RequestOutcome {
  const status = meta.status;
  if (status !== undefined) {
    if (status >= 500) return "failed";
    if (status >= 300) return "blocked";
    if (status >= 200) return "served";
  }
  const stack = options.stack ?? (options.javascriptApp ? "node" : undefined);
  if (stack && meta.path && foreignTo(stack, pathFamilies(meta.path))) return "not_applicable";
  return "unknown";
}

/** A failed sign-in: a 401/403 on an auth path in an access log, or an app's own "login failed" line. */
export function isAuthFailure(line: string, source: LineSource): boolean {
  if (source === "prompt" || source === "output") return false; // a chat message saying "login failed" isn't one
  if (source === "http") return (/"\s(?:401|403)\s/.test(line) || /"(?:status|httpStatus|status_code|statusCode|response_status)"\s*:\s*"?(?:401|403)\b/.test(line)) && AUTH_PATH.test(line);
  return AUTH_FAIL_TEXT.test(line);
}

/** Method, path and status only: the few fields the attack-in-progress signals read on every request. */
export function quickRequest(line: string): { method?: string; path?: string; status?: number } {
  const text = line.length > 16_384 ? line.slice(0, 16_384) : line;
  const request = text.match(REQUEST_LINE);
  const status = text.match(ACCESS_STATUS);
  const code = Number(status?.[1] ?? status?.[2]);
  return {
    method: request?.[1] ?? text.match(JSON_METHOD)?.[1],
    path: request?.[2] ?? text.match(JSON_PATH)?.[1],
    status: code >= 100 && code <= 599 ? code : undefined,
  };
}

/** A path as a route: no query, and ids, numbers and hashes as ":id" ("/orders/8812?x=1" -> "/orders/:id"). */
export function routeKey(path: string): string {
  return (path.split(/[?#]/)[0] || "/")
    .split("/")
    .map(s => (/^\d+$|^[0-9a-f]{8,}$|^[0-9a-f]{8}-[0-9a-f-]{27}$|^(?=.*\d)[A-Za-z0-9_-]{16,}$/i.test(s) ? ":id" : s))
    .join("/")
    .slice(0, 200);
}

const AUTH_SUCCESS_TEXT = /\b(?:login|sign[- ]?in|authentication|auth)\s+(?:succeeded|successful|success|ok)\b|\b(?:successfully\s+)?(?:logged|signed)\s+in\b|\bsession\s+(?:created|started)\s+for\b/i;
/** A successful sign-in: a POST to an auth path answered 2xx or 3xx, or an app's "login succeeded" line. */
export function isAuthSuccess(line: string, source: LineSource): boolean {
  if (source === "http") {
    const r = quickRequest(line);
    return r.method === "POST" && r.status !== undefined && r.status >= 200 && r.status < 400 && Boolean(r.path && AUTH_PATH.test(r.path.split("?")[0]!));
  }
  return source === "log" && AUTH_SUCCESS_TEXT.test(line) && !AUTH_FAIL_TEXT.test(line);
}

// Privilege changes. Text: an app's own audit lines. Traffic: a write, answered 2xx, to an
// endpoint whose path names roles, permissions or keys.
const ADMIN_TEXT = /\b(?:granted|assigned|added|promoted|elevated|made|set)\b[^.\n]{0,60}\b(?:admin(?:istrator)?|owner|superuser|super[- ]admin|root)\b(?:\s+(?:role|access|privileges?|permissions?))?|\b(?:role|is_?admin|is_?superuser|permission)s?\b["']?\s*[:=]\s*["']?(?:admin|owner|superuser|true)\b[^.\n]{0,40}\b(?:granted|assigned|changed|updated|set)\b/i;
const KEY_TEXT = /\b(?:api[ _-]?key|access[ _-]?token|personal access token|service[ _-]account(?: key)?|secret key)\b[^.\n]{0,40}\b(?:created|generated|issued|added|minted)\b|\b(?:created|generated|issued|minted)\b[^.\n]{0,40}\b(?:api[ _-]?key|access[ _-]?token|personal access token|service[ _-]account key)\b/i;
const ADMIN_PATH = /\/(?:roles?|permissions?|grants?|promote|make[-_]admin|admins|privileges?)(?:\/|$)/i;
const KEY_PATH = /\/(?:api[-_]?keys?|keys|tokens|access[-_]tokens|personal[-_]access[-_]tokens|credentials|service[-_]accounts)(?:\/|$)/i;
/** "admin" for a role or permission grant, "key" for a new API key or token, else null. */
export function privilegeChange(line: string, source: LineSource): "admin" | "key" | null {
  if (source === "http") {
    const r = quickRequest(line);
    if (!r.method || !["POST", "PUT", "PATCH"].includes(r.method) || r.status === undefined || r.status < 200 || r.status >= 300 || !r.path) return null;
    const path = r.path.split("?")[0]!;
    return ADMIN_PATH.test(path) ? "admin" : KEY_PATH.test(path) ? "key" : null;
  }
  if (source !== "log") return null;
  return ADMIN_TEXT.test(line) ? "admin" : KEY_TEXT.test(line) ? "key" : null;
}

const TOKENS_TOTAL = /"(?:total_tokens|totalTokens|tokens_used|tokensUsed)"\s*:\s*(\d{1,9})/;
const TOKENS_IN = /"(?:input_tokens|prompt_tokens|inputTokens|promptTokens)"\s*:\s*(\d{1,9})/;
const TOKENS_OUT = /"(?:output_tokens|completion_tokens|outputTokens|completionTokens)"\s*:\s*(\d{1,9})/;
const LOG_USER = /"(?:user|userId|user_id|uid|account|accountId|account_id)"\s*:\s*"([^"]{1,80})"|\b(?:user(?:_?id)?|uid|account(?:_?id)?)=([\w.@:-]{1,80})/i;
/** LLM token usage logged by the app (OpenAI and Anthropic usage fields), with the user it's for. */
export function tokenUsage(line: string): { tokens: number; user?: string } | null {
  if (!line.includes("tokens") && !line.includes("Tokens")) return null;
  const total = line.match(TOKENS_TOTAL)?.[1];
  const tokens = total ? Number(total) : Number(line.match(TOKENS_IN)?.[1] ?? 0) + Number(line.match(TOKENS_OUT)?.[1] ?? 0);
  if (!tokens) return null;
  const user = line.match(LOG_USER);
  return { tokens, user: user?.[1] ?? user?.[2] };
}
/** The user a log line is about (user=, "userId": ...), for keying sign-ins and spend. */
export function logUser(line: string): string | undefined {
  const m = line.match(LOG_USER);
  return m?.[1] ?? m?.[2];
}
