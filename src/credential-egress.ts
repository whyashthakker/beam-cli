import type { MatchSpan } from "./rule-matches.js";
// A bounded, dependency-free shell heuristic, shared by the CLI and edge SDK.
// Unlike a whole-text keyword conjunction, only transfer arguments / connected
// stdin are sinks. This is not a general shell or JavaScript taint analyzer.
const SENSITIVE = /(?:\.env(?:\b|[./])|\.ssh[\\/]|id_(?:rsa|ed25519)|\.aws[\\/]credentials|\.pgpass\b|\.docker[\\/]config\.json|credentials\.json|\b(?:printenv|process\.env|os\.environ)\b|(?:api[_-]?key|access[_-]?token|password|secret)\b|\$\{?[\w]*(?:TOKEN|SECRET|PASSWORD|API_KEY|CREDENTIAL)[\w]*\}?)/i;
type Token = { value: string; raw: string; start: number; end: number };
type Command = { tokens: Token[]; pipe: boolean; start: number; end: number };

// Preserve quoted arguments as one token. Separators inside quotes cannot join
// unrelated fixtures into a command. Keep raw quotes for recursive shell -c.
function commands(text: string): Command[] {
  const out: Command[] = []; let tokens: Token[] = []; let value = "", raw = "", quote = "", tokenStart = 0;
  const word = () => { if (raw) tokens.push({ value, raw, start: tokenStart, end: tokenStart + raw.length }); value = raw = ""; };
  const end = (pipe: boolean) => { word(); if (tokens.length) out.push({ tokens, pipe, start: tokens[0].start, end: tokens[tokens.length - 1].end }); tokens = []; };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (!raw && !/\s/.test(c)) tokenStart = i;
    if (!quote && c === "$" && text[i + 1] === "(") {
      let level = 1; const start = i; i++;
      while (++i < text.length && level) { if (text[i] === "(") level++; else if (text[i] === ")") level--; }
      const substitution = text.slice(start, i); raw += substitution; value += substitution; i--;
    } else if (c === "\\" && quote !== "'") {
      raw += c;
      if (i + 1 < text.length) { raw += text[++i]; if (text[i] !== "\n") value += text[i]; }
    } else if (quote) {
      raw += c; if (c === quote) quote = ""; else value += c;
    } else if (c === "'" || c === '"') { quote = c; raw += c; }
    else if (c === "#" && !raw) { while (i < text.length && text[i] !== "\n") i++; end(false); }
    else if (c === ";" || c === "\n" || c === "|" || c === "&") {
      const pipe = c === "|" && text[i + 1] !== "|";
      end(pipe); if (text[i + 1] === c && (c === "|" || c === "&")) i++;
    } else if (/\s/.test(c)) word();
    else { raw += c; value += c; }
  }
  end(false); return out;
}

function executable(tokens: Token[]): number {
  let i = 0;
  while (i < tokens.length && (/^[\w]+=[\s\S]*/.test(tokens[i].value) || /^(?:sudo|command|exec)$/.test(tokens[i].value) || tokens[i].value === "env" && i + 1 < tokens.length)) i++;
  return i;
}
function name(token?: Token): string { return token?.value.split(/[\\/]/).pop()?.toLowerCase() ?? ""; }

// Shell substitutions execute even inside double quotes (but not single quotes).
function expansionExposure(text: string, depth: number): boolean {
  let quote = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "\\" && quote !== "'") { i++; continue; }
    if (c === "'" && quote !== '"') { quote = quote ? "" : "'"; continue; }
    if (quote === "'") continue;
    if (c === '"') { quote = quote ? "" : '"'; continue; }
    if (c === "$" && text[i + 1] === "(") {
      const start = i + 2; let level = 1; i++;
      while (++i < text.length && level) { if (text[i] === "(") level++; else if (text[i] === ")") level--; }
      if (shellExposure(text.slice(start, level ? i : i - 1), depth + 1)) return true;
      i--;
    } else if (c === "`") {
      const start = ++i;
      while (i < text.length && text[i] !== "`") { if (text[i] === "\\") i++; i++; }
      if (shellExposure(text.slice(start, i), depth + 1)) return true;
    }
  }
  return false;
}

function shellExposure(text: string, depth: number): boolean {
  if (depth > 4) return false;
  // Here-doc bodies are data to their recipient. Examine shell recipients as
  // code; for files, examine the body only if that path is subsequently run.
  const lines = text.split("\n"); const visible: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const doc = /<<(-)?\s*(?:'([^']+)'|"([^"]+)"|([\w]+))/.exec(line);
    if (!doc) { visible.push(line); continue; }
    // Ignore heredoc-looking text inside quoted fixture strings and comments.
    let quote = "";
    for (let j = 0; j < doc.index; j++) {
      const c = line[j];
      if (c === "\\" && quote !== "'") { j++; continue; }
      if (quote) { if (c === quote) quote = ""; }
      else if (c === "'" || c === '"') quote = c;
      else if (c === "#") { quote = "#"; break; }
    }
    if (quote) { visible.push(line); continue; }
    const delimiter = doc[2] ?? doc[3] ?? doc[4]; const body: string[] = [];
    while (++i < lines.length && (doc[1] ? lines[i].replace(/^\t+/, "") : lines[i]) !== delimiter) body.push(lines[i]);
    const head = commands(line)[0]?.tokens ?? [];
    const recipient = name(head[executable(head)]);
    const file = />\s*([^\s<>]+)/.exec(line)?.[1];
    const later = lines.slice(i + 1).join("\n");
    const runsFile = file && commands(later).some(c => {
      const at = executable(c.tokens); const cmd = name(c.tokens[at]);
      return c.tokens[at]?.value === file || /^(?:bun|node|tsx|python[23]?|sh|bash|zsh)$/.test(cmd) && c.tokens.slice(at + 1).some(t => t.value === file);
    });
    if ((/^(?:sh|bash|zsh)$/.test(recipient) || /\|\s*(?:sh|bash|zsh)\b/.test(line) || runsFile) && shellExposure(body.join("\n"), depth + 1)) return true;
    // A here-doc sent to curl is itself an outbound payload.
    if (/^(?:nc|ncat|socat)$/.test(recipient) && SENSITIVE.test(body.join("\n"))) return true;
    if (/^(?:curl|wget)$/.test(recipient) && /(?:@-|--post-file[= ]-)/.test(line) && SENSITIVE.test(body.join("\n"))) return true;
    if (doc[4] && expansionExposure(body.join("\n"), depth)) return true;
    visible.push(line.replace(doc[0], ""));
  }
  let sensitiveStdin = false;
  const sensitiveVariables = new Set<string>();
  const sensitive = (value: string) => SENSITIVE.test(value) || [...value.matchAll(/\$\{?([A-Za-z_]\w*)/g)].some(m => sensitiveVariables.has(m[1]));
  for (const command of commands(visible.join("\n"))) {
    const { tokens, pipe } = command; const at = executable(tokens); const cmd = name(tokens[at]);
    for (const token of tokens) {
      const assignment = /^([A-Za-z_]\w*)=([\s\S]*)$/.exec(token.value);
      if (!assignment) break;
      if (sensitive(assignment[2])) sensitiveVariables.add(assignment[1]);
      else sensitiveVariables.delete(assignment[1]);
    }
    if (/^(?:echo|printf|cat|curl|wget|scp|rsync|nc|ncat|socat|env|sh|bash|zsh)$/.test(cmd) || tokens.some(t => /^[A-Za-z_]\w*=/.test(t.value))) {
      if (expansionExposure(tokens.map(t => t.raw).join(" "), depth)) return true;
    }
    const args = tokens.slice(at + 1).map(t => t.value); const joined = args.join(" ");
    // Inspect explicitly executed shell strings, never arbitrary string args to
    // echo, grep, console.log, detect, etc.
    if (/^(?:sh|bash|zsh)$/.test(cmd)) {
      const flag = args.findIndex(a => /^-[a-z]*c[a-z]*$/.test(a));
      if (flag >= 0 && shellExposure(args[flag + 1] ?? "", depth + 1)) return true;
    }
    const transfer = /^(?:curl|wget|scp|rsync|nc|ncat|socat)$/.test(cmd);
    if (transfer) {
      if (sensitiveStdin && /^(?:nc|ncat|socat)$/.test(cmd)) return true;
      if (/^(?:scp|rsync)$/.test(cmd) && /^[^/\s]+:[\s\S]+/.test(args[args.length - 1] ?? "") && args.slice(0, -1).some(a => sensitive(a))) return true;
      for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        // A URL path mentioning 'secret' is not a secret payload. Query values
        // and userinfo can carry credentials; payload/header/file options can too.
        if (/^https?:\/\//i.test(arg) && ((/[?&](?:api[_-]?key|token|password|secret)=/i.test(arg)) || /^https?:\/\/[^/@\s]+:[^/@\s]+@/i.test(arg) || /[?&][^=]+=\$/.test(arg) && sensitive(arg))) return true;
        const compact = /^-(?:d|F|H|u|T)(.+)$/.exec(arg);
        if (compact && sensitive(compact[1])) return true;
        if (/^(?:-d|-F|-H|-u|-T|--json|--data(?:-raw|-binary|-urlencode)?|--form|--header|--user|--upload-file|--post-data|--post-file)(?:=|$)/.test(arg)) {
          const payload = arg.includes("=") ? arg.slice(arg.indexOf("=") + 1) : args[++i] ?? "";
          if (sensitive(payload)) return true;
          if (sensitiveStdin && /(?:@-|\/dev\/stdin|\/proc\/self\/fd\/0)/.test(payload)) return true;
        }
        if (/^<(?:\s*)/.test(arg) && sensitive(arg + (args[i + 1] ?? ""))) return true;
      }
    }
    const readsSensitive = /^(?:cat|printenv|env|echo|printf|head|tail|sed|awk|base64)$/.test(cmd) && (sensitive(joined) || /^(?:printenv|env)$/.test(cmd));
    const propagates = /^(?:cat|base64|gzip|tee|sed|awk|tr|head|tail)$/.test(cmd);
    sensitiveStdin = pipe && (readsSensitive || sensitiveStdin && propagates);
  }
  return false;
}

export function possibleCredentialExposure(text: string): boolean {
  if (shellExposure(text, 0)) return true;
  // Skills are natural-language instructions, not just shell programs. Require
  // an explicit sensitive read followed by a referring delivery instruction.
  // Do not correlate arbitrary prose, URLs, code strings or separate fixtures.
  return /(?:^|\n)\s*(?:read|collect|extract)\b[^\n]{0,200}(?:\.env\b|\bAPI_KEY\b|\bcredentials?\b)[^\n]*\n\s*(?:send|upload|exfiltrate)\s+(?:it|them|the\s+(?:credentials?|contents?|secrets?))\b[^\n]{0,200}https?:\/\//i.test(text);
}

/** Locate only original executable command/pipeline ranges independently
 * accepted by the detector. Do not scan inert heredoc bodies as commands. */
function heredocDataRanges(text: string): {start:number;end:number}[] {
  const hidden: {start:number;end:number}[] = []; const lines = text.split("\n"); let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]; const doc = /<<(-)?\s*(?:'([^']+)'|"([^"]+)"|([\w]+))/.exec(line);
    let quote = "";
    if (doc) for (let j = 0; j < doc.index; j++) {
      const c=line[j]; if(c === "\\" && quote !== "'"){j++;continue;}
      if(quote){if(c===quote)quote="";} else if(c === "'" || c === '"')quote=c; else if(c==="#"){quote="#";break;}
    }
    offset += line.length + 1;
    if (!doc || quote) continue;
    const start=offset; const delimiter=doc[2]??doc[3]??doc[4];
    while (++i < lines.length) { offset += lines[i].length + 1; if((doc[1]?lines[i].replace(/^\t+/,""):lines[i])===delimiter) break; }
    hidden.push({start,end:offset});
  }
  return hidden;
}
export function shellActionCommands(text: string) {
  const hidden = heredocDataRanges(text);
  return commands(text).filter(command => !hidden.some(range => command.start < range.end && command.end > range.start));
}
export function credentialExposureSpans(text: string): MatchSpan[] {
  const hidden = heredocDataRanges(text);
  const spans: MatchSpan[] = []; let groupStart: number | undefined;
  for (const command of commands(text)) {
    if (hidden.some(range => command.start < range.end && command.end > range.start)) { groupStart=undefined; continue; }
    groupStart ??= command.start;
    const candidate=text.slice(groupStart,command.end);
    if (possibleCredentialExposure(candidate)) {
      spans.push({start:groupStart,end:command.end,label:"Sensitive outbound transfer"});
      if(spans.length===8)break;
    }
    const assignment=/^[A-Za-z_]\w*=/.test(command.tokens[0]?.value??"");
    if(!command.pipe && !assignment)groupStart=undefined;
  }
  return spans;
}
