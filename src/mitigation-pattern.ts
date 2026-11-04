/** A bounded suggestion for commands with a concrete, stable target. */
function basicPattern(command: string): string | null {
  if (!command || command.length > 4000 || /\[(?:REDACTED|TRUNCATED)[^\]]*\]|…|[$`\\\n\r]/i.test(command)) return null;
  const source = command.trim();
  if (/^(?:(?:sudo|command)\s+)?(?:env|printenv)(?:\s+-0)?$/i.test(source))
    return String.raw`(?:^|[;&|]\s*)(?:(?:sudo|command)\s+)?(?:env|printenv)(?:\s+-0)?(?=\s*(?:[;&|]|$))`;

  const ping = /^(?:(?:sudo|command)\s+)?(?:\/[A-Za-z0-9_.\/-]+\/)?ping(?:\s+(?:--|-[A-Za-z][A-Za-z0-9-]*(?:=\d{1,6})?|\d{1,6}))*\s+(['"]?)([A-Za-z0-9.-]+)\1$/i.exec(source);
  const host = ping?.[2]?.replace(/\.$/, "");
  if (!host || host.length > 200 || !/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(host)) return null;
  const pattern = String.raw`(?:^|[;&|]\s*)(?:(?:sudo|command)\s+)?(?:\/?[A-Za-z0-9_.-]+\/)*ping(?:\s+(?:--|-[A-Za-z][A-Za-z0-9-]*(?:=\d{1,6})?|\d{1,6}))*\s+['"]?${host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\.?['"]?(?=$|[\s;&|])`;
  return pattern.length <= 1000 ? pattern : null;
}

const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const cleanTarget = (value: string) => value.length >= 2 && !/\[(?:REDACTED|TRUNCATED)|…|[$`\r\n]/i.test(value);
const executablePrefix = String.raw`(?:^|[;&|\n]\s*)(?:(?:sudo|command|exec)\s+)?(?:[\w./\\-]*[/\\])?`;

function scopedPattern(executable: string, target: string, operation?: string, inlineCode = false): string | null {
  if (!cleanTarget(target)) return null;
  const targetSource = escape(target).replace(/\\\*/g, String.raw`[^\s"';|&]*`);
  const range = inlineCode ? String.raw`[\s\S]{0,16000}` : String.raw`[^;&|\n]{0,4000}`;
  const pattern = executablePrefix + executable + String.raw`\b` +
    (operation ? "(?=" + range + operation + ")" : "") +
    "(?=" + range + String.raw`(?:[\s"'=(@]|^)` + targetSource + String.raw`(?=$|[\s"';|&,?)\]}]))`;
  return pattern.length <= 1000 ? pattern : null;
}

/** Derive stable operation + target patterns. Never execute or evaluate the command. */
function derivePattern(command: string): string | null {
  if (!command.trim() || command.length > 16000 || /\[TRUNCATED[^\]]*\]|…/i.test(command)) return null;
  const basic = basicPattern(command);
  if (basic) return basic;

  // Interpreter file operations: retain the path and operation, not the changing payload.
  const interpreter = /^\s*(?:(?:sudo|command)\s+)?(?:[\w./\\-]*[/\\])?(python[23]?|node|bun|ruby|perl|pwsh|powershell)\b/i.exec(command)?.[1];
  if (interpreter) {
    const pathOperation = /(?:Path|open|readFileSync|readFile|writeFileSync|writeFile|appendFileSync|appendFile|read_text|write_text)\s*\(\s*['"]([^'"\r\n]{2,200})['"]/g;
    for (const match of command.matchAll(pathOperation)) {
      const target = match[1] ?? "";
      if (!/(?:[\\/]|\.[A-Za-z0-9_*.-]+$)/.test(target)) continue;
      const write = /(?:write_text|write_bytes|writeFile|appendFile|\.write\s*\(|open\s*\([^\n]{0,220},\s*['"][wax])/i.test(command);
      const read = /(?:read_text|read_bytes|readFile|\.read\s*\(|open\s*\([^\n]{0,220},\s*['"]r)/i.test(command);
      const operation = write ? String.raw`(?:write_text|write_bytes|writeFile|appendFile|\.write\s*\(|['"][wax][+b]?['"])` : read ? String.raw`(?:read_text|read_bytes|readFile|\.read\s*\(|['"]r[+b]?['"])` : undefined;
      if (operation) { const pattern = scopedPattern(escape(interpreter), target, operation, true); if (pattern) return pattern; }
    }
    return null;
  }

  // Parse quoted words without evaluating substitutions, variables or script bodies.
  const segments: string[] = []; let start = 0, quote = "";
  for (let i = 0; i < command.length && segments.length < 40; i++) {
    const c = command[i] ?? "";
    if (c === "\\" && quote !== "'") { i++; continue; }
    if (quote) { if (c === quote) quote = ""; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (/[;|&\n]/.test(c)) { segments.push(command.slice(start, i)); start = i + 1; }
  }
  segments.push(command.slice(start));
  for (const segment of segments) {
    const words = segment.match(/"[^"\r\n]*"|'[^'\r\n]*'|[^\s]+/g)?.map(w => w.replace(/^(['"])([\s\S]*)\1$/, "$2")) ?? [];
    let at = 0;
    while (/^(?:sudo|command|exec)$/.test(words[at] ?? "") || /^[A-Za-z_]\w*=/.test(words[at] ?? "")) at++;
    const executable = (words[at] ?? "").split(/[\\/]/).pop()?.toLowerCase() ?? "";
    const args = words.slice(at + 1);
    if (/^(?:curl|wget|invoke-webrequest|invoke-restmethod)$/.test(executable)) {
      const destination = args.find(a => /^https?:\/\//i.test(a));
      if (destination) {
        try {
          const url = new URL(destination); if (url.username || url.password) continue;
          const target = `${url.protocol}//${url.host}${url.pathname}`;
          const pattern = scopedPattern("(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)", target);
          if (pattern) return pattern;
        } catch { /* no complete destination */ }
      }
    }
    if (/^(?:cat|head|tail|less|more|sed|grep|rg|rm|unlink|rmdir|chmod|chown|cp|mv|tee|touch|truncate|Get-Content|Set-Content|Remove-Item|Select-String)$/i.test(executable)) {
      const targets = args.filter(a => !a.startsWith("-") && cleanTarget(a) && /(?:[\\/]|\.[A-Za-z0-9_*.-]+$)/.test(a));
      const target = targets.find(a => /(?:^|[\\/])(?:\.env|\.ssh|\.aws|credentials|id_(?:rsa|ed25519))/i.test(a)) ?? targets.at(-1);
      if (target) { const pattern = scopedPattern(escape(executable), target); if (pattern) return pattern; }
    }
    if (executable === "git" && /^(?:push|reset|clean|checkout|restore)$/.test(args[0] ?? "")) {
      const behavior = args.includes("--hard") ? "--hard" : args.includes("--force") ? "--force" : args.find((a, i) => i > 0 && !a.startsWith("-"));
      if (behavior) { const pattern = scopedPattern("git", behavior, escape(args[0] ?? "") + String.raw`\b`); if (pattern) return pattern; }
    }
    if (/^(?:npm|pnpm|yarn|pip|pip3|uv|cargo|gem)$/.test(executable) && /^(?:install|add|remove|uninstall)$/.test(args[0] ?? "")) {
      const target = args.slice(1).find(a => !a.startsWith("-") && cleanTarget(a));
      if (target) { const pattern = scopedPattern(escape(executable), target, escape(args[0] ?? "") + String.raw`\b`); if (pattern) return pattern; }
    }
  }
  return null;
}

export function commandBehaviorRegex(command: string): string | null {
  const pattern = derivePattern(command);
  if (!pattern || pattern.length > 1000 || /\[(?:REDACTED|TRUNCATED)/i.test(pattern)) return null;
  try { const regex = new RegExp(pattern, "i"); return !regex.test("") && regex.test(command) ? pattern : null; } catch { return null; }
}
