import { redact, type Finding, type Severity } from "./core.js";
import { firstInstruction } from "./skill-context.js";

// Risky-behavior checks for skill files: privilege escalation, persistence, credential-file
// access, exfiltration tooling, obfuscation, dynamic code execution, download-and-run, supply
// chain, and broad destructive commands. The categories follow explainx-cli's audit rules
// (whyashthakker/explainx-cli, src/audit.ts), but the patterns are tighter on purpose: explainx
// flags bare words like "delete", "npm" or "network", which would light up nearly every skill and
// make the score meaningless. Each pattern here needs an actual command or path shape.
type RiskRule = { id: string; title: string; severity: Severity; explanation: string; re: RegExp };

export const riskRules: RiskRule[] = [
  { id: "risk.privilege_escalation", title: "Privilege escalation (sudo / su / setuid)", severity: "high", explanation: "The skill runs commands with elevated privileges. Confirm it needs root and prefer least-privilege alternatives.",
    re: /\b(?:sudo|doas)\b|(?:^|[\s;&|`(])su\s+(?:-\s*\w*|root)\b|\bchown\s+(?:-R\s+)?root\b|\b(?:setuid|setgid)\b|\bchmod\s+(?:[ugoa]*\+s\b|[2467][0-7]{3}\b)/i },
  { id: "risk.sudoers", title: "Sudoers or admin-group modification", severity: "critical", explanation: "The skill edits sudo configuration or grants admin rights, which permanently widens what any process on the machine can do.",
    re: /\/etc\/sudoers|\bvisudo\b|\bNOPASSWD\b|\busermod\s+-aG\s+(?:sudo|wheel|admin)\b/i },
  { id: "risk.persistence", title: "Persistence mechanism", severity: "high", explanation: "The skill schedules itself or edits startup files, so its effects survive after the agent session ends.",
    re: /\bcrontab\s+(?:-[a-z]+\s+)?\S|\/etc\/cron\.\w+|\blaunchctl\s+(?:load|bootstrap|enable)\b|Launch(?:Agents|Daemons)\b|\bsystemctl\s+(?:--user\s+)?enable\b|\bschtasks(?:\.exe)?\s+\/create\b|Register-ScheduledTask|\bsc(?:\.exe)?\s+create\b|(?:>>|\btee\s+-a)\s*~?\/?(?:\S*\/)?\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b|\/etc\/(?:rc\.local|profile\.d)\b/i },
  { id: "risk.sensitive_files", title: "Credential or identity file access", severity: "high", explanation: "The skill touches SSH keys, cloud credentials, browser stores or password files. Confirm the agent needs their contents.",
    re: /(?:~|\$HOME)?\/?\.ssh\/|\bid_(?:rsa|ed25519|ecdsa)\b|\/etc\/(?:shadow|passwd)\b|(?:~|\$HOME)\/\.aws\/|\.config\/gcloud\b|\.kube\/config\b|\.docker\/config\.json\b|\.gnupg\b|\.netrc\b|\.git-credentials\b|\bLogin Data\b|\bcookies\.sqlite\b|\bwallet\.dat\b|Library\/Keychains/i },
  { id: "risk.exfil_tools", title: "Data exfiltration tooling", severity: "high", explanation: "The skill pipes data to a network tool, uploads files, or sends to a public collection endpoint.",
    re: /\|\s*(?:curl|wget|nc|ncat|netcat|socat)\b|\b(?:scp|rsync)\s+[^\n]*\S+@\S+:|\b(?:sendmail|swaks)\b|\bmailx?\s+-s\b|\bcurl\b[^\n]*(?:\s-d\s+[@<]|--data(?:-binary|-raw)?\s+[@<]|\s-F\s|\s-T\s|--upload-file)|\b(?:transfer\.sh|pastebin\.com|webhook\.site|requestbin\.\w+|interact\.sh|ngrok\.io|burpcollaborator\.net|oast\.\w+)\b/i },
  { id: "risk.obfuscation", title: "Obfuscated or encoded content", severity: "medium", explanation: "Encoded strings, hex escapes or URL shorteners hide what will actually run or where it goes.",
    re: /\bbase64\s+(?:-d|--decode|-D)\b|\batob\s*\(|\bFromBase64String\b|(?:\\x[0-9a-f]{2}){4,}|\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|goo\.gl|cutt\.ly)\/\w|\bchr\s*\(\s*\d+\s*\)\s*\+\s*chr/i },
  { id: "risk.decode_exec", title: "Decode then execute", severity: "high", explanation: "Decompressed or decoded data is piped straight into a shell or interpreter, so its contents are never reviewed.",
    re: /\b(?:gunzip|zcat|gzip\s+-d|xxd\s+-r|openssl\s+enc\s+-d)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\bbase64\s+(?:-d|--decode)\b[^\n]*\|\s*(?:sudo\s+)?(?:python3?|node|ruby|perl)\b/i },
  { id: "risk.code_exec", title: "Dynamic code execution", severity: "medium", explanation: "Strings are evaluated or shells are spawned from code. Check what feeds them.",
    re: /\beval\s*\(|\bnew\s+Function\s*\(|\b__import__\s*\(|\bimportlib\.import_module\b|\bos\.system\s*\(|\bsubprocess\.\w+\([^\n]*shell\s*=\s*True|\bRuntime\.getRuntime\(\)\.exec|\bchild_process\b[^\n]*\bexec(?:Sync)?\s*\(/i },
  { id: "risk.download_exec", title: "Download and run", severity: "high", explanation: "The skill fetches a file or script and executes it in the same step.",
    re: /\b(?:curl|wget)\b[^\n]*(?:\s-o\s|\s-O\b|--output\b)[^\n]*(?:&&|;)\s*(?:chmod\s+\+x|(?:ba|z)?sh\b|python3?\b|node\b|\.\/)|\bcurl\b[^\n]*\|\s*(?:sudo\s+)?(?:python3?|node|ruby|perl)\b|\b(?:iwr|Invoke-WebRequest)\b[^\n]*\|\s*(?:iex|Invoke-Expression)\b|\bDownloadString\s*\(|\b(?:iex|Invoke-Expression)\b[^\n]*\b(?:iwr|Invoke-WebRequest|DownloadString)\b/i },
  { id: "risk.supply_chain", title: "Unpinned or non-registry install", severity: "medium", explanation: "Packages come from a git URL, a custom index, or a mutable tag instead of a reviewed registry version.",
    re: /\bpip3?\s+install\s+[^\n]*git\+|\bnpm\s+(?:i|install)\s+(?:-g\s+)?(?:github:|git\+|https?:\/\/)|\bnpx\s+(?:-y\s+)?(?:github:|https?:\/\/)|(?:--index-url|--extra-index-url|--trusted-host|--allow-unverified)\b|\bgo\s+install\s+\S+@latest\b|\bcargo\s+install\s+--git\b|\bnpm\s+config\s+set\s+registry\b|\bnpm\s+(?:i|install)\s+[^\n]*--registry\b/i },
  { id: "risk.destructive_broad", title: "Broad destructive command", severity: "high", explanation: "The command can wipe a disk, the home directory, or shared git history.",
    re: /\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:\/(?:\s|$|\*)|~\/?(?:\s|$|\*)|\$HOME\/?(?:\s|$|\*))|\bmkfs\.\w+|\bdd\s+if=[^\n]*\bof=\/dev\/|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|>\s*\/dev\/sd[a-z]|\bchmod\s+-R\s+777\s+\/(?:\s|$)|\bgit\s+push\s+[^\n]*(?:--force|\s-f\b)[^\n]*\b(?:main|master)\b/i },
];

export function scanRisky(content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);
  for (const rule of riskRules) {
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].length > 2000 || !firstInstruction(lines[i], rule.re, "command", { prev: lines[i - 1], next: lines[i + 1] })) continue;
      findings.push({ id: rule.id, title: rule.title, severity: rule.severity, explanation: rule.explanation, evidence: redact(lines[i].trim()).slice(0, 200), line: i + 1 });
      break;
    }
  }
  return findings;
}

// Pairs that are worse together than either alone (explainx escalates the same way: privilege
// escalation plus destruction is critical). "skill" combos look across the whole skill, since an
// instruction file and the script it runs are separate files. The credential/exfil pair is
// "file"-scoped: both halves are common in unrelated reference docs (an API example with curl,
// a path-traversal note mentioning /etc/passwd), so co-occurring anywhere in a big skill means
// nothing -- they only count together in one file.
const COMBOS: Array<{ scope: "skill" | "file"; all: string[]; id: string; title: string; explanation: string }> = [
  { scope: "skill", all: ["risk.privilege_escalation", "risk.destructive_broad"], id: "risk.combo.privileged_destructive", title: "Elevated privileges combined with destructive commands", explanation: "Root access plus a broad delete or overwrite can destroy the whole machine." },
  { scope: "skill", all: ["risk.privilege_escalation", "risk.download_exec"], id: "risk.combo.privileged_download_exec", title: "Downloads and runs code with elevated privileges", explanation: "Unreviewed remote code would run as root." },
  { scope: "file", all: ["risk.sensitive_files", "risk.exfil_tools"], id: "risk.combo.credential_exfil", title: "Credential files together with outbound transfer tooling", explanation: "Reading key or credential files and having a way to send data out is the shape of credential theft." },
];

export function comboFindings(perFile: Array<{ file: string; ids: Set<string> }>): Array<Finding & { file: string }> {
  const all = new Set(perFile.flatMap(f => [...f.ids]));
  const out: Array<Finding & { file: string }> = [];
  for (const c of COMBOS) {
    const hits = c.scope === "skill" ? (c.all.every(id => all.has(id)) ? ["(whole skill)"] : []) : perFile.filter(f => c.all.every(id => f.ids.has(id))).map(f => f.file);
    for (const file of hits) out.push({ id: c.id, title: c.title, severity: "critical", explanation: c.explanation, evidence: `Together: ${c.all.join(" + ")}`, file });
  }
  return out;
}
