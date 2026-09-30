import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { comboFindings, scanRisky } from "./skill-risk-rules.js";
import { firstInstruction } from "./skill-context.js";
import { detect, redact, risk, scanText, severityRank, type Finding, type Severity } from "./core.js";

// Prompt-injection rules for skill content only. Kept out of core.ts's builtinRules on purpose:
// those also run against live agent events (commands, file paths), where phrases like "you are
// now" are ordinary text, not an attack. A skill is instructions the agent will obey, so it gets
// the stricter set.
type InjectionRule = { id: string; title: string; severity: Severity; explanation: string; match?: (s: string) => boolean; re?: RegExp; /** false: invisible characters and the like have no "quoted example" reading */ context?: boolean };
const ruleMatches = (rule: InjectionRule, text: string) => rule.re ? new RegExp(rule.re.source, rule.re.flags.replace("g", "")).test(text) : Boolean(rule.match?.(text));
const injectionRules: InjectionRule[] = [
  { id: "injection.role_override", title: "Role or system-prompt override", severity: "critical", explanation: "The skill tells the agent to drop its existing instructions or adopt a new identity.", re: /\b(?:ignore|disregard)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:system\s+)?(?:instructions|prompts?|rules|messages)\b|\b(?:disregard|forget|override|bypass)\s+(?:all\s+|any\s+)?(?:your|the|previous|prior|above)\s+(?:system\s+)?(?:prompt|instructions|rules|guidelines|safeguards)\b|\bforget\s+everything\s+(?:above|before)\b|\byou\s+are\s+now\s+(?:in\s+)?(?:DAN|developer\s+mode|an?\s+unrestricted)\b/i },
  { id: "injection.fake_delimiter", title: "Forged conversation or system delimiter", severity: "critical", explanation: "Chat-template or 'end of skill' markers are used to make the following text look like a higher-trust message.", re: /<\|(?:im_start|im_end|system|endoftext)\|>|<\/?system(?:-reminder)?>|\[\/?INST\]|---\s*END\s+(?:OF\s+)?SKILL\s*---|\bBEGIN\s+SYSTEM\s+PROMPT\b/i },
  { id: "injection.concealment", title: "Instruction to hide activity from the user", severity: "high", explanation: "The skill asks the agent to act without telling the user or to hide what it did.", re: /(?:without|don'?t|do\s+not|never)\s+(?:telling|tell|mention(?:ing)?|inform(?:ing)?|reveal(?:ing)?|show(?:ing)?)\s+(?:the\s+)?(?:user|human|operator)\b(?!\s+to\b)|\b(?:silently|secretly|covertly)\s+(?:run|execute|send|upload|post|fetch|install|delete|modify)\b|hide\s+(?:this|these|the)\s+(?:step|action|output|command)s?\s+from/i },
  { id: "injection.priority_hijack", title: "Attempt to outrank the user or system", severity: "high", explanation: "The skill claims its instructions take precedence over the user's or the platform's.", re: /\b(?:these|this)\s+instructions?\s+(?:take|has|have)\s+(?:priority|precedence)\s+over|\bbefore\s+(?:doing\s+)?anything\s+else,?\s+(?:you\s+must\s+)?(?:(?:fetch|send|curl|wget|download|upload)\b|(?:run|execute)\s+[`"']?(?:curl|wget|nc|ncat|bash|sh|eval|powershell)\b)/i },
  { id: "injection.hidden_text", context: false, title: "Hidden or invisible text", severity: "high", explanation: "Zero-width, bidirectional-control, or Unicode tag characters can smuggle instructions a human reviewer never sees.", re: /[​-‏‪-‮⁠-⁤﻿]|[\u{E0000}-\u{E007F}]/u },
  { id: "injection.hidden_comment", title: "Instructions inside an HTML comment", severity: "high", explanation: "HTML comments are invisible when a skill is rendered but are still read by the agent.", re: /(?:ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above)|\byou\s+(?:must|should|will)\b|(?:new|hidden|secret)\s+instructions?|system\s+prompt|do\s+not\s+(?:tell|mention|reveal)|\b(?:curl|wget)\s+\S+|\bsend\s+(?:it|this|the\s+\w+)\s+to\b|exfiltrat\w+|\bassistant\s*:)/i },
  { id: "injection.encoded_payload", title: "Encoded payload with a follow-instruction", severity: "high", explanation: "A base64 or hex blob is paired with a request to decode and act on it.", match: s => /(?:[A-Za-z0-9+/]{80,}={0,2})/.test(s) && /\b(?:decode|decrypt|deobfuscate)\b[^\n]{0,60}\b(?:and\s+)?(?:follow|run|execute|obey|apply)\b/i.test(s) },
  { id: "injection.exfil_instruction", title: "Instruction to send data to an external address", severity: "critical", explanation: "The skill directs the agent to transmit conversation, files, or environment to a remote URL.", re: /\b(?:send|post|upload|forward|include|append)\b[^\n]{0,80}\b(?:conversation|chat\s+history|system\s+prompt|context|transcript|environment|env\s+vars?|credentials?|api\s+keys?|source\s+code)\b[^\n]{0,80}https?:\/\//i },
];

// 0-100. Prompt injection is weighted up because a skill is text the agent will obey, and one
// critical finding alone is already enough to land in HIGH.
const WEIGHT: Record<Severity, number> = { critical: 40, high: 20, medium: 8, info: 2 };
export function skillRiskScore(findings: Finding[]): { score: number; level: SkillScan["level"] } {
  // Each rule counts once per skill (a big skill repeating "production" across 30 files is one
  // signal, not thirty). Ordinary rules that merely *mention* env vars, sudo or curl are common in
  // legitimate skills, so their non-critical total is capped below the HIGH band; reaching HIGH or
  // CRITICAL takes prompt injection or a genuinely critical pattern.
  const unique = [...new Map(findings.map(f => [f.id, f])).values()];
  const injection = unique.filter(f => f.id.startsWith("injection.")).reduce((s, f) => s + WEIGHT[f.severity] * 1.5, 0);
  const critical = unique.filter(f => !f.id.startsWith("injection.") && f.severity === "critical").length * WEIGHT.critical;
  const ordinary = Math.min(35, unique.filter(f => !f.id.startsWith("injection.") && f.severity !== "critical").reduce((s, f) => s + WEIGHT[f.severity] / (f.id.startsWith("risk.") ? 1 : 2), 0));
  const score = Math.min(100, Math.round(injection + critical + ordinary));
  return { score, level: score >= 70 ? "CRITICAL" : score >= 40 ? "HIGH" : score >= 15 ? "MEDIUM" : "LOW" };
}

// Core rules that don't fit skill prose. `instructions.override` is the older, context-blind version
// of injection.role_override / injection.concealment, which already cover it with quoting and
// negation handled. `mcp.write` matches tool identifiers such as mcp__memory__memory_write, which
// in live events means "the agent is calling a write tool", but in a skill is a documentation
// mention of a tool by name.
const SKIP_CORE_FOR_SKILLS = new Set(["instructions.override", "mcp.write"]);

const TEXT_EXT = /\.(?:md|mdx|txt|json|ya?ml|toml|sh|bash|zsh|py|js|mjs|cjs|ts|rb|ps1)$/i;
const SKIP_DIR = new Set([".git", "node_modules", ".venv", "__pycache__"]);
const MAX_FILES = 200;
const MAX_FILE_BYTES = 500_000;

export interface SkillFileScan { file: string; findings: Finding[] }
export interface SkillScan { name: string; dir: string; hash: string; score: number; level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; risk: Severity; files: SkillFileScan[]; findings: Array<Finding & { file: string }>; filesScanned: number; skipped: string[] }

async function listFiles(root: string, dir = root, out: string[] = []): Promise<string[]> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (out.length >= MAX_FILES) break;
    if (entry.isSymbolicLink() || SKIP_DIR.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await listFiles(root, full, out);
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

// A finding's identity for review purposes: the rule, the file inside the skill, and the text of
// the line -- but not the line number, so a "safe" verdict survives the line moving when the skill
// is edited elsewhere, and stops applying the moment the flagged text itself changes. Computed on
// the device (where the full text is) and never reversible to the line.
export function findingFingerprint(f: Pick<Finding, "id" | "evidence">, file: string): string {
  const text = redact(f.evidence ?? "").replace(/\s+/g, " ").trim().toLowerCase().slice(0, 300);
  return createHash("sha256").update(`${f.id}|${file}|${text}`).digest("hex").slice(0, 16);
}

const lineOf = (content: string, index: number) => content.slice(0, index).split("\n").length;
const snippet = (text: string) => redact(text.trim().replace(/\s+/g, " ")).slice(0, 200);

export function scanInjection(content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);
  const add = (rule: InjectionRule, evidence: string, line: number) =>
    findings.push({ id: rule.id, title: rule.title, severity: rule.severity, explanation: rule.explanation, evidence, line });
  for (const rule of injectionRules) {
    // These two span lines, so they are matched against the whole file -- but each still points at
    // the line and text that triggered it, since that is what a reviewer needs to see.
    if (rule.id === "injection.hidden_comment") {
      for (const block of content.matchAll(/<!--[\s\S]*?-->/g)) {
        if (ruleMatches(rule, block[0])) { add(rule, snippet(block[0]), lineOf(content, block.index ?? 0)); break; }
      }
      continue;
    }
    if (rule.id === "injection.encoded_payload") {
      if (!ruleMatches(rule, content)) continue;
      const at = lines.findIndex(l => /\b(?:decode|decrypt|deobfuscate)\b[^\n]{0,60}\b(?:and\s+)?(?:follow|run|execute|obey|apply)\b/i.test(l));
      add(rule, at >= 0 ? snippet(lines[at]) : "Long encoded string with a decode-and-run instruction", at >= 0 ? at + 1 : 1);
      continue;
    }
    for (let i = 0; i < lines.length; i++) {
      // A phrase that is only being quoted, refused, or given as an example is not an instruction.
      const hit = rule.re && rule.context !== false ? firstInstruction(lines[i], rule.re, "phrase", { prev: lines[i - 1], next: lines[i + 1] }) : ruleMatches(rule, lines[i]) ? { index: 0 } : null;
      if (hit) { add(rule, snippet(lines[i]), i + 1); break; }
    }
  }
  return findings;
}

// scanText looks at three-line windows (so a credential on one line and a "send it to" on the next
// are seen together) and reports the window's first line. For a reviewer that is misleading: the
// risky text can be two lines further down. When the rule matches a single line on its own, point
// at that line and show only it; when it needs the lines together, keep the window.
function narrowToLine(finding: Finding, content: string): Finding {
  if (!finding.line) return finding;
  const lines = content.split(/\r?\n/);
  for (let k = 0; k < 3; k++) {
    const text = lines[finding.line - 1 + k];
    if (text !== undefined && detect(text).some(f => f.id === finding.id)) return { ...finding, line: finding.line + k, evidence: snippet(text) };
  }
  return { ...finding, evidence: snippet(finding.evidence) };
}

// Scans every text file in a skill folder -- not just SKILL.md, since bundled scripts and
// reference docs are loaded or executed by the agent too. Never executes anything.
export async function scanSkillDir(dir: string, name: string): Promise<SkillScan> {
  return scanPaths(dir, name, await listFiles(dir));
}

// One markdown file on its own (a stray skills.md), without sweeping its whole parent folder.
export async function scanSkillFile(file: string): Promise<SkillScan> {
  return scanPaths(join(file, ".."), basename(file), [file]);
}

async function scanPaths(dir: string, name: string, paths: string[]): Promise<SkillScan> {
  const skipped: string[] = [];
  const files: SkillFileScan[] = [];
  const hash = createHash("sha256");
  for (const path of paths) {
    const rel = relative(dir, path);
    if (!TEXT_EXT.test(path)) continue;
    if ((await stat(path)).size > MAX_FILE_BYTES) { skipped.push(`${rel} (over 500 KB)`); continue; }
    const content = await readFile(path, "utf8");
    if (!content.trim()) continue;
    hash.update(`${rel}\0${content}\0`);
    const findings = [...scanInjection(content), ...scanRisky(content)];
    try { for (const f of scanText(rel, content, "skill").findings) if (!SKIP_CORE_FOR_SKILLS.has(f.id) && !findings.some(x => x.id === f.id)) findings.push(narrowToLine(f, content)); }
    catch { /* over the scanText size cap; injection rules above still ran */ }
    files.push({ file: rel, findings });
  }
  const fileFindings = files.flatMap(f => f.findings.map(x => ({ ...x, file: f.file })));
  // Combinations (e.g. sudo in one file, a broad rm in another) are judged over the whole skill or per file, see skill-risk-rules.ts.
  const combos = comboFindings(files.map(f => ({ file: f.file, ids: new Set(f.findings.map(x => x.id)) })));
  const findings = [...fileFindings, ...combos]
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
  return { name, dir, hash: hash.digest("hex"), ...skillRiskScore(findings), risk: risk(findings), files, findings, filesScanned: files.length, skipped };
}
