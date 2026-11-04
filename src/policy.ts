import { activityType } from "./activity.js";
import { classifyActionContext } from "./action-context.js";
import { environmentRisk } from "./access-risk.js";
import { builtinRulesById } from "./rule-catalog.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { getDataDirectory } from "./config.js";
import type { CustomDetector } from "./data-detectors.js";
import type { ApprovalPolicy } from "./approvals.js";
import { canonicalPolicyPath, canonicalPolicyPattern, policyPathTargets, type PolicyPathTarget } from "./policy-paths.js";

export type PolicyMode = "observe" | "advisory" | "enforce";
export type PolicyAction = "ALLOW" | "ASK" | "BLOCK" | "REDACT" | "AUDIT";
export interface PolicyRule { id: string; title?: string; action: PolicyAction; enforce?: true; risk?: number; eventType?: string; tool?: string; command?: string; commandLine?: string; commandRegex?: string; args?: string[]; path?: string; url?: string; role?: string; user?: string; agent?: string; cwd?: string; repository?: string; branch?: string; environment?: string; time?: { after?: string; before?: string }; reason?: string; approval?: ApprovalPolicy }
// A bare string ("integrity.tls_bypass") pauses that rule for every agent. An object with
// `agent` scopes the pause to just that agent (case-insensitive, e.g. "codex") -- other
// agents keep detecting it normally.
export interface IgnoredRule { ruleId: string; agent?: string }
export interface PolicyRules { mode: PolicyMode; blockedTools: string[]; blockedCommandPatterns: string[]; disabledAgents: string[]; rules?: PolicyRule[]; risk?: { askAt?: number; blockAt?: number }; customDetectors?: CustomDetector[]; ignoredRules?: (string | IgnoredRule)[] }
export interface PolicyBundle { version: number; rules: PolicyRules; notAfter: string | null; errors?: string[] }
const EMPTY: PolicyRules = { mode: "observe", blockedTools: [], blockedCommandPatterns: [], disabledAgents: [], rules: [], customDetectors: [], ignoredRules: [] };
export function policyPath(): string { return join(getDataDirectory(), "policy.json"); }
export function lastGoodPolicyPath(): string { return join(getDataDirectory(), "policy.last-good.json"); }

function validAction(v: unknown): v is PolicyAction { return ["ALLOW", "ASK", "BLOCK", "REDACT", "AUDIT"].includes(String(v).toUpperCase()); }
function validRule(v: unknown, index: number, errors: string[]): PolicyRule | undefined {
  if (!v || typeof v !== "object" || Array.isArray(v)) { errors.push(`rules[${index}] must be an object`); return undefined; }
  const r = v as Record<string, unknown>;
  if (typeof r.id !== "string" || !r.id.trim()) { errors.push(`rules[${index}].id is required`); return undefined; }
  if (!validAction(r.action)) { errors.push(`rules[${index}] (${r.id}) has an invalid action`); return undefined; }
  if (r.enforce !== undefined && (r.enforce !== true || String(r.action).toUpperCase() !== "BLOCK")) { errors.push(`rules[${index}] (${r.id}).enforce is only supported for explicit BLOCK rules`); return undefined; }
  if (r.eventType !== undefined && (typeof r.eventType !== "string" || !r.eventType.trim())) { errors.push(`rules[${index}] (${r.id}).eventType must be a non-empty string`); return undefined; }
  if (r.commandRegex !== undefined) {
    if (typeof r.commandRegex !== "string" || r.commandRegex.length < 3 || r.commandRegex.length > 1000) { errors.push(`rules[${index}] (${r.id}).commandRegex must be 3-1000 characters`); return undefined; }
    try { if (new RegExp(r.commandRegex, "i").test("")) { errors.push(`rules[${index}] (${r.id}).commandRegex matches every command`); return undefined; } }
    catch { errors.push(`rules[${index}] (${r.id}).commandRegex is invalid`); return undefined; }
  }
  if (r.args !== undefined && (!Array.isArray(r.args) || r.args.some(a => typeof a !== "string"))) { errors.push(`rules[${index}] (${r.id}).args must be strings`); return undefined; }
  if (r.risk !== undefined && (typeof r.risk !== "number" || r.risk < 0 || r.risk > 100)) { errors.push(`rules[${index}] (${r.id}).risk must be 0-100`); return undefined; }
  return { ...r, action: String(r.action).toUpperCase() as PolicyAction } as PolicyRule;
}
export async function readPolicy(): Promise<PolicyBundle | null> {
  const read = async (path: string): Promise<PolicyBundle> => {
    const parsed = JSON.parse(await readFile(path, "utf8")) as Partial<PolicyBundle>;
    if (!parsed.rules || typeof parsed.rules !== "object") throw new Error("missing rules");
    const errors: string[] = []; const source = parsed.rules as Partial<PolicyRules>;
    if (source.customDetectors !== undefined && (!Array.isArray(source.customDetectors) || source.customDetectors.some(d => !d || typeof d.name !== "string" || typeof d.pattern !== "string" || typeof d.replacement !== "string"))) errors.push("customDetectors must contain name, pattern, and replacement strings");
    if (source.ignoredRules !== undefined && (!Array.isArray(source.ignoredRules) || source.ignoredRules.some(e => {
      if (typeof e === "string") return !e.trim();
      if (!e || typeof e !== "object" || Array.isArray(e)) return true;
      const entry = e as unknown as Record<string, unknown>;
      return typeof entry.ruleId !== "string" || !entry.ruleId.trim() || (entry.agent !== undefined && (typeof entry.agent !== "string" || !entry.agent.trim()));
    }))) errors.push("ignoredRules must contain rule id strings, or {ruleId, agent?} objects");
    for (const detector of Array.isArray(source.customDetectors) ? source.customDetectors : []) { try { new RegExp(detector.pattern); } catch { errors.push(`Invalid custom detector pattern: ${detector.name}`); } }
    const rules = Array.isArray(source.rules) ? source.rules.map((r, i) => validRule(r, i, errors)).filter((r): r is PolicyRule => Boolean(r)) : [];
    if (source.rules !== undefined && !Array.isArray(source.rules)) errors.push("rules must be an array");
    return { version: typeof parsed.version === "number" ? parsed.version : 0, notAfter: typeof parsed.notAfter === "string" ? parsed.notAfter : null, rules: { ...EMPTY, ...source, rules }, errors };
  };
  try {
    return await read(policyPath());
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    try { return await read(lastGoodPolicyPath()); } catch {
      // A present but malformed policy with no last-known-good copy fails closed.
      return { version: 0, notAfter: null, errors: ["Policy file is malformed or unreadable; no last-known-good policy is available."], rules: { ...EMPTY, mode: "enforce" } };
    }
  }
}

export type DecisionAction = "allow" | "ask" | "block" | "redact" | "audit" | "warn" | "deny";
export interface ActionContext { eventType?: string; input?: Record<string, unknown>; agent: string; tool: string; command: string; args?: string[]; path?: string; url?: string; role?: string; user?: string; cwd?: string; repository?: string; branch?: string; environment?: string; time?: string }
export interface Decision { action: DecisionAction; reason?: string; mode: PolicyMode; policyVersion: number; policy?: string; rule?: string; approval?: ApprovalPolicy; actor?: string; role?: string; agent?: string; tool?: string; command?: string; args?: string[]; resource?: string; riskScore: number; riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; riskFactors: string[]; customDetectors?: CustomDetector[]; errors?: string[] }
const safety: Record<PolicyAction, number> = { ALLOW: 0, AUDIT: 1, REDACT: 2, ASK: 3, BLOCK: 4 };
function glob(pattern: string, value: string): boolean { const e = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "§§").replace(/\*/g, "[^/]*").replace(/§§/g, ".*").replace(/\?/g, "."); return new RegExp(`^${e}$`, "i").test(value); }
function same(a: string | undefined, b: string | undefined): boolean { return !a || (b ?? "").toLowerCase() === a.toLowerCase(); }
function riskInfo(c: ActionContext): { score: number; level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; factors: string[] } { const s = `${c.command} ${c.path ?? ""} ${c.url ?? ""}`; const factors: string[] = []; const accessContext=classifyActionContext(c.tool,{file_path:c.path},c.cwd??"",c.command,v=>v,false); const access=environmentRisk(accessContext); const routineNamed=!!access && "severity" in access && access.severity==="info" && accessContext.actions.every(a=>a.operation==="environment-lookup"); let n = 0; if (builtinRulesById(["destructive.delete"])[0]?.severityFor?.(c.command) === "medium") { n += 35; factors.push("scoped temporary test cleanup"); } else if (/\brm\s+.*-rf\s+\//i.test(s)) { n += 98; factors.push("destructive operation"); } else if (/\brm\b/i.test(s)) { n += 45; factors.push("filesystem operation"); } if (/\bsudo\b/i.test(s)) { n += 35; factors.push("privileged operation"); } if (/\b(curl|wget)\b|https?:\/\//i.test(s)) { n += 25; factors.push("external destination"); } if (/\.env|\.ssh|\.aws|private.?key|api.?key|token|secret/i.test(s)) { n += routineNamed ? 5 : 35; factors.push(routineNamed ? "scoped named environment lookup" : "sensitive data or file"); } const score = Math.min(100, n); return { score, level: score >= 90 ? "CRITICAL" : score >= 70 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW", factors }; }
function matches(r: PolicyRule, c: ActionContext & { riskScore: number; pathTargets?: PolicyPathTarget[] }): boolean {
  // r.tool supports glob wildcards (e.g. "mcp__posthog__*") so a dashboard rule can target one
  // MCP server's tools without matching every MCP call; other identity fields stay exact-match.
  if (!r.path && r.eventType && !glob(r.eventType, c.eventType ?? "")) return false;
  if (r.tool && !glob(r.tool, c.tool)) return false;
  if (!same(r.role, c.role) || !same(r.user, c.user) || !same(r.agent, c.agent) || !same(r.repository, c.repository) || !same(r.branch, c.branch) || !same(r.environment, c.environment)) return false;
  if (r.cwd && !glob(r.cwd, c.cwd ?? "")) return false;
  if (r.command && !glob(r.command, c.command.split(/\s+/)[0] ?? "")) return false;
  if (r.commandLine && !glob(r.commandLine, c.command)) return false;
  if (r.commandRegex) { try { if (!new RegExp(r.commandRegex, "i").test(c.command)) return false; } catch { return false; } }
  if (r.path) {
    const rulePath = r.path;
    const pattern = canonicalPolicyPattern(rulePath, c.cwd) ?? rulePath;
    const targets = c.pathTargets ?? (c.path ? [{ path: c.path, eventType: c.eventType ?? "" }] : []);
    if (!targets.some((target) => {
      if (r.eventType && !glob(r.eventType, target.eventType) && !glob(r.eventType, c.eventType ?? "")) return false;
      const path = canonicalPolicyPath(target.path, c.cwd) ?? target.path;
      // A subtree restriction covers both the directory itself and its contents.
      return glob(pattern, path) || (pattern.endsWith("/**") && glob(pattern.slice(0, -3), path)) || glob(rulePath, target.path);
    })) return false;
  }
  if (r.url && !glob(r.url, c.url ?? "")) return false;
  if (r.args && r.args.some((a, i) => !glob(a, c.args?.[i] ?? ""))) return false;
  if (r.risk !== undefined && c.riskScore < r.risk) return false;
  if (r.time && c.time) { const t = c.time.slice(11, 16); if (r.time.after && t < r.time.after || r.time.before && t > r.time.before) return false; }
  return true;
}
function specificity(r: PolicyRule): number { return [r.eventType, r.tool, r.command, r.commandLine, r.commandRegex, r.args?.length, r.path, r.url, r.role, r.user, r.agent, r.cwd, r.repository, r.branch, r.environment, r.time].filter(Boolean).length; }

export function evaluate(bundle: PolicyBundle | null, ctx: ActionContext): Decision {
  // Use the same classifier as Activity, including argument-dependent web tools.
  ctx = { ...ctx, eventType: ctx.eventType ?? activityType({ tool_name: ctx.tool, tool_input: ctx.input }, "tool.call") };
  const info = riskInfo(ctx); const score = info.score; const base = { mode: bundle?.rules.mode ?? "observe", policyVersion: bundle?.version ?? 0, riskScore: score, riskLevel: info.level, riskFactors: info.factors, customDetectors: bundle?.rules.customDetectors ?? [], actor: ctx.user, role: ctx.role, agent: ctx.agent, tool: ctx.tool, command: ctx.command, args: ctx.args, resource: ctx.path ?? ctx.url, errors: bundle?.errors };
  if (!bundle) return { action: "allow", ...base };
  if (bundle.errors?.length) return { action: "deny", ...base, reason: `Security policy rejected: ${bundle.errors.join("; ")}`, rule: "policy.invalid" };
  if (bundle.notAfter && Date.parse(bundle.notAfter) < Date.now()) return { action: "allow", ...base };
  const pathTargets = bundle.rules.rules?.some((r) => r.path) ? policyPathTargets(ctx) : undefined;
  // A manager can enforce a narrow mitigation without enabling unrelated policy
  // rules or risk thresholds for this member's other tools and agents.
  const mandatory = (bundle.rules.rules ?? []).filter((r) => r.enforce === true && r.action === "BLOCK" && matches(r, { ...ctx, riskScore: score, pathTargets })).sort((a, b) => specificity(b) - specificity(a))[0];
  if (mandatory) return { ...base, mode: "enforce", action: "deny", reason: mandatory.reason, policy: "local policy", rule: mandatory.id };
  const observe = bundle.rules.mode === "observe";
  // A disabled agent is a suspension, so a more specific command ALLOW must not re-enable it.
  // User-scoped bundles limit this suspension to their recipient. This is an explicit block, same
  // as a BLOCK rule below -- it takes effect in Observe mode too, same reasoning as those: Observe
  // only ever suppresses the *implicit* risk-score heuristic and ASK/REDACT rules, which need a
  // human actually watching to act on them; an explicit "block this" does not need a human to mean
  // what it says. Advisory still softens it to "ask" rather than a silent local deny.
  if (bundle.rules.disabledAgents.some(a => a.toLowerCase() === ctx.agent.toLowerCase())) {
    return { ...base, action: bundle.rules.mode === "advisory" ? "ask" : "deny", reason: `${ctx.agent} is disabled by workspace policy.`, policy: "local policy", rule: "legacy.disabled-agent" };
  }
  const candidates: Array<{ r: PolicyRule; rank: number }> = [];
  for (const r of bundle.rules.rules ?? []) if (matches(r, { ...ctx, riskScore: score, pathTargets })) candidates.push({ r, rank: specificity(r) });
  for (const tool of bundle.rules.blockedTools) { const r: PolicyRule = { id: `legacy.tool.${tool}`, tool, action: "BLOCK", reason: `The ${tool} tool is blocked by workspace policy.` }; if (matches(r, { ...ctx, riskScore: score })) candidates.push({ r, rank: 1 }); }
  for (const pattern of bundle.rules.blockedCommandPatterns) { try { if (new RegExp(pattern, "i").test(ctx.command)) candidates.push({ r: { id: `legacy.command.${pattern}`, action: "BLOCK", reason: `Command matches blocked pattern: /${pattern}/` }, rank: 1 }); } catch { /* preserve legacy fail-open behavior; structured rules are validated and reported */ } }
  const selected = candidates.sort((a, b) => b.rank - a.rank || safety[b.r.action] - safety[a.r.action])[0]?.r;
  if (observe) {
    // Pure monitoring, except an explicit BLOCK still blocks: a structured BLOCK rule, a legacy
    // blocked tool, or a blocked command pattern. ASK/REDACT rules and the risk-score heuristic
    // below need a human watching this device to act on them, so those stay silent in Observe.
    if (selected?.action === "BLOCK") return { ...base, action: "deny", reason: selected.reason, policy: "local policy", rule: selected.id };
    return { action: "allow", ...base };
  }
  const thresholds = bundle.rules.risk ?? { askAt: 30, blockAt: 70 }; let action: PolicyAction = selected?.action ?? "ALLOW";
  if (!selected && score >= (thresholds.blockAt ?? 70)) action = "BLOCK"; else if (!selected && score >= (thresholds.askAt ?? 30)) action = "ASK";
  const reason = selected?.reason ?? (action === "BLOCK" ? `Risk score ${score} exceeds the block threshold.` : action === "ASK" ? `Risk score ${score} requires approval.` : action === "REDACT" ? "Sensitive data must be transformed before this action." : undefined);
  // An explicit ASK rule is an approval gate in every non-observe policy mode. Advisory
  // changes the default posture for unmatched/risk-threshold actions, but must not downgrade
  // a manager's explicit request for approval into a stderr-only warning. A pinned-command BLOCK
  // rule (commandLine set -- exclusively what the risk panel's "Block" quick action writes, see
  // dashboard lib/policy.ts) gets the same treatment: it's a deliberate decision on one exact
  // command the UI promised would be refused outright, not a risk-threshold guess, so advisory
  // mode must not soften it into an "ask" prompt either. A broader BLOCK -- a legacy blocked
  // tool/pattern/agent, or a structured rule matched by tool/path/etc without commandLine --
  // still follows the mode's default posture, same as before.
  const mapped: DecisionAction = action === "BLOCK"
    ? (selected?.commandLine ? "deny" : bundle.rules.mode === "enforce" ? "deny" : bundle.rules.mode === "advisory" ? "ask" : "warn")
    : action.toLowerCase() as DecisionAction;
  return { ...base, action: mapped, reason, policy: "local policy", rule: selected?.id, approval: selected?.approval };
}
