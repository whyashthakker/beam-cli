import { CATEGORIES, categoryFor } from "./categories.js";
// Renders the same Check[] as a single self-contained HTML page, styled to match Beam's web
// dashboard design tokens (packages/tailwind-config/tokens.css in the beam monorepo) so this
// looks like part of the same product instead of a disconnected ad hoc report.
import type { Check, Status } from "./types.js";
import type { MatrixCell, Surface } from "./checks/matrix-test.js";
import type { NamedMatrix } from "./report.js";

const STATUS_LABEL: Record<Status, string> = { fail: "Fail", pass: "Pass", warn: "Warn", skip: "Not checkable" };
const STATUS_TOKEN: Record<Status, string> = { fail: "danger", pass: "success", warn: "warning", skip: "muted" };
const STATUS_ORDER: Record<Status, number> = { fail: 0, warn: 1, skip: 2, pass: 3 };

// A 0-100 security score per check (higher = safer), shown alongside the pass/fail badge so a
// question's items can be ranked and averaged the same way the skill-risk engine already scores
// skills. Checks that embed their own finer-grained "risk score NN/100 (LEVEL)" (skills, MCP tool
// introspection) are inverted into a security score instead of collapsing to a flat per-status
// value, so a skill at 2/100 safety reads very differently from one at 95/100 even though both
// might be a plain "warn". Checks with no finer signal fall back to a flat per-status score. `skip`
// has no score (nothing was verified) and is excluded from question averages rather than counted
// as a bad or neutral result.
function securityScore(c: Check): number | null {
  const m = /risk score (\d+)\/100/i.exec(c.detail);
  if (m) return Math.max(0, Math.min(100, 100 - Number(m[1])));
  if (c.status === "skip") return null;
  return { fail: 10, warn: 55, pass: 95 }[c.status];
}
function scoreLabel(score: number): string {
  return score >= 80 ? "Secure" : score >= 40 ? "Review" : "Not secure";
}
function scoreToken(score: number): string {
  return score >= 80 ? "success" : score >= 40 ? "warning" : "danger";
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

/** Dot + label status badge -- the same visual language as the dashboard's CheckStatusBadge. */
function badge(token: string, label: string, pill = false): string {
  return pill
    ? `<span class="badge badge-pill" data-tone="${token}"><span class="dot"></span>${esc(label)}</span>`
    : `<span class="badge" data-tone="${token}"><span class="dot"></span>${esc(label)}</span>`;
}

function matrixOutcome(r: MatrixCell, review: boolean): { token: string; label: string } {
  if (review && r.actionObserved) return { token: "warning", label: "Edit observed / review unverified" };
  if (r.blocked === null) return { token: "muted", label: "Not tested" };
  if (review) return r.blocked ? { token: "success", label: "Approval required" } : { token: "danger", label: "Ran with no approval" };
  return r.blocked ? { token: "success", label: "Blocked" } : { token: "danger", label: "Not blocked" };
}

function matrixSection(matrix: NamedMatrix): string {
  if (matrix.cells.length === 0) return "";
  const surfaces: Surface[] = [...new Set(matrix.cells.map(cell => cell.surface))];
  const review = matrix.title.includes("4.3");
  const columns = surfaces.map(surface => {
    const rows = matrix.cells.filter(c => c.surface === surface);
    if (rows.length === 0) return "";
    return `
    <div class="matrix-col">
      <h3>${esc(surface)}</h3>
      <table class="matrix-table">
        ${rows.map((r, i) => {
          const group = r.dataCategory ?? (r.label.includes(" / ") ? r.label.split(" / ")[0] : undefined);
          const previous = i ? rows[i-1]!.dataCategory ?? rows[i-1]!.label.split(" / ")[0] : undefined;
          const heading = group && group !== previous ? `<tr class="data-group"><th colspan="3">${esc(group)}</th></tr>` : "";
          const label = group && r.label.includes(" / ") ? r.label.slice(r.label.indexOf(" / ") + 3) : r.label;
          const outcome = matrixOutcome(r, review);
          return `${heading}<tr><td class="m-label">${esc(label)}</td><td class="m-detail">${badge(outcome.token, outcome.label)}<p>${esc(r.detail)}</p>${r.testId ? `<p class="m-testid">Test ID: ${esc(r.testId)}</p>` : ""}</td></tr>`;
        }).join("")}
      </table>
    </div>`;
  }).join("");
  return `
  <section class="panel matrix">
    <div class="panel-title"><h2>${esc(matrix.title)}</h2></div>
    <div class="panel-body"><div class="matrix-grid">${columns}</div></div>
  </section>`;
}

// Question-based drill-down, scoped to "AI agent discovery and configuration" first. Each question
// pulls matching checks by id pattern from the FULL check list (not just this category's checkFor()
// bucket), since the user's real questions ("how many MCP tools", "are Skills consistent") cut across
// categories as currently defined. Checks are claimed by the first matching question so counts don't
// double up within this view; the normal flat category-by-category rendering below is unaffected and
// still shows every check under its categoryFor() home.
export interface AgentQuestion { id: string; question: string; match: (c: Check) => boolean; }
export const AGENT_DISCOVERY_QUESTIONS: AgentQuestion[] = [
  { id: "q-agents-detected", question: "Which AI agents were detected, and where (CLI config vs. editor extension)?", match: c => /^(inventory-|editor-configuration-|extension-inventory-)/.test(c.id) },
  { id: "q-official-client", question: "Are the detected agents official, or could they be unofficial/forked clients?", match: c => c.id.startsWith("3.5-unofficial-client") },
  { id: "q-mcp-count-safety", question: "How many MCP servers are configured, and are they structurally safe (pinned, approved origin, no auto-trust)?", match: c => c.id.startsWith("mcp-") && !c.id.startsWith("mcp-tools-") && c.id !== "mcp-tool-introspection" },
  { id: "q-mcp-tools", question: "What tools does each MCP server expose -- how many are write-mode, and could any read tool reach customer/PII data?", match: c => c.id.startsWith("mcp-tools-") || c.id === "mcp-tool-introspection" },
  { id: "q-skills", question: "How many Skills exist per agent, are same-named Skills consistent across agents, and is there prompt-injection-shaped content?", match: c => c.id.startsWith("skill-") },
  // Explicit allowlist: a substring match on "approval" also caught "9-approval-signoff" (an
  // unrelated manual paperwork item for policy 9's human sign-off) and would have caught
  // "agent-auth-permissions-*"/"log-permissions-*" (credential-cache ACL / logging checks) too.
  { id: "q-auto-approve", question: "Is auto-edit / automatic approval (bypassing manual review) enabled anywhere?", match: c => c.id.startsWith("agent-approval-") || c.id.startsWith("agent-file-resolution-") || c.id.startsWith("permissions-") || c.id === "codex-managed-constraints" },
  // Explicit allowlist, not /hook/i: that regex also matched git pre-commit hook checks
  // (6.2-precommit-hook, effective-hook-*, hook-bypass-environment) -- an unrelated repo-hygiene
  // feature that happens to share the word "hook" with Claude Code's own PreToolUse/UserPromptSubmit
  // agent hooks. Mixing them in dragged this question's score down for the wrong reason entirely.
  { id: "q-hooks", question: "Are there config-level hooks that monitor or enforce actions, and do any call out to the network?", match: c => c.id.startsWith("agent-required-prompt-hooks-") || c.id.startsWith("agent-hooks-disabled-") || c.id.startsWith("agent-prompt-hooks-") || c.id.startsWith("agent-hook-network-") || c.id === "global-hook-present" || c.id === "repo-settings-override-no-hook" },
  { id: "q-memory", question: "Is persistent cross-session memory on or off, and does its content contain anything sensitive?", match: c => /memory/i.test(c.id) },
  { id: "q-sandbox", question: 'Can the agent run unrestricted ("mindless") shell/network commands -- sandbox disabled, wildcard tool grants, network access allowed?', match: c => /sandbox|extra-roots|network-environment/i.test(c.id) },
];

export function matchesAgentDiscoveryQuestion(c: Check): boolean {
  return AGENT_DISCOVERY_QUESTIONS.some(q => q.match(c));
}

function questionBlock(q: AgentQuestion, items: Check[], meta: ReportMeta): string {
  const counts = { pass: 0, fail: 0, warn: 0, skip: 0 };
  for (const c of items) counts[c.status]++;
  const scores = items.map(securityScore).filter((s): s is number => s !== null);
  const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
  const avgBadge = avg !== null ? badge(scoreToken(avg), `${avg}/100 avg · ${scoreLabel(avg)}`, true) : badge("muted", "No score (all not checked)", true);
  const overview = items.length ? `${items.length} checks · ${counts.fail} fail · ${counts.warn} review · ${counts.pass} pass · ${counts.skip} not checked` : "No matching checks run.";
  return `
  <details class="question-block">
    <summary><strong>${esc(q.question)}</strong>${avgBadge}<span class="q-overview">${overview}</span></summary>
    <div class="question-detail">
      <p class="device-meta">Host: ${esc(meta.hostname ?? "unknown")} &middot; User: ${esc(meta.username ?? "unknown")} &middot; Platform: ${esc(meta.platform ?? "unknown")} &middot; Home: ${esc(meta.home ?? "unknown")}</p>
      ${items.length ? items.map(c => card(c, { showScore: true })).join("") : `<p class="detail">No checks in this scan matched this question's evidence pattern.</p>`}
    </div>
  </details>`;
}

function agentDiscoveryQuestionSection(allChecks: Check[], meta: ReportMeta): string {
  const claimed = new Set<Check>();
  const blocks = AGENT_DISCOVERY_QUESTIONS.map(q => {
    const items = allChecks.filter(c => !claimed.has(c) && q.match(c));
    for (const c of items) claimed.add(c);
    return questionBlock(q, items, meta);
  }).join("");
  return `<div class="question-list">${blocks}</div>`;
}

function card(c: Check, options: { showScore?: boolean } = {}): string {
  const evidence = c.evidence?.length
    ? `<ul class="evidence">${c.evidence.slice(0, 50).map(e => `<li>${esc(e)}</li>`).join("")}</ul>`
    : "";
  const fix = c.fix ? `<p class="fix"><strong>Fix</strong> ${esc(c.fix)}</p>` : "";
  const score = options.showScore ? securityScore(c) : null;
  const scoreBadge = score !== null ? badge(scoreToken(score), `${score}/100 · ${scoreLabel(score)}`, true) : "";
  const why = options.showScore
    ? `<details class="check-why"><summary>Why</summary><p class="detail">${esc(c.detail)}</p>${evidence}${fix}</details>`
    : `<p class="detail">${esc(c.detail)}</p>${evidence}${fix}`;
  return `
  <div class="check-row">
    <div class="check-head">
      ${badge(STATUS_TOKEN[c.status], STATUS_LABEL[c.status])}
      ${scoreBadge}
      <h3>${esc(c.title)}</h3>
      <span class="policy">policy ${esc(c.policySection)}</span>
    </div>
    ${why}
  </div>`;
}

export interface ReportMeta { roots: string[]; repoCount: number; generatedAt: string; liveTestsRun: boolean; hostname?: string; username?: string; platform?: string; home?: string; }
export function renderHtmlReport(checks: Check[], matrices: NamedMatrix[], meta: ReportMeta): string {
  const sorted = [...checks].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);
  const counts = { fail: 0, pass: 0, warn: 0, skip: 0 };
  for (const c of checks) counts[c.status]++;
  const fails = sorted.filter(c => c.status === "fail");
  const categories = new Map<string, Check[]>(CATEGORIES.map(name => [name, []]));
  for (const c of checks) { const name = categoryFor(c); categories.set(name, [...(categories.get(name) ?? []), c]); }
  const categoryId = (name: string) => `category-${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
  const categoryOverview = [...categories].map(([name, items]) => {
    const failed = items.filter(c => c.status === "fail").length;
    const warnings = items.filter(c => c.status === "warn").length;
    const passing = items.filter(c => c.status === "pass").length;
    const skipped = items.filter(c => c.status === "skip").length;
    const token = failed ? "danger" : warnings ? "warning" : skipped || !items.length ? "muted" : "success";
    const state = failed ? "Needs attention" : warnings ? "Review" : skipped || !items.length ? "Partial" : "Clean";
    return `<a class="tile" data-tone="${token}" href="#${categoryId(name)}">
      <div class="tile-head"><strong>${esc(name)}</strong>${badge(token, state, true)}</div>
      <span class="tile-counts">${failed} fail · ${warnings} review · ${passing} pass · ${skipped} not checked</span>
    </a>`;
  }).join("");
  const categorySections = [...categories].map(([name, items]) => {
    const questionSection = name === "AI agent discovery and configuration"
      ? `<p class="eyebrow" style="margin-top:4px">Breakdown by question</p>${agentDiscoveryQuestionSection(checks, meta)}<p class="eyebrow" style="margin-top:22px">All checks in this category</p>`
      : "";
    return `<section class="panel category-section" id="${categoryId(name)}">
      <div class="panel-title"><h2>${esc(name)}</h2><span class="panel-title-meta">${items.length} checks</span></div>
      <div class="panel-body">${questionSection}<div class="check-list">${items.map(c => card(c)).join("")}</div></div>
    </section>`;
  }).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>beam-audit report</title>
<style>
  :root {
    color-scheme: light;
    --color-background: #fafaf9;
    --color-foreground: #111318;
    --color-muted: #6b6f76;
    --color-subtle: #6e7279;
    --color-surface: #ffffff;
    --color-border: #e5e5e2;
    --color-border-strong: #d6d6d2;
    --color-primary: #5d55f9;
    --color-primary-subtle: #f4f3ff;
    --color-success: #16a34a;
    --color-success-subtle: #f0fdf4;
    --color-warning: #d97706;
    --color-warning-subtle: #fffbeb;
    --color-danger: #dc2626;
    --color-danger-subtle: #fef2f2;
    --color-muted-subtle: #f1f1ef;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    max-width: 880px; margin: 0 auto; padding: 40px 20px 80px;
    background: var(--color-background); color: var(--color-foreground); line-height: 1.55;
    font-size: 13px;
  }
  a { color: var(--color-primary); }
  .eyebrow { color: var(--color-primary); text-transform: uppercase; font-size: 11px; font-weight: 600; letter-spacing: 0.1em; margin: 0 0 6px; }
  h1 { font-size: 1.6rem; font-weight: 600; letter-spacing: -0.02em; margin: 0 0 4px; }
  .subtitle { color: var(--color-muted); margin: 0; font-size: 0.95rem; }
  .meta { font-size: 12px; color: var(--color-subtle); margin: 14px 0 24px; }

  /* Status badge: dot + label, same visual language as the dashboard's CheckStatusBadge. */
  .badge { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; white-space: nowrap; }
  .badge .dot { width: 6px; height: 6px; border-radius: 999px; flex-shrink: 0; }
  .badge[data-tone="success"] { color: var(--color-success); } .badge[data-tone="success"] .dot { background: var(--color-success); }
  .badge[data-tone="warning"] { color: var(--color-warning); } .badge[data-tone="warning"] .dot { background: var(--color-warning); }
  .badge[data-tone="danger"] { color: var(--color-danger); } .badge[data-tone="danger"] .dot { background: var(--color-danger); }
  .badge[data-tone="muted"] { color: var(--color-muted); } .badge[data-tone="muted"] .dot { background: var(--color-muted); }
  .badge-pill { padding: 2px 8px 2px 7px; border-radius: 999px; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.03em; }
  .badge-pill[data-tone="success"] { background: var(--color-success-subtle); }
  .badge-pill[data-tone="warning"] { background: var(--color-warning-subtle); }
  .badge-pill[data-tone="danger"] { background: var(--color-danger-subtle); }
  .badge-pill[data-tone="muted"] { background: var(--color-muted-subtle); }

  /* Summary metrics, matching the dashboard's Metrics card grid. */
  .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0 24px; }
  @media (max-width: 640px) { .metrics { grid-template-columns: repeat(2, 1fr); } }
  .metric { border: 1px solid var(--color-border); border-radius: 8px; background: var(--color-surface); padding: 14px 16px; }
  .metric .label { font-size: 11px; color: var(--color-muted); text-transform: uppercase; letter-spacing: 0.04em; margin: 0 0 8px; }
  .metric .num { font-size: 1.9rem; font-weight: 600; letter-spacing: -0.03em; line-height: 1; }
  .metric[data-tone="danger"] .num { color: var(--color-danger); }
  .metric[data-tone="warning"] .num { color: var(--color-warning); }
  .metric[data-tone="success"] .num { color: var(--color-success); }
  .metric[data-tone="muted"] .num { color: var(--color-muted); }

  /* A generic bordered panel -- category sections, live-test matrices. */
  .panel { border: 1px solid var(--color-border); border-radius: 8px; background: var(--color-surface); overflow: hidden; margin-bottom: 20px; }
  .panel-title { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; padding: 14px 18px; background: var(--color-background); border-bottom: 1px solid var(--color-border); }
  .panel-title h2 { margin: 0; font-size: 15px; font-weight: 600; }
  .panel-title-meta { font-size: 12px; color: var(--color-subtle); white-space: nowrap; }
  .panel-body { padding: 16px 18px; }

  .note { border: 1px solid var(--color-border); background: var(--color-background); border-radius: 8px; padding: 14px 16px; color: var(--color-muted); margin: 0 0 20px; font-size: 12.5px; }
  .note strong { color: var(--color-foreground); }
  .cta { border: 1px solid color-mix(in srgb, var(--color-danger) 35%, var(--color-border)); background: var(--color-danger-subtle); border-radius: 8px; padding: 14px 18px; margin: 0 0 20px; }
  .cta h2 { margin: 0 0 4px; font-size: 14px; color: var(--color-danger); }
  .cta p { margin: 0; font-size: 12.5px; color: var(--color-foreground); }

  .overview-title { font-size: 1.05rem; font-weight: 600; margin: 32px 0 12px; }
  .category-overview { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-bottom: 8px; }
  @media (max-width: 640px) { .category-overview { grid-template-columns: 1fr; } }
  .tile { display: flex; flex-direction: column; gap: 6px; padding: 14px 16px; border: 1px solid var(--color-border); border-radius: 8px; background: var(--color-surface); text-decoration: none; color: inherit; transition: border-color 120ms ease; }
  .tile:hover { border-color: var(--color-border-strong); }
  .tile-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .tile-head strong { font-size: 13px; }
  .tile-counts { color: var(--color-subtle); font-size: 11.5px; }

  /* One check, as a row inside a category panel rather than its own floating card. */
  .check-list { display: flex; flex-direction: column; }
  .check-row { padding: 12px 0; border-top: 1px solid var(--color-border); }
  .check-row:first-child { border-top: none; padding-top: 0; }
  .check-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
  .check-head h3 { margin: 2px 0 0; font-size: 13.5px; font-weight: 600; flex-basis: 100%; order: 3; }
  .policy { font-size: 11px; color: var(--color-subtle); margin-left: auto; order: 2; }
  .detail { margin: 6px 0; color: var(--color-muted); }
  .evidence { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; background: var(--color-background); border: 1px solid var(--color-border); border-radius: 6px; padding: 8px 12px; margin: 8px 0; max-height: 220px; overflow-y: auto; }
  .evidence li { margin-bottom: 4px; word-break: break-all; color: var(--color-muted); }
  .fix { font-size: 12px; color: var(--color-primary); background: var(--color-primary-subtle); border-radius: 6px; padding: 7px 11px; }
  .fix strong { font-weight: 600; }
  .check-why { margin-top: 6px; }
  .check-why summary { cursor: pointer; color: var(--color-primary); font-size: 12px; font-weight: 500; list-style: none; }
  .check-why summary::-webkit-details-marker { display: none; }
  .check-why[open] summary { margin-bottom: 6px; }

  footer { color: var(--color-subtle); font-size: 11.5px; margin-top: 36px; border-top: 1px solid var(--color-border); padding-top: 14px; }

  /* Live-test matrices. */
  .matrix-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 640px) { .matrix-grid { grid-template-columns: 1fr; } }
  .matrix-col h3 { margin: 0 0 10px; font-size: 13px; font-weight: 600; }
  .matrix-table { width: 100%; border-collapse: collapse; }
  .matrix-table td { padding: 8px 0; border-top: 1px solid var(--color-border); font-size: 12.5px; vertical-align: top; }
  .matrix-table tr:first-child td { border-top: none; }
  .m-label { width: 110px; color: var(--color-foreground); font-weight: 600; padding-right: 10px; }
  .m-detail p { margin: 4px 0 0; color: var(--color-muted); }
  .m-testid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; color: var(--color-subtle); }
  .data-group th { padding: 16px 0 7px; text-align: left; color: var(--color-foreground); font-size: 13px; font-weight: 600; border-bottom: 1px solid var(--color-border); }

  /* Question drill-down (AI agent discovery and configuration). */
  .question-list { display: flex; flex-direction: column; gap: 8px; margin: 10px 0 20px; }
  .question-block { border: 1px solid var(--color-border); border-radius: 8px; background: var(--color-background); }
  .question-block summary { cursor: pointer; padding: 12px 16px; display: flex; flex-direction: column; gap: 4px; list-style: none; }
  .question-block summary::-webkit-details-marker { display: none; }
  .question-block summary strong { font-size: 13px; }
  .question-block summary .q-overview { font-size: 11.5px; color: var(--color-subtle); }
  .question-block[open] summary { border-bottom: 1px solid var(--color-border); }
  .question-detail { padding: 10px 16px 14px; background: var(--color-surface); }
  .device-meta { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; color: var(--color-subtle); background: var(--color-background); border-radius: 6px; padding: 7px 11px; margin: 4px 0 10px; }
</style>
</head>
<body>
  <p class="eyebrow">Security audit report</p>
  <h1>beam-audit</h1>
  <p class="subtitle">Developer workstation and AI agent security audit — results grouped by category, with evidence and verification limits.</p>
  <p class="meta">Generated ${esc(meta.generatedAt)} &middot; ${meta.repoCount} repositories scanned under: ${meta.roots.map(esc).join(", ")} &middot; live round-trip tests: ${meta.liveTestsRun ? "requested (see test outcomes for completion)" : "skipped"}</p>

  <div class="metrics">
    <div class="metric" data-tone="danger"><p class="label">Failing</p><p class="num">${counts.fail}</p></div>
    <div class="metric" data-tone="success"><p class="label">Passing</p><p class="num">${counts.pass}</p></div>
    <div class="metric" data-tone="warning"><p class="label">Warnings</p><p class="num">${counts.warn}</p></div>
    <div class="metric" data-tone="muted"><p class="label">Not checked</p><p class="num">${counts.skip}</p></div>
  </div>

  <div class="note"><strong>Read this report carefully:</strong> Pass means the specific check found acceptable evidence. Not checked means evidence was unavailable. A category with skipped checks is partial; this report does not certify the entire machine.</div>
  ${fails.length > 0 ? `<div class="cta"><h2>${fails.length} checks failed</h2><p>Open each category below to see the finding, evidence, and suggested fix.</p></div>` : ""}

  <h2 class="overview-title">Category overview</h2>
  <nav class="category-overview" aria-label="Audit category overview">${categoryOverview}</nav>

  ${matrices.length ? `<h2 class="overview-title">Live agent data blocking tests</h2><div class="note">Samples are fictitious. An echoed sample establishes observed behavior for that sample; an omitted response or model refusal does not establish a block. Synthetic fixtures may be allowed by policy. Guardrail UI reports are not independent network interception proof.</div>${matrices.map(matrixSection).join("")}` : `<div class="note"><strong>Live agent tests were skipped.</strong> The category results below are based on local configuration and file checks only.</div>`}

  ${categorySections}

  <footer>Generated by beam-audit. Secret/PII patterns are heuristic; verify positives before acting. Live tests use obviously-fake synthetic values only.</footer>
</body>
</html>`;
}
