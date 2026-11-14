import { CATEGORIES, categoryFor } from "./categories.js";
// Renders the same Check[] as a single self-contained HTML page.
import type { Check, Status } from "./types.js";
import type { MatrixCell, Surface } from "./checks/matrix-test.js";
import type { NamedMatrix } from "./report.js";

const STATUS_LABEL: Record<Status, string> = { fail: "FAIL", pass: "PASS", warn: "WARN", skip: "NOT CHECKED" };
const STATUS_COLOR: Record<Status, string> = { fail: "#b91c1c", pass: "#15803d", warn: "#a16207", skip: "#6b7280" };
const STATUS_ORDER: Record<Status, number> = { fail: 0, warn: 1, skip: 2, pass: 3 };

function esc(s: string): string {
  return s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

function matrixIcon(c: MatrixCell): string {
  if (c.blocked === null) return `<span class="m-icon m-skip">-</span>`;
  return c.blocked ? `<span class="m-icon m-pass">&#10003;</span>` : `<span class="m-icon m-fail">&#10007;</span>`;
}

function matrixSection(matrix: NamedMatrix): string {
  if (matrix.cells.length === 0) return "";
  const surfaces: Surface[] = [...new Set(matrix.cells.map(cell => cell.surface))];
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
          const review = matrix.title.includes("4.3");
          const outcome = review && r.actionObserved ? "EDIT OBSERVED / REVIEW UNVERIFIED" : r.blocked === null ? "INCONCLUSIVE / NOT TESTED" : review ? r.blocked ? "APPROVAL REQUEST OBSERVED" : "AUTOMATIC ACTION OBSERVED" : r.blocked ? "GUARDRAIL REPORTS BLOCK" : "SAMPLE NOT BLOCKED";
          return `${heading}<tr><td class="m-label">${esc(label)}</td><td class="m-icon-cell">${matrixIcon(r)}</td><td class="m-detail"><strong class="outcome">${outcome}</strong><br>${esc(r.detail)}${r.testId ? `<br><small>Test ID: ${esc(r.testId)}</small>` : ""}</td></tr>`;
        }).join("")}
      </table>
    </div>`;
  }).join("");
  return `
  <section class="matrix">
    <h2>${esc(matrix.title)}</h2>
    <div class="matrix-grid">${columns}</div>
  </section>`;
}

function card(c: Check): string {
  const evidence = c.evidence?.length
    ? `<ul class="evidence">${c.evidence.slice(0, 50).map(e => `<li>${esc(e)}</li>`).join("")}</ul>`
    : "";
  const fix = c.fix ? `<p class="fix"><strong>Fix:</strong> ${esc(c.fix)}</p>` : "";
  return `
  <div class="card status-${c.status}">
    <div class="card-head">
      <span class="badge" style="background:${STATUS_COLOR[c.status]}">${STATUS_LABEL[c.status]}</span>
      <span class="policy">policy ${esc(c.policySection)}</span>
      <h3>${esc(c.title)}</h3>
    </div>
    <p class="detail">${esc(c.detail)}</p>
    ${evidence}
    ${fix}
  </div>`;
}

export function renderHtmlReport(checks: Check[], matrices: NamedMatrix[], meta: { roots: string[]; repoCount: number; generatedAt: string; liveTestsRun: boolean }): string {
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
    const state = failed ? "FAIL" : warnings ? "REVIEW" : skipped || !items.length ? "PARTIAL" : "PASS";
    return `<a class="category-tile ${failed ? "tile-fail" : warnings ? "tile-warn" : skipped ? "tile-skip" : "tile-pass"}" href="#${categoryId(name)}"><strong>${esc(name)}</strong><span>${state} · ${failed} fail · ${warnings} review · ${passing} pass · ${skipped} not checked</span></a>`;
  }).join("");
  const categorySections = [...categories].map(([name, items]) => `<section class="category-section" id="${categoryId(name)}"><div class="category-heading"><div><p class="eyebrow">AUDIT CATEGORY</p><h2>${esc(name)}</h2></div><span class="category-count">${items.length} checks</span></div>${items.map(card).join("")}</section>`).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>beam-audit report</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 920px; margin: 0 auto; padding: 32px 20px 80px; background: #0b0d12; color: #e6e8eb; line-height: 1.55; }
  h1 { font-size: 1.55rem; margin-bottom: 2px; }
  .subtitle { color: #9aa1ab; margin-top: 0; }
  .meta { font-size: 0.82rem; color: #8b929c; margin-bottom: 22px; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 22px 0 28px; }
  .stat { background: #141821; border: 1px solid #262c38; border-radius: 10px; padding: 14px; text-align: center; }
  .stat .num { font-size: 1.7rem; font-weight: 700; }
  .stat.fail .num { color: #ef4444; }
  .stat.pass .num { color: #22c55e; }
  .stat.warn .num { color: #eab308; }
  .stat.skip .num { color: #9ca3af; }
  .stat .label { font-size: 0.72rem; color: #9aa1ab; text-transform: uppercase; letter-spacing: 0.04em; }
  .cta { background: #1a1210; border: 1px solid #5c2a1a; border-radius: 10px; padding: 16px 18px; margin-bottom: 28px; }
  .coverage-note { background:#171c26; border:1px solid #30394a; border-radius:10px; padding:14px 18px; color:#cbd2db; margin:18px 0 24px; }
  .overview-title { font-size:1.2rem; margin:28px 0 12px; }
  .category-overview { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
  .category-tile { display:flex; flex-direction:column; gap:5px; padding:14px 16px; border:1px solid #30394a; border-radius:10px; background:#141821; color:#e6e8eb; text-decoration:none; }
  .category-tile:hover { border-color:#75839a; }
  .category-tile span { color:#9aa1ab; font-size:.78rem; }
  .tile-fail { border-left:4px solid #b91c1c; } .tile-warn { border-left:4px solid #a16207; } .tile-skip { border-left:4px solid #4b5563; } .tile-pass { border-left:4px solid #15803d; }
  .category-section { margin:34px 0; scroll-margin-top:20px; }
  .category-heading { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #30394a; padding-bottom:8px; }
  .category-heading h2 { margin:0 0 8px; font-size:1.2rem; }
  .eyebrow { color:#8b929c; font-size:.68rem; letter-spacing:.12em; margin:0 0 4px; }
  .category-count { color:#9aa1ab; font-size:.8rem; }
  .agent-matrix-title { margin-top:36px; }
  @media (max-width:640px) { .category-overview { grid-template-columns:1fr; } }
  .cta h2 { margin: 0 0 8px; font-size: 1.02rem; color: #f87171; }
  .cta p { margin: 4px 0; }
  .cta a { color: #93c5fd; }
  .card { background: #141821; border: 1px solid #262c38; border-radius: 10px; padding: 16px 18px; margin: 12px 0; }
  .card.status-fail { border-left: 4px solid #b91c1c; }
  .card.status-pass { border-left: 4px solid #15803d; }
  .card.status-warn { border-left: 4px solid #a16207; }
  .card.status-skip { border-left: 4px solid #4b5563; }
  .card-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .card-head h3 { margin: 4px 0; font-size: 1rem; flex-basis: 100%; }
  .badge { color: white; font-size: 0.68rem; font-weight: 700; padding: 2px 9px; border-radius: 999px; letter-spacing: 0.03em; }
  .policy { font-size: 0.75rem; color: #8b929c; }
  .detail { margin: 8px 0; }
  .evidence { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.78rem; background: #0b0d12; border-radius: 8px; padding: 10px 14px; margin: 8px 0; max-height: 240px; overflow-y: auto; }
  .evidence li { margin-bottom: 4px; word-break: break-all; }
  .fix { font-size: 0.86rem; color: #bcd9ff; background: #0f1b2c; border-radius: 8px; padding: 8px 12px; }
  footer { color: #6b7280; font-size: 0.74rem; margin-top: 36px; border-top: 1px solid #262c38; padding-top: 14px; }
  .matrix { margin-bottom: 32px; }
  .matrix h2 { font-size: 1.1rem; border-bottom: 1px solid #262c38; padding-bottom: 6px; }
  .matrix-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 14px; }
  @media (max-width: 640px) { .matrix-grid { grid-template-columns: 1fr; } }
  .matrix-col { background: #141821; border: 1px solid #262c38; border-radius: 10px; padding: 14px 16px; }
  .matrix-col h3 { margin: 0 0 10px; font-size: 0.95rem; }
  .matrix-table { width: 100%; border-collapse: collapse; }
  .matrix-table td { padding: 6px 0; border-top: 1px solid #1c212c; font-size: 0.88rem; }
  .matrix-table tr:first-child td { border-top: none; }
  .m-label { width: 90px; color: #cbd2db; font-weight: 600; }
  .m-icon-cell { width: 28px; }
  .m-icon { display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }
  .m-pass { background: #15803d; color: white; }
  .m-fail { background: #b91c1c; color: white; }
  .m-skip { background: #4b5563; color: white; }
  .m-detail { color: #9aa1ab; }
  .outcome { color: #d5dce6; font-size: .72rem; }
  .data-group th { padding:16px 0 7px; text-align:left; color:#e6e8eb; font-size:.9rem; border-bottom:1px solid #30394a; }
</style>
</head>
<body>
  <h1>beam-audit report</h1>
  <p class="subtitle">Developer workstation and AI agent security audit. Results are grouped by category with evidence and verification limits.</p>
  <p class="meta">Generated ${esc(meta.generatedAt)} &middot; ${meta.repoCount} repositories scanned under: ${meta.roots.map(esc).join(", ")} &middot; live round-trip tests: ${meta.liveTestsRun ? "requested (see test outcomes for completion)" : "skipped"}</p>

  <div class="summary-grid">
    <div class="stat fail"><div class="num">${counts.fail}</div><div class="label">Failing</div></div>
    <div class="stat pass"><div class="num">${counts.pass}</div><div class="label">Passing</div></div>
    <div class="stat warn"><div class="num">${counts.warn}</div><div class="label">Warnings</div></div>
    <div class="stat skip"><div class="num">${counts.skip}</div><div class="label">Not checked</div></div>
  </div>

  <div class="coverage-note"><strong>Read this report carefully:</strong> PASS means the specific check found acceptable evidence. NOT CHECKED means evidence was unavailable. A category with skipped checks is partial; this report does not certify the entire PC.</div>
  ${fails.length > 0 ? `<div class="cta"><h2>${fails.length} checks failed</h2><p>Open each category below to see the finding, evidence, and suggested fix.</p></div>` : ""}
  <h2 class="overview-title">Category overview</h2>
  <nav class="category-overview" aria-label="Audit category overview">${categoryOverview}</nav>
  ${matrices.length ? `<h2 class="agent-matrix-title">Live agent data blocking tests</h2><p class="coverage-note">Samples are fictitious. An echoed sample establishes observed behavior for that sample; an omitted response or model refusal does not establish a block. Synthetic fixtures may be allowed by policy. Guardrail UI reports are not independent network interception proof.</p>${matrices.map(matrixSection).join("")}` : `<div class="coverage-note"><strong>Live agent tests were skipped.</strong> The category results below are based on local configuration and file checks only.</div>`}
  ${categorySections}

  <footer>Generated by beam-audit. Secret/PII patterns are heuristic; verify positives before acting. Live tests use obviously-fake synthetic values only.</footer>
</body>
</html>`;
}
