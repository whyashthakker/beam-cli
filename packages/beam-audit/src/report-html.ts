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
  const surfaces: Surface[] = ["VS Code", "Claude Code (CLI)"];
  const columns = surfaces.map(surface => {
    const rows = matrix.cells.filter(c => c.surface === surface);
    if (rows.length === 0) return "";
    return `
    <div class="matrix-col">
      <h3>${esc(surface)}</h3>
      <table class="matrix-table">
        ${rows.map(r => `<tr><td class="m-label">${esc(r.label)}</td><td class="m-icon-cell">${matrixIcon(r)}</td><td class="m-detail">${esc(r.detail)}</td></tr>`).join("")}
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
</style>
</head>
<body>
  <h1>beam-audit report</h1>
  <p class="subtitle">Claude Code Secure Usage Policy checks &mdash; no beam-cli install required.</p>
  <p class="meta">Generated ${esc(meta.generatedAt)} &middot; ${meta.repoCount} repositories scanned under: ${meta.roots.map(esc).join(", ")} &middot; live round-trip tests: ${meta.liveTestsRun ? "ran (real API calls)" : "skipped"}</p>

  <div class="summary-grid">
    <div class="stat fail"><div class="num">${counts.fail}</div><div class="label">Failing</div></div>
    <div class="stat pass"><div class="num">${counts.pass}</div><div class="label">Passing</div></div>
    <div class="stat warn"><div class="num">${counts.warn}</div><div class="label">Warnings</div></div>
    <div class="stat skip"><div class="num">${counts.skip}</div><div class="label">Not checked</div></div>
  </div>

  ${fails.length > 0 ? `
  <div class="cta">
    <h2>${fails.length} check(s) failed on this machine</h2>
    <p>Nothing here currently stops the listed data categories from reaching a Claude Code prompt.</p>
    <p><a href="https://agentbeam.com">agentbeam.com</a> &mdash; <code>npm i -g @agent-beam/beam && beam setup</code> fixes this.</p>
  </div>` : ""}

  ${matrices.map(matrixSection).join("")}

  ${sorted.map(card).join("")}

  <footer>Generated by beam-audit. Secret/PII patterns are heuristic; verify positives before acting. Live tests use obviously-fake synthetic values only.</footer>
</body>
</html>`;
}
