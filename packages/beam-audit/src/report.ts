import type { Check, Status } from "./types.js";
import type { MatrixCell, Surface } from "./checks/matrix-test.js";

export interface NamedMatrix { title: string; cells: MatrixCell[] }

const ICON: Record<Status, string> = { pass: "✓", warn: "!", fail: "✗", skip: "-" };
const CELL_ICON = (c: MatrixCell) => c.blocked === null ? "-" : c.blocked ? "✓" : "✗";

function formatMatrix(matrix: NamedMatrix): string[] {
  if (matrix.cells.length === 0) return [];
  const lines = [matrix.title, ""];
  const surfaces: Surface[] = [...new Set(matrix.cells.map(cell => cell.surface))];
  for (const surface of surfaces) {
    const rows = matrix.cells.filter(c => c.surface === surface);
    if (rows.length === 0) continue;
    lines.push(` ${surface}`);
    for (const r of rows) lines.push(`  ${r.label.padEnd(20)} ${CELL_ICON(r)}   ${r.detail}`);
    lines.push("");
  }
  return lines;
}

export function formatReport(checks: Check[], matrices: NamedMatrix[] = []): string {
  const lines = [
    "beam-audit: developer workstation and AI agent security audit",
    "No beam-cli installation required -- this checks what your machine does today.",
    "",
    ...matrices.flatMap(formatMatrix),
  ];
  for (const c of checks) {
    lines.push(` ${ICON[c.status]} ${c.status.toUpperCase().padEnd(4)}  ${c.title}  (policy ${c.policySection})`);
    lines.push(`          ${c.detail}`);
    if (c.evidence?.length) for (const e of c.evidence.slice(0, 10)) lines.push(`          - ${e}`);
    if (c.fix && c.status !== "pass") lines.push(`          Fix: ${c.fix}`);
    lines.push("");
  }
  const n = (s: Status) => checks.filter(c => c.status === s).length;
  const matrixFails = matrices.flatMap(m => m.cells.filter(c => c.blocked === false && m.title.includes("4.3") && !checks.some(check => check.id === `live-${m.title}-${c.surface}-${c.label}`))).length;
  const fails = n("fail") + matrixFails;
  lines.push(`${n("pass")} passed, ${n("warn")} warnings, ${n("fail")} failed, ${n("skip")} not checkable.`);
  if (n("skip") > 0 || n("warn") > 0) lines.push("Coverage is incomplete or requires review; this report does not certify the workstation secure.");
  if (fails > 0) {
    lines.push("");
    lines.push(`${fails} check(s) failed. Review each finding and its stated remediation.`);
  }
  return lines.join("\n");
}

export const exitCode = (checks: Check[], matrices: NamedMatrix[] = []) =>
  checks.some(c => c.status === "fail") || matrices.some(m => m.title.includes("4.3") && m.cells.some(c => c.blocked === false)) ? 1 : 0;
