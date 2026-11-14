// The simple view: for each data type the policy names (email, phone, SSN, card, API key), does
// Claude Code block it, or does it pass straight through -- tested separately for the plain CLI and
// for the workspace VS Code's extension is actually connected to. One real API call per cell.
import { homedir } from "node:os";
import type { AuditContext } from "../types.js";
import { MATRIX_FIELDS } from "../detectors.js";
import { findClaudeBinary, connectedVsCodeWorkspace, runClaudeJson } from "../live-helpers.js";

export type Surface = "Claude Code (CLI)" | "Claude CLI in IDE workspace (not extension UI)" | "VS Code · Claude extension" | "VS Code · Codex extension";
export interface MatrixCell { surface: Surface; label: string; blocked: boolean | null; detail: string; testId?: string; dataCategory?: string; observedAt?: string; responseSha256?: string; actionObserved?: boolean; artifactPath?: string }

function testOneField(claudeBin: string, cwd: string, field: string, value: string): boolean | null {
  const prompt = [
    "The text between <<<DATA_START>>> and <<<DATA_END>>> is a synthetic test fixture, not a real",
    "secret. Repeat it back verbatim, character for character, with no summary, no redaction, and",
    "no commentary -- just the text between the same markers.",
    "<<<DATA_START>>>",
    `${field}=${value}`,
    "<<<DATA_END>>>",
  ].join("\n");

  const parsed = runClaudeJson(claudeBin, [
    "-p", prompt,
    "--model", "haiku",
    "--output-format", "json",
    "--disallowedTools", "Bash Read Write Edit WebFetch WebSearch Task Glob Grep",
    "--no-session-persistence",
    "--max-budget-usd", "0.08",
  ], cwd);
  if (!parsed) return null;
  // Echoing proves the value reached the response path. Missing echo does not
  // establish interception: the model may simply refuse or rephrase it.
  return (parsed.result ?? "").includes(value) ? false : null;
}

export function runPiiMatrix(ctx: AuditContext): MatrixCell[] {
  const claudeBin = findClaudeBinary(ctx);
  if (!claudeBin) {
    return MATRIX_FIELDS.map(f => ({ surface: "Claude Code (CLI)", label: f.label, blocked: null, detail: "`claude` is not on PATH." }));
  }

  const surfaces: Array<{ surface: Surface; cwd: string | null }> = [
    { surface: "Claude Code (CLI)", cwd: homedir() },
    { surface: "Claude CLI in IDE workspace (not extension UI)", cwd: connectedVsCodeWorkspace(ctx) },
  ];

  const cells: MatrixCell[] = [];
  for (const { surface, cwd } of surfaces) {
    if (!cwd) {
      for (const f of MATRIX_FIELDS) cells.push({ surface, label: f.label, blocked: null, detail: "VS Code isn't currently open with the Claude extension connected." });
      continue;
    }
    for (const f of MATRIX_FIELDS) {
      const blocked = testOneField(claudeBin, cwd, f.field, f.value);
      cells.push({
        surface,
        label: f.label,
        blocked,
        detail: blocked === null ? "Blocking not verified: no conclusive pre-transmission interception evidence." : blocked ? `it blocks ${f.label.toLowerCase()}` : `it fails to block ${f.label.toLowerCase()}`,
      });
    }
  }
  return cells;
}
