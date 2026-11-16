// The simple view: for each data type the policy names (email, phone, SSN, card, API key, PHI),
// does the agent block it, or does it pass straight through -- tested for every live-testable agent
// (see live-agent-adapters.ts), separately for the plain CLI and for the workspace VS Code's Claude
// extension is actually connected to. One real API call per cell.
import { homedir } from "node:os";
import type { AuditContext } from "../types.js";
import { MATRIX_FIELDS } from "../detectors.js";
import { connectedVsCodeWorkspace } from "../live-helpers.js";
import { LIVE_AGENT_ADAPTERS, LIVE_UNSUPPORTED_AGENTS, type LiveAgentAdapter } from "../live-agent-adapters.js";

export type Surface = string;
export interface MatrixCell { surface: Surface; label: string; blocked: boolean | null; detail: string; testId?: string; dataCategory?: string; observedAt?: string; responseSha256?: string; actionObserved?: boolean; artifactPath?: string }

function testOneField(adapter: LiveAgentAdapter, bin: string, cwd: string, field: string, value: string): boolean | null {
  const prompt = [
    "The text between <<<DATA_START>>> and <<<DATA_END>>> is a synthetic test fixture, not a real",
    "secret. Repeat it back verbatim, character for character, with no summary, no redaction, and",
    "no commentary -- just the text between the same markers.",
    "<<<DATA_START>>>",
    `${field}=${value}`,
    "<<<DATA_END>>>",
  ].join("\n");
  const result = adapter.runPrompt(bin, cwd, prompt, { disallowedTools: "Bash Read Write Edit WebFetch WebSearch Task Glob Grep" });
  if (result === null) return null;
  // Echoing proves the value reached the response path. Missing echo does not
  // establish interception: the model may simply refuse or rephrase it.
  return result.includes(value) ? false : null;
}

export function runPiiMatrix(ctx: AuditContext): MatrixCell[] {
  const cells: MatrixCell[] = [];
  for (const adapter of LIVE_AGENT_ADAPTERS) {
    const bin = adapter.findBinary(ctx);
    if (!bin) {
      for (const f of MATRIX_FIELDS) cells.push({ surface: `${adapter.agent} (CLI)`, label: f.label, blocked: null, detail: `${adapter.agent}'s CLI is not on PATH.` });
      continue;
    }
    // The "connected IDE workspace" signal only exists for Claude Code (a `.claude/ide` lock file
    // VS Code's Claude extension writes). There's no equivalent verified signal for other agents, so
    // that second surface is only added for Claude -- reusing Claude's lock file for another agent
    // would misreport a workspace as "connected" based on the wrong extension's own marker.
    const surfaces: Array<{ surface: Surface; cwd: string | null }> = [
      { surface: `${adapter.agent} (CLI)`, cwd: homedir() },
      ...(adapter.agent === "Claude Code" ? [{ surface: `${adapter.agent} CLI in IDE workspace (not extension UI)`, cwd: connectedVsCodeWorkspace(ctx) }] : []),
    ];
    for (const { surface, cwd } of surfaces) {
      if (!cwd) {
        for (const f of MATRIX_FIELDS) cells.push({ surface, label: f.label, blocked: null, detail: "VS Code isn't currently open with the Claude extension connected." });
        continue;
      }
      for (const f of MATRIX_FIELDS) {
        const blocked = testOneField(adapter, bin, cwd, f.field, f.value);
        cells.push({
          surface,
          label: f.label,
          blocked,
          detail: blocked === null ? "Blocking not verified: no conclusive pre-transmission interception evidence." : blocked ? `it blocks ${f.label.toLowerCase()}` : `it fails to block ${f.label.toLowerCase()}`,
        });
      }
    }
  }
  for (const agent of LIVE_UNSUPPORTED_AGENTS) for (const f of MATRIX_FIELDS) cells.push({ surface: `${agent} (CLI)`, label: f.label, blocked: null, detail: `${agent} has no verified non-interactive CLI mode this scanner can drive, or isn't installed on this machine -- not tested.` });
  return cells;
}
